// QAField — server-side e-mail (Edge Function `send-email`).
// Sends lab orders, non-conformance (NCR) reports and pre-control forms with the PDF attached, through Resend.
//
// Secrets (Supabase → Edge Functions → Secrets):
//   RESEND_API_KEY   Resend key. The literal value `dry-run` validates and logs everything but sends nothing (staging tests).
//                    Missing → the function answers 503 not_configured and the web app falls back to the old `mailto:` flow.
//   MAIL_FROM        e.g.  QAField <noreply@dror-pro.com>   (the domain must be verified in Resend)
//   SB_SECRET_KEY    service-role / secret key of this project (only used to write public.email_log and count the rate limits)
//   SB_PUBLISHABLE_KEY  (optional) publishable key; falls back to SUPABASE_ANON_KEY
//
// Security model: the caller's own JWT is used for every read (RLS decides what they may see). The function never trusts the
// client for anything that matters: the referenced row must be visible to the caller, the attachment must be a file of that
// row (and readable by the caller through storage RLS), recipients are capped, pre-control mail may only go to project users,
// and sends are rate-limited per user and per company. Every attempt is written to email_log.
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.4';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

const URL_ = Deno.env.get('SUPABASE_URL')!;
const ANON = Deno.env.get('SB_PUBLISHABLE_KEY') ?? Deno.env.get('SUPABASE_ANON_KEY')!;
const SECRET = Deno.env.get('SB_SECRET_KEY') ?? Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const RESEND_KEY = Deno.env.get('RESEND_API_KEY') ?? '';
const MAIL_FROM = Deno.env.get('MAIL_FROM') ?? '';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// no control characters (NUL…), no spaces, no `..`, a real domain with an alphabetic TLD
const EMAIL_RE = /^(?!.*\.\.)[^\s@<>"',;\u0000-\u001f\u007f]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
const stripCtl = (s: string, keepNewlines: boolean) => s.replace(keepNewlines ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g : /[\u0000-\u001f\u007f]/g, '');
const PATH_RE = /^[A-Za-z0-9_\-./]+$/;
const KINDS = ['lab_order', 'ncr', 'precontrol'];
const MAX_RECIPIENTS = 15;
const MAX_ATTACH_BYTES = 10 * 1024 * 1024;
const LIMIT_USER_HOUR = 30;
const LIMIT_COMPANY_DAY = 300;
const LIMIT_PROJECT_DAY = 100;

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const noTags = (s: string) => s.replace(/<(?=[A-Za-z/!?])/g, '‹');
const toHtml = (text: string) =>
  `<div dir="rtl" style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.7;color:#1a2233;white-space:pre-wrap">` +
  esc(text).replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" style="color:#2563eb">$1</a>') +
  `</div>`;
const b64 = (buf: ArrayBuffer) => {
  const bytes = new Uint8Array(buf); let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return json(405, { error: 'method_not_allowed' });

  if (!RESEND_KEY || (RESEND_KEY !== 'dry-run' && !MAIL_FROM)) return json(503, { error: 'not_configured', message: 'שליחת מייל מהשרת עדיין לא הוגדרה' });

  // ── who is calling ──
  const auth = req.headers.get('Authorization') ?? '';
  if (!auth.startsWith('Bearer ')) return json(401, { error: 'unauthorized', message: 'נדרשת התחברות' });
  const user = createClient(URL_, ANON, { global: { headers: { Authorization: auth } }, auth: { persistSession: false } });
  const { data: u, error: uErr } = await user.auth.getUser();
  if (uErr || !u?.user) return json(401, { error: 'unauthorized', message: 'ההתחברות פגה, התחבר מחדש' });
  const me = u.user;
  const { data: prof } = await user.from('profiles').select('company_id, full_name').eq('id', me.id).maybeSingle();
  if (!prof?.company_id) return json(403, { error: 'forbidden', message: 'אין הרשאה' });
  const svc = createClient(URL_, SECRET, { auth: { persistSession: false } });

  // ── input ──
  let b: any;
  try { b = await req.json(); } catch { return json(400, { error: 'bad_request', message: 'בקשה לא תקינה' }); }
  const kind = String(b?.kind ?? ''), ref = String(b?.ref_id ?? '');
  if (!KINDS.includes(kind)) return json(400, { error: 'bad_kind', message: 'סוג מייל לא נתמך' });
  if (!UUID_RE.test(ref)) return json(400, { error: 'bad_ref', message: 'מזהה לא תקין' });
  const to = [...new Set((Array.isArray(b?.to) ? b.to : []).map((x: unknown) => String(x).trim().toLowerCase()))] as string[];
  if (!to.length) return json(400, { error: 'no_recipients', message: 'לא נבחר נמען' });
  if (to.length > MAX_RECIPIENTS) return json(400, { error: 'too_many_recipients', message: `עד ${MAX_RECIPIENTS} נמענים` });
  const badAddr = to.filter((a) => a.length > 254 || !EMAIL_RE.test(a));
  if (badAddr.length) return json(400, { error: 'bad_recipient', message: 'כתובת לא תקינה: ' + badAddr.join(', ') });
  const subject = stripCtl(String(b?.subject ?? '').replace(/[\r\n]+/g, ' '), false).trim().slice(0, 200);
  const text = stripCtl(String(b?.text ?? ''), true).slice(0, 20000);
  if (!subject || !text) return json(400, { error: 'empty', message: 'נושא או תוכן ריקים' });
  const attachPath = b?.attachment_path ? String(b.attachment_path) : '';
  const attachName = String(b?.attachment_name ?? 'document.pdf').replace(/[^\w.\-א-ת ]+/g, '_').slice(0, 80) || 'document.pdf';

  // ── the referenced row must be visible to the caller (RLS) ──
  let projectId: string | null = null, expectPrefix = '', exactPath = '';
  if (kind === 'lab_order') {
    const { data } = await user.from('inspection_orders').select('id, project_id, pdf_url').eq('id', ref).maybeSingle();
    if (!data) return json(403, { error: 'forbidden', message: 'אין הרשאה להזמנה זו' });
    projectId = data.project_id;
    exactPath = attachPath && String(data.pdf_url ?? '').endsWith('/' + attachPath) ? attachPath : '';
  } else if (kind === 'ncr') {
    const { data } = await user.from('findings').select('id, project_id').eq('id', ref).maybeSingle();
    if (!data) return json(403, { error: 'forbidden', message: 'אין הרשאה לאי-ההתאמה' });
    projectId = data.project_id; expectPrefix = `findings/${ref}/`;
  } else {
    const { data } = await user.from('precontrol_forms').select('id, project_id').eq('id', ref).maybeSingle();
    if (!data) return json(403, { error: 'forbidden', message: 'אין הרשאה לטופס' });
    projectId = data.project_id; expectPrefix = `precontrol/${ref}/`;
    // pre-control mail goes to the project's own users only
    const { data: users, error: rpcErr } = await user.rpc('get_project_user_emails', { p_project_id: projectId });
    if (rpcErr) return json(403, { error: 'forbidden', message: 'אין הרשאה' });
    const allowed = new Set((users ?? []).map((x: any) => String(x.email).toLowerCase()));
    const outside = to.filter((a) => !allowed.has(a));
    if (outside.length) return json(403, { error: 'recipient_not_allowed', message: 'בבקרה מקדימה אפשר לשלוח רק למשתמשי הפרויקט: ' + outside.join(', ') });
  }

  // ── attachment path: a PDF of that row (the download itself happens after the slot is reserved) ──
  if (attachPath) {
    const okPath = PATH_RE.test(attachPath) && !attachPath.includes('..') && attachPath.toLowerCase().endsWith('.pdf') &&
      ((expectPrefix && attachPath.startsWith(expectPrefix)) || (exactPath && attachPath === exactPath));
    if (!okPath) return json(400, { error: 'bad_attachment', message: 'הקובץ המצורף אינו שייך לרשומה' });
  }

  // ── reserve a send slot atomically (rate limits per user / company / project; fail closed if the log cannot be written) ──
  const { data: slot, error: slotErr } = await svc.rpc('reserve_email_slot', {
    p_company: prof.company_id, p_project: projectId, p_user: me.id, p_kind: kind, p_ref: ref, p_to: to, p_subject: noTags(subject),
    p_user_hour: LIMIT_USER_HOUR, p_company_day: LIMIT_COMPANY_DAY, p_project_day: LIMIT_PROJECT_DAY,
  });
  if (slotErr || !slot) return json(500, { error: 'log_unavailable', message: 'לא ניתן לרשום את השליחה, המייל לא נשלח' });
  if (slot.limited) {
    const msg = slot.limited === 'user' ? 'חרגת ממכסת השליחה לשעה. נסה שוב מאוחר יותר'
      : slot.limited === 'project' ? 'חרגתם ממכסת השליחה היומית של הפרויקט' : 'חרגתם ממכסת השליחה היומית של החברה';
    return json(429, { error: 'rate_limited', message: msg });
  }
  const slotId: string = slot.id;
  const finish = async (status: string, error: string | null, providerId: string | null, attachedPath: string | null) => {
    const { error: e } = await svc.from('email_log').update({ status, error: error ? noTags(stripCtl(error, false)).slice(0, 500) : null, provider_id: providerId, attachment: attachedPath }).eq('id', slotId);
    if (e) console.error('email_log update failed', e.message);   // the reserved row stays `pending`, which still counts against the limits
  };

  // ── attachment: readable by the caller through storage RLS ──
  let attachment: { filename: string; content: string } | null = null;
  if (attachPath) {
    const { data: blob, error: dErr } = await user.storage.from('documents').download(attachPath);
    if (dErr || !blob) { await finish('failed', 'attachment unreadable', null, null); return json(403, { error: 'attachment_unreadable', message: 'לא ניתן לקרוא את הקובץ המצורף' }); }
    if (blob.size > MAX_ATTACH_BYTES) { await finish('failed', 'attachment too large', null, null); return json(413, { error: 'attachment_too_large', message: 'הקובץ גדול מדי לשליחה במייל' }); }
    attachment = { filename: attachName.toLowerCase().endsWith('.pdf') ? attachName : attachName + '.pdf', content: b64(await blob.arrayBuffer()) };
  }

  if (RESEND_KEY === 'dry-run' || b?.dry_run === true) {   // `dry_run: true` in the body: validate + log, send nothing (used by the test suites against a live key)
    await finish('dry_run', null, null, attachment ? attachPath : null);
    return json(200, { ok: true, dry_run: true, sent_to: to.length, attached: !!attachment });
  }

  // ── send ──
  // The mail is sent from our verified address but carries the logged-in user's name, and replies go to that user (Reply-To).
  const fromAddr = (MAIL_FROM.match(/<([^>]+)>/)?.[1] ?? MAIL_FROM).trim();
  // letters / marks (Hebrew niqqud, other scripts) / digits and a few harmless punctuation marks (Hebrew gershayim, maqaf, curly apostrophe); cut by code points
  const senderName = Array.from(String(prof.full_name ?? '').replace(/[^\p{L}\p{M}\p{N} .'\-׳״־’]/gu, '').replace(/\s+/g, ' ').trim()).slice(0, 50).join('').trim();
  const from = senderName ? `"${senderName} via QAField" <${fromAddr}>` : MAIL_FROM;
  const payload: Record<string, unknown> = { from, to, subject, text, html: toHtml(text) };
  if (me.email && EMAIL_RE.test(me.email)) payload.reply_to = me.email;
  if (attachment) payload.attachments = [attachment];
  let res: Response;
  try {
    res = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  } catch (e) {
    await finish('failed', 'network: ' + String(e), null, null);
    return json(502, { error: 'provider_unreachable', message: 'שירות המייל אינו זמין כרגע' });
  }
  const out = await res.json().catch(() => ({}));
  if (!res.ok) {
    await finish('failed', `${res.status} ${out?.message ?? out?.name ?? ''}`, null, null);
    return json(res.status >= 500 ? 502 : 422, { error: 'provider_rejected', message: 'שליחת המייל נכשלה: ' + (out?.message ?? res.status) });
  }
  await finish('sent', null, out?.id ?? null, attachment ? attachPath : null);
  return json(200, { ok: true, id: out?.id ?? null, sent_to: to.length, attached: !!attachment });
});
