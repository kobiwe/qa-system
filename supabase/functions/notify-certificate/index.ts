// QAField — "a lab certificate arrived" notification (Edge Function `notify-certificate`).
// A database trigger (migration 024) calls this function through pg_net when the lab uploads a certificate to an order
// (inspection_orders.certificate_url goes from NULL to a value). The function mails the person who created the order, with the
// certificate PDF attached. Not callable by users: it needs the shared secret header `x-notify-secret`.
//
// Secrets: NOTIFY_SECRET (same value as the Vault secret `notify_secret` in the database), RESEND_API_KEY, MAIL_FROM,
//          SB_SECRET_KEY, APP_URL (e.g. https://qafield.netlify.app). RESEND_API_KEY=dry-run validates and logs without sending.
// Safety: one notification per order (email_log dedupe); addresses on reserved test domains (.test, example.*) are never really sent.
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.4';

const json = (status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const URL_ = Deno.env.get('SUPABASE_URL')!;
const SECRET = Deno.env.get('SB_SECRET_KEY') ?? Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const NOTIFY_SECRET = Deno.env.get('NOTIFY_SECRET') ?? '';
const RESEND_KEY = Deno.env.get('RESEND_API_KEY') ?? '';
const MAIL_FROM = Deno.env.get('MAIL_FROM') ?? '';
const APP_URL = (Deno.env.get('APP_URL') ?? '').replace(/\/+$/, '');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^(?!.*\.\.)[^\s@<>"',;\u0000-\u001f\u007f]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
const MAX_ATTACH_BYTES = 10 * 1024 * 1024;

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const noTags = (s: string) => s.replace(/<(?=[A-Za-z/!?])/g, '‹');
// control characters and bidi / invisible marks (RLO etc.) never reach a subject or body
const clean = (s: unknown, max = 200) => String(s ?? '').replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩﻿]+/g, ' ').trim().slice(0, max);
const toHtml = (text: string) =>
  `<div dir="rtl" style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.7;color:#1a2233;white-space:pre-wrap">` +
  esc(text).replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" style="color:#2563eb">$1</a>') + `</div>`;
const b64 = (buf: ArrayBuffer) => {
  const bytes = new Uint8Array(buf); let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
};
// constant-time comparison of the shared secret
const same = (a: string, b: string) => {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return d === 0;
};

Deno.serve(async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'method_not_allowed' });
  if (!NOTIFY_SECRET || !same(req.headers.get('x-notify-secret') ?? '', NOTIFY_SECRET)) return json(401, { error: 'unauthorized' });
  if (!RESEND_KEY || (RESEND_KEY !== 'dry-run' && !MAIL_FROM)) return json(503, { error: 'not_configured' });

  let b: any; try { b = await req.json(); } catch { return json(400, { error: 'bad_request' }); }
  const orderId = String(b?.order_id ?? '');
  if (!UUID_RE.test(orderId)) return json(400, { error: 'bad_order' });
  const svc = createClient(URL_, SECRET, { auth: { persistSession: false } });

  const { data: o } = await svc.from('inspection_orders')
    .select('id, company_id, project_id, order_number, location, created_by, certificate_url, projects(name)').eq('id', orderId).maybeSingle();
  if (!o) return json(404, { error: 'order_not_found' });
  if (!o.certificate_url) return json(409, { error: 'no_certificate' });

  // one notification per order
  const { count } = await svc.from('email_log').select('id', { count: 'exact', head: true }).eq('kind', 'lab_certificate').eq('ref_id', orderId).in('status', ['pending', 'sent', 'dry_run']);
  if ((count ?? 0) > 0) return json(200, { ok: true, skipped: 'already_notified' });

  // recipient: the person who created the order
  let email = '', name = '';
  if (o.created_by) {
    const { data: u } = await svc.auth.admin.getUserById(o.created_by);
    email = String(u?.user?.email ?? '').trim().toLowerCase();
    const { data: p } = await svc.from('profiles').select('full_name').eq('id', o.created_by).maybeSingle();
    name = clean(p?.full_name, 60);
  }
  const subject = noTags(`התקבלה תעודת מעבדה — הזמנה #${o.order_number ?? ''} | ${clean((o as any).projects?.name, 80)}`);
  const logRow = (status: string, error: string | null, providerId: string | null, attachment: string | null) => ({
    company_id: o.company_id, project_id: o.project_id, user_id: o.created_by, kind: 'lab_certificate', ref_id: orderId,
    to_list: email ? [email] : [], subject, attachment, status, error: error ? noTags(clean(error, 400)) : null, provider_id: providerId,
  });
  if (!email || !EMAIL_RE.test(email)) {
    await svc.from('email_log').insert(logRow('failed', 'no recipient (order has no creator e-mail)', null, null));
    return json(200, { ok: true, skipped: 'no_recipient' });
  }
  // per-project daily cap on these notifications (whoever holds a lab link cannot make us mail more than this per project and day)
  const { count: projCount } = await svc.from('email_log').select('id', { count: 'exact', head: true }).eq('kind', 'lab_certificate').eq('project_id', o.project_id)
    .in('status', ['pending', 'sent', 'dry_run']).gte('created_at', new Date(Date.now() - 86400_000).toISOString());
  if ((projCount ?? 0) >= 30) { await svc.from('email_log').insert(logRow('failed', 'project daily cap reached', null, null)); return json(200, { ok: true, skipped: 'project_cap' }); }
  // atomic dedupe: a partial unique index (migration 025) allows one live row per order, so a concurrent second insert fails here
  const { data: slot, error: slotErr } = await svc.from('email_log').insert(logRow('pending', null, null, null)).select('id').single();
  if (slotErr?.code === '23505') return json(200, { ok: true, skipped: 'already_notified' });
  if (slotErr || !slot) return json(500, { error: 'log_unavailable' });
  const finish = async (status: string, error: string | null, providerId: string | null, attachment: string | null) => {
    const { error: e } = await svc.from('email_log').update({ status, error: error ? noTags(clean(error, 400)) : null, provider_id: providerId, attachment }).eq('id', slot.id);
    if (e) console.error('email_log update failed', e.message);
  };

  // attach the certificate (service role: the file sits in certificates/, uploaded by the lab)
  let attachment: { filename: string; content: string } | null = null, attachedPath: string | null = null;
  const path = decodeURIComponent(String(o.certificate_url).match(/\/documents\/(certificates\/[^?#]+\.pdf)$/)?.[1] ?? '');
  // the file name must belong to THIS order (project id + order number) and the bytes must really be a PDF: the lab upload is anonymous,
  // so nothing else may ever travel as an attachment from our verified domain
  const ownName = new RegExp('^certificates/cert_' + String(o.project_id).toLowerCase() + '_' + Number(o.order_number) + '_\\d{10,14}\\.pdf$');
  if (path && ownName.test(path)) {
    const { data: blob } = await svc.storage.from('documents').download(path);
    if (blob && blob.size <= MAX_ATTACH_BYTES) {
      const buf = await blob.arrayBuffer();
      if (new TextDecoder('latin1').decode(new Uint8Array(buf.slice(0, 5))) === '%PDF-') { attachment = { filename: `certificate_${o.order_number ?? 'order'}.pdf`, content: b64(buf) }; attachedPath = path; }
    }
  }

  const text = [`שלום${name ? ' ' + name : ''},`, '', `המעבדה העלתה תעודה להזמנה #${o.order_number ?? ''}.`, `פרויקט: ${clean((o as any).projects?.name, 80)}`,
    o.location ? `מיקום: ${clean(o.location, 120)}` : null, '', attachment ? 'התעודה מצורפת למייל (PDF), והיא נשמרה גם בהזמנה במערכת.' : 'התעודה נשמרה בהזמנה במערכת.',
    APP_URL ? '' : null, APP_URL ? `לצפייה בהזמנה: ${APP_URL}` : null].filter((l) => l !== null).join('\n');

  // reserved / non-deliverable test domains are never really sent (keeps the sender reputation clean while testing)
  const testAddress = /@[^@]*\.test$/i.test(email) || /@(?:[^@]*\.)?example\.[a-z]+$/i.test(email) || /@[^@]*\.(?:invalid|localhost)$/i.test(email);
  if (RESEND_KEY === 'dry-run' || testAddress || b?.dry_run === true) {
    await finish('dry_run', null, null, attachedPath);
    return json(200, { ok: true, dry_run: true, attached: !!attachment });
  }
  const payload: Record<string, unknown> = { from: MAIL_FROM, to: [email], subject, text, html: toHtml(text) };
  if (attachment) payload.attachments = [attachment];
  let res: Response;
  try {
    res = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  } catch (e) { await finish('failed', 'network: ' + String(e), null, null); return json(502, { error: 'provider_unreachable' }); }
  const out = await res.json().catch(() => ({}));
  if (!res.ok) { await finish('failed', `${res.status} ${out?.message ?? out?.name ?? ''}`, null, null); return json(502, { error: 'provider_rejected' }); }
  await finish('sent', null, out?.id ?? null, attachedPath);
  return json(200, { ok: true, id: out?.id ?? null, attached: !!attachment });
});
