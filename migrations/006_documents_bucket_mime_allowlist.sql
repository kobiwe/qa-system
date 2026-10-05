-- the bucket only allowed pdf/html, so every image/Office upload failed with 415
update storage.buckets set file_size_limit = 52428800, allowed_mime_types = array[
 'application/pdf','text/html','image/png','image/jpeg','image/webp','image/gif','image/heic','image/heif',
 'application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
 'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
 'application/vnd.ms-powerpoint','application/vnd.openxmlformats-officedocument.presentationml.presentation',
 'text/plain','text/csv','application/zip','application/octet-stream','application/acad','image/vnd.dwg','application/x-dwg','image/vnd.dxf'
] where id = 'documents';
