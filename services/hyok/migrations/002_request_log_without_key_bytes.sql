-- Earlier releases logged each HYOK request and response whole, so keys a
-- caller wrapped and keys unwrapped for it were stored in clear
-- (13.29.0-beta). Drop those fields from the rows already written; the
-- service now logs sizes only (request_log.go).
UPDATE hyok_requests
SET request_json = (request_json::jsonb - 'plaintext' - 'ciphertext' - 'iv')::text
WHERE request_json LIKE '%"plaintext"%' OR request_json LIKE '%"ciphertext"%' OR request_json LIKE '%"iv"%';

UPDATE hyok_requests
SET response_json = (response_json::jsonb - 'plaintext' - 'ciphertext' - 'iv')::text
WHERE response_json LIKE '%"plaintext"%' OR response_json LIKE '%"ciphertext"%' OR response_json LIKE '%"iv"%';
