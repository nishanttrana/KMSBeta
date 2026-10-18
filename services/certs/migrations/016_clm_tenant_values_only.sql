-- 016: the certificate lifetime policy holds only the tenant's own values
-- (13.22.0-beta, docs/CERTIFICATES.md "Certificate lifetime policy").
--
-- schedule_aware tightened the tenant's limit to the CA/B Forum SC-081
-- schedule on dates the product chose; the customer decides the limit and
-- when it changes. renew_before_days was stored and shown but nothing read
-- it. A saved policy keeps its mode and limit.

ALTER TABLE cert_clm_policies DROP COLUMN IF EXISTS schedule_aware;
ALTER TABLE cert_clm_policies DROP COLUMN IF EXISTS renew_before_days;
ALTER TABLE cert_clm_policies ALTER COLUMN mode SET DEFAULT 'off';
ALTER TABLE cert_clm_policies ALTER COLUMN max_validity_days SET DEFAULT 0;
