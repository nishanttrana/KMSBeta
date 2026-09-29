-- 031: remove the per-interface pqc_mode (6.4.0-beta).
--
-- key_interface_ports.pqc_mode (inherit | classical | hybrid | pqc_only) was
-- stored and shown, but no listener read it: the key exchange an interface
-- negotiates is set by pkg/svctls (per-service kx_profile, PKI → mTLS) and by
-- Envoy's ecdh_curves. Migration 008 no longer adds the column; this drops
-- it where it exists.

ALTER TABLE key_interface_ports DROP COLUMN IF EXISTS pqc_mode;
