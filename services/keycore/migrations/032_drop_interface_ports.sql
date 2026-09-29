-- 032: remove the interface port and TLS-default records (6.8.0-beta).
--
-- key_interface_ports (bind address, port, protocol, certificate source,
-- enabled) and key_interface_tls_defaults (the certificate source for
-- "TLS-enabled interfaces") were stored and shown in System Administration,
-- but no listener read them: listeners, ports and certificates come from the
-- deployment (docker-compose, Envoy, the certs runtime materializer). The
-- external listeners' key exchange is certs' edge policy (Service mTLS).
-- 004 no longer creates key_interface_ports, 006, 007 and 031 are deleted;
-- this drops the tables where they exist (their row policies go with them).

DROP TABLE IF EXISTS key_interface_ports;
DROP TABLE IF EXISTS key_interface_tls_defaults;
