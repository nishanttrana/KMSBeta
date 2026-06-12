-- 013: remove key sharing tokens and edge/IoT device registry.
--
-- Key sharing tokens minted unenforced bearer credentials that duplicated the
-- principal-bound KeyAccessGrant system (key_access_grants) without any
-- redemption path; the feature is cut rather than redesigned because the
-- sound design already exists. The edge device registry lost its UI in the
-- product trim and had no key-lifecycle integration.

DROP TABLE IF EXISTS key_sharing_tokens;
DROP TABLE IF EXISTS edge_devices;
