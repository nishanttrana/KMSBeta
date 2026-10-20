-- The "Azure EKM" vault and key-mapping feature is removed (13.30.0-beta).
-- It had Azure create its own key and called that an import; it never used
-- the Vecta key. Azure Managed HSM external key management is now a HYOK
-- protocol (services/hyok/azure_ekm.go), and importing a key into Azure is
-- Cloud BYOK. The vault credentials stay in Playbooks → Credentials.
DROP TABLE IF EXISTS ekm_azure_key_mappings;
DROP TABLE IF EXISTS ekm_azure_configs;
