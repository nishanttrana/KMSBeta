# Deployment Configuration

- `deployment.yaml`: active feature profile configuration.
- `deployment.schema.json`: JSON schema for `deployment.yaml`.

`install.sh` writes this file and `infra/scripts/parse-deployment.sh` converts it to Docker Compose profiles.

Current install-aware feature keys:

- `secrets`
- `certs`
- `governance`
- `cloud_byok`
- `hyok_proxy`
- `kmip_server`
- `qkd_interface`
- `qrng_generator`
- `ekm_database`
- `payment_crypto`
- `compliance_dashboard`
- `sbom_cbom`
- `reporting_alerting`
- `posture_management`
- `ai_llm`
- `pqc_migration`
- `crypto_discovery`
- `mpc_engine`
- `data_protection`
- `clustering`

Built-in clustering replication profile IDs available immediately after install:

- `cluster-profile-base`
- `cluster-profile-standard`
- `cluster-profile-security`
- `cluster-profile-full`
