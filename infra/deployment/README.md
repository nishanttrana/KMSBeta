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
- `autokey_provisioning`
- `workload_identity`
- `confidential_compute`
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

Notes:

- `pqc_migration` enables the dedicated `kms-pqc` microservice for tenant-scoped post-quantum policy, readiness scans, inventory classification, and migration reporting.
- It expects `kms-keycore` and `kms-certs` to be available so it can classify keys, certificates, and request-handling interfaces as classical, hybrid, or PQC-only.
- `workload_identity` enables the dedicated `kms-workload-identity` microservice for tenant-scoped SPIFFE trust domains, SVID issuance, workload-to-key authorization, and token exchange into short-lived KMS bearer tokens.
- It expects `kms-auth` so exchanged workload identity can mint standard KMS access tokens, and it uses audit state to show which workload used which key.
- `autokey_provisioning` enables the dedicated `kms-autokey` microservice for tenant-scoped policy-driven key handle provisioning.
- It expects `kms-keycore` for actual key creation and `kms-governance` when Autokey approvals are required.
- The service persists Autokey templates, per-service defaults, request catalogs, and managed handle bindings as shared control-plane data, so the feature is cluster-aware and included in backup coverage metadata.
- `confidential_compute` enables the dedicated `kms-confidential` microservice for tenant-scoped attested key release and confidential-compute policy.
- It is cluster-aware and intended for verified workload release flows such as Nitro Enclaves, Secure Key Release, GCP Confidential Space, or other TEE-attestation brokers.
- AWS verification is local once the Nitro root is trusted; Azure and GCP verification require outbound HTTPS so the service can resolve issuer metadata and JWKS during attestation validation.
- `cert_security.acme_renewal` configures coordinated certificate renewal for the built-in PKI stack.
- `start-kms.sh` and `start-kms.ps1` now read `cert_security.acme_renewal` and seed the ACME protocol policy on boot so ARI settings remain deployment-file driven.
- The `certs` component in cluster replication includes the derived renewal-intelligence state used for coordinated windows, missed-window tracking, emergency rotation, and mass-renewal hotspot detection.

Built-in clustering replication profile IDs available immediately after install:

- `cluster-profile-base`
- `cluster-profile-standard`
- `cluster-profile-security`
- `cluster-profile-full`
