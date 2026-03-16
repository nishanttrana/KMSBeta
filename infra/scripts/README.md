# Deployment Profile Scripts

- `parse-deployment.sh` / `parse-deployment.ps1`: read `deployment.yaml` and emit `COMPOSE_PROFILES`.
- `start-kms.sh` / `start-kms.ps1`: start Docker Compose using enabled profiles, with one recovery retry on startup failures.
- `stop-kms.sh` / `stop-kms.ps1`: stop Docker Compose with profile-aware cleanup (`--force` available).
- `recover-kms.sh` / `recover-kms.ps1`: forced repair flow (`stop --force` then `start`).
- `healthcheck-enabled-services.sh`: verify health endpoints for core + enabled optional services.
- `healthcheck-enabled-services.ps1`: native PowerShell health checks for Windows.
- Deployment schema: `infra/deployment/deployment.schema.json`.

Feature-to-profile coverage includes:

- core security modules: `secrets`, `certs`, `governance`, `data_protection`
- integrations: `cloud_byok`, `hyok_proxy`, `kmip_server`, `ekm_database`
- advanced crypto: `qkd_interface`, `qrng_generator`, `pqc_migration`, `mpc_engine`
- monitoring and governance: `compliance_dashboard`, `sbom_cbom`, `reporting_alerting`, `posture_management`, `crypto_discovery`, `ai_llm`
- HA and replication: `clustering`

Installer flows also understand these built-in cluster replication profile IDs:

- `cluster-profile-base`
- `cluster-profile-standard`
- `cluster-profile-security`
- `cluster-profile-full`

Example (Linux):

```bash
./infra/scripts/start-kms.sh /etc/vecta/deployment.yaml
```

Example (PowerShell):

```powershell
.\infra\scripts\start-kms.ps1 -DeploymentFile .\infra\deployment\deployment.yaml
```

Stop + recover examples:

```bash
./infra/scripts/stop-kms.sh /etc/vecta/deployment.yaml --force
./infra/scripts/recover-kms.sh /etc/vecta/deployment.yaml
```

```powershell
.\infra\scripts\stop-kms.ps1 -DeploymentFile .\infra\deployment\deployment.yaml -Force
.\infra\scripts\recover-kms.ps1 -DeploymentFile .\infra\deployment\deployment.yaml
```

## Default One-Command Startup

Root `.env` now contains `COMPOSE_PROFILES` from the default deployment. This allows:

```bash
docker compose up -d
```

to bring up the expected service set without manually passing profiles.
