# Deployment Profile Scripts

- `parse-deployment.sh` / `parse-deployment.ps1`: read `deployment.yaml` and emit `COMPOSE_PROFILES`.
- `start-kms.sh` / `start-kms.ps1`: start Docker Compose using enabled profiles, with one recovery retry on startup failures.
- `stop-kms.sh` / `stop-kms.ps1`: stop Docker Compose with profile-aware cleanup (`--force` available).
- `recover-kms.sh` / `recover-kms.ps1`: forced repair flow (`stop --force` then `start`).
- `healthcheck-enabled-services.sh`: verify health endpoints for core + enabled optional services.
- `healthcheck-enabled-services.ps1`: native PowerShell health checks for Windows.
- Deployment schema: `infra/deployment/deployment.schema.json`.

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

First-boot wizard container (local/dev):

```powershell
docker compose --profile firstboot up -d firstboot
```

## Default One-Command Startup

Root `.env` now contains `COMPOSE_PROFILES` from the default deployment. This allows:

```bash
docker compose up -d
```

to bring up the expected service set without manually passing profiles.
