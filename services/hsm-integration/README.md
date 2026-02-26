# HSM Integration Service

This container provides a dedicated SSH/SCP/SFTP endpoint for customer HSM library onboarding.

## Features
- Password-protected CLI user for SSH access.
- `sudo` privileges for package/script installation inside the container.
- PKCS#11 tooling (`pkcs11-tool`) for partition/slot discovery.
- Tenant workspace under `/var/lib/vecta/hsm/providers/<tenant>/`.

## Default credentials
- Username: `cli-user`
- Password: `VectaCLI@2026`

Override with environment variables:
- `HSM_INTEGRATION_USER`
- `HSM_INTEGRATION_PASSWORD`
- `HSM_INTEGRATION_WORKSPACE_ROOT`

## Built-in helper scripts
- `/opt/vecta/hsm/scripts/install-provider.sh`
- `/opt/vecta/hsm/scripts/verify-provider.sh`
- `/opt/vecta/hsm/scripts/list-partitions.sh`
