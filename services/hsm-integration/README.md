# HSM Integration Service

An SSH/SCP/SFTP endpoint for uploading a customer's PKCS#11 library and
vendor client files. `hsm-connector` then loads the library
([docs/SECURITY/HSM_INTEGRATION.md](../../docs/SECURITY/HSM_INTEGRATION.md)).

## Access
There is no default password, and none is ever written in this repository.

- **Keys (preferred).** Put SSH public keys in
  `HSM_INTEGRATION_SSH_AUTHORIZED_KEYS` in `.env`, separated by `;`.
  - Password login is then turned off.
  - The keys file is root-owned, so a session can't add a key of its own.
- **Password.** Without keys, the account's password is locked at every
  start. When an administrator opens a CLI session from the dashboard,
  auth sets it to the KMS CLI user's password.
  - That password is managed in user management. Installers generate
    `AUTH_BOOTSTRAP_CLI_PASSWORD`.
  - Auth refuses a password that has ever been published, and replaces it
    on existing accounts.
  - The password reaches the container through the exec environment, never
    a command line.
- **Port 2222** listens on loopback. Set `HSM_INTEGRATION_SSH_BIND` to
  expose it deliberately.

## What the account can do
- Write to the provider workspace
  `/var/lib/vecta/hsm/providers/<tenant>/`. It is setgid, group
  `hsm-providers` (gid 10430), which `hsm-connector` joins to read the
  libraries.
- Run `pkcs11-tool` and the helper scripts below.
- Nothing else:
  - no `sudo`;
  - no root login;
  - no TCP, agent or X11 forwarding, and no tunnels into the platform
    network.

## Audit
- **File changes:** `hsm-connector` audits the workspace. It emits an
  inventory at start, then `audit.hsm.provider_library_added`, `_changed`
  and `_removed`, each with the file's SHA-256.
- **Auth:** it audits CLI sessions and their refusals, the password copy,
  and revocations (`audit.auth.cli_*`).
- **Logins:** sshd logs every login, with the key fingerprint, in the
  container log.

## Helper scripts
- `/opt/vecta/hsm/scripts/install-provider.sh <tenant> <file>`
- `/opt/vecta/hsm/scripts/verify-provider.sh <library>`
- `/opt/vecta/hsm/scripts/list-partitions.sh <library> [slot]`
