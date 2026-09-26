#!/usr/bin/env bash
# SSH/SCP/SFTP endpoint for uploading customer PKCS#11 libraries
# (services/hsm-integration/README.md, docs/SECURITY/SECURE_DEFAULTS.md).
# - No password ships anywhere. The account is locked at every start. Auth
#   sets the KMS CLI user's password when an admin opens a CLI session, or
#   public keys in HSM_INTEGRATION_SSH_AUTHORIZED_KEYS enable key login, which
#   then turns password login off.
# - No sudo, no forwarding or tunnels into the platform network.
# - Uploads land in a setgid workspace owned by group hsm-providers, which
#   hsm-connector joins (group_add) to read them; it audits every change.
set -euo pipefail

HSM_USER="$(printf '%s' "${HSM_INTEGRATION_USER:-cli-user}" | tr -cd '[:alnum:]_.-')"
HSM_USER="${HSM_USER:-cli-user}"
WORKSPACE_ROOT="${HSM_INTEGRATION_WORKSPACE_ROOT:-/var/lib/vecta/hsm/providers}"
PROVIDERS_GID="${HSM_PROVIDERS_GID:-10430}"

getent group hsm-providers >/dev/null || groupadd --gid "${PROVIDERS_GID}" hsm-providers
if ! id -u "${HSM_USER}" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --gid hsm-providers "${HSM_USER}"
fi
# Locked until auth sets the password (and after every restart).
passwd -l "${HSM_USER}" >/dev/null

mkdir -p "${WORKSPACE_ROOT}"
chown -R "${HSM_USER}:hsm-providers" /var/lib/vecta/hsm
chmod 2750 /var/lib/vecta/hsm "${WORKSPACE_ROOT}"
find "${WORKSPACE_ROOT}" -type d -exec chmod g+rxs {} + 2>/dev/null || true
find "${WORKSPACE_ROOT}" -type f -exec chmod g+r {} + 2>/dev/null || true

cat > /etc/profile.d/vecta-hsm.sh <<EOF
export HSM_INTEGRATION_WORKSPACE_ROOT="${WORKSPACE_ROOT}"
umask 027
EOF
chmod 0644 /etc/profile.d/vecta-hsm.sh

# Public keys only, root-owned so a session can't add its own.
keys_file="/etc/ssh/authorized_keys/${HSM_USER}"
: > "${keys_file}"
key_count=0
if [ -n "${HSM_INTEGRATION_SSH_AUTHORIZED_KEYS:-}" ]; then
  while IFS= read -r key; do
    key="$(printf '%s' "${key}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "${key}" ] || continue
    case "${key}" in
      ssh-ed25519\ *|ecdsa-sha2-nistp*\ *|sk-ssh-ed25519@openssh.com\ *|sk-ecdsa-sha2-nistp256@openssh.com\ *|ssh-rsa\ *)
        printf '%s\n' "${key}" >> "${keys_file}"
        key_count=$((key_count + 1)) ;;
      *) echo "hsm-integration: ignoring an entry of HSM_INTEGRATION_SSH_AUTHORIZED_KEYS that is not an SSH public key" >&2 ;;
    esac
  done <<< "$(printf '%s' "${HSM_INTEGRATION_SSH_AUTHORIZED_KEYS}" | tr ';' '\n')"
fi
chown root:root "${keys_file}"
chmod 0644 "${keys_file}"
password_auth="yes"
if [ "${key_count}" -gt 0 ]; then
  password_auth="no"
fi

ssh-keygen -A >/dev/null
sed -i '/^[[:space:]]*Subsystem[[:space:]]\+sftp/d' /etc/ssh/sshd_config
# Included before the rest of sshd_config, so these values win.
cat > /etc/ssh/sshd_config.d/90-vecta.conf <<EOF
PermitRootLogin no
AllowUsers ${HSM_USER}
AuthorizedKeysFile /etc/ssh/authorized_keys/%u
PubkeyAuthentication yes
PasswordAuthentication ${password_auth}
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM yes
AllowTcpForwarding no
AllowStreamLocalForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
MaxAuthTries 3
LoginGraceTime 30
LogLevel VERBOSE
Subsystem sftp internal-sftp
EOF
/usr/sbin/sshd -t

echo "hsm-integration: ready user=${HSM_USER} workspace_root=${WORKSPACE_ROOT} password_auth=${password_auth} authorized_keys=${key_count}"
exec /usr/sbin/sshd -D -e
