#!/usr/bin/env bash
set -euo pipefail

HSM_USER="${HSM_INTEGRATION_USER:-cli-user}"
WORKSPACE_ROOT="${HSM_INTEGRATION_WORKSPACE_ROOT:-/var/lib/vecta/hsm/providers}"

sanitize_user() {
  printf "%s" "$1" | tr -cd '[:alnum:]_.-'
}

HSM_USER="$(sanitize_user "${HSM_USER}")"
if [ -z "${HSM_USER}" ]; then
  HSM_USER="cli-user"
fi

if ! id -u "${HSM_USER}" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "${HSM_USER}"
fi

# Lock password by default — the KMS auth service syncs the password
# from user management when an SSH session is opened via the dashboard.
passwd -l "${HSM_USER}" 2>/dev/null || true
usermod -aG sudo "${HSM_USER}"

cat > /etc/sudoers.d/90-hsm-integration <<EOF
${HSM_USER} ALL=(ALL) NOPASSWD:ALL
EOF
chmod 0440 /etc/sudoers.d/90-hsm-integration

mkdir -p "${WORKSPACE_ROOT}"
chown -R "${HSM_USER}:${HSM_USER}" /var/lib/vecta/hsm
chmod 0750 /var/lib/vecta/hsm
chmod 0750 "${WORKSPACE_ROOT}"

cat > /etc/profile.d/vecta-hsm.sh <<EOF
export HSM_INTEGRATION_WORKSPACE_ROOT="${WORKSPACE_ROOT}"
EOF
chmod 0644 /etc/profile.d/vecta-hsm.sh

mkdir -p /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "${SSHD_CONFIG}" ]; then
  sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' "${SSHD_CONFIG}"
  sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' "${SSHD_CONFIG}"
  sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' "${SSHD_CONFIG}"
  sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication yes/' "${SSHD_CONFIG}"
  sed -i 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication yes/' "${SSHD_CONFIG}"
  if ! grep -q "^KbdInteractiveAuthentication " "${SSHD_CONFIG}"; then
    echo "KbdInteractiveAuthentication yes" >> "${SSHD_CONFIG}"
  fi
  sed -i 's/^#\?UsePAM .*/UsePAM yes/' "${SSHD_CONFIG}"
  sed -i 's|^#\?Subsystem sftp .*|Subsystem sftp /usr/lib/openssh/sftp-server|' "${SSHD_CONFIG}" || true
  if ! grep -q "^AllowUsers " "${SSHD_CONFIG}"; then
    echo "AllowUsers ${HSM_USER}" >> "${SSHD_CONFIG}"
  fi
fi

echo "hsm-integration: ready user=${HSM_USER} workspace_root=${WORKSPACE_ROOT}"
exec /usr/sbin/sshd -D -e
