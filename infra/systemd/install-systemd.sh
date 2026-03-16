#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYSTEMD_DIR="${ROOT_DIR}/infra/systemd"

bash "${SYSTEMD_DIR}/generate-container-units.sh"

sudo install -D -m 0644 "${SYSTEMD_DIR}/vecta-stack.service" /etc/systemd/system/vecta-stack.service
sudo install -D -m 0644 "${SYSTEMD_DIR}/vecta-deployment.path" /etc/systemd/system/vecta-deployment.path
sudo install -D -m 0644 "${SYSTEMD_DIR}/vecta-healthcheck.service" /etc/systemd/system/vecta-healthcheck.service
sudo install -D -m 0644 "${SYSTEMD_DIR}/vecta-healthcheck.timer" /etc/systemd/system/vecta-healthcheck.timer
sudo install -D -m 0644 "${SYSTEMD_DIR}/vecta-containers.target" /etc/systemd/system/vecta-containers.target

if compgen -G "${SYSTEMD_DIR}/containers/*.service" >/dev/null; then
  sudo cp "${SYSTEMD_DIR}"/containers/*.service /etc/systemd/system/
fi

sudo systemctl daemon-reload
sudo systemctl enable vecta-stack.service
sudo systemctl enable vecta-deployment.path
sudo systemctl enable vecta-healthcheck.timer

echo "systemd units installed"
