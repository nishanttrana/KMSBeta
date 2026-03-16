#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="/tmp/vecta-kms-src"
DEST_DIR="/opt/vecta"
CONFIG_DIR="/etc/vecta"

if [[ ! -d "${SRC_DIR}" ]]; then
  echo "missing source directory: ${SRC_DIR}" >&2
  exit 1
fi

sudo rm -rf "${DEST_DIR}"
sudo mkdir -p "${DEST_DIR}"
sudo cp -a "${SRC_DIR}/." "${DEST_DIR}/"
sudo install -d -m 0750 "${CONFIG_DIR}"
sudo install -d -m 0750 "${CONFIG_DIR}/examples"
sudo install -m 0644 "${DEST_DIR}/infra/deployment/deployment.schema.json" "${CONFIG_DIR}/deployment.schema.json"
sudo install -m 0644 "${DEST_DIR}/infra/deployment/deployment.yaml" "${CONFIG_DIR}/examples/deployment.example.yaml"
sudo install -m 0644 "${DEST_DIR}/infra/deployment/README.md" "${CONFIG_DIR}/examples/README.md"

sudo install -D -m 0644 "${DEST_DIR}/infra/systemd/vecta-stack.service" /etc/systemd/system/vecta-stack.service
sudo install -D -m 0644 "${DEST_DIR}/infra/systemd/vecta-deployment.path" /etc/systemd/system/vecta-deployment.path
sudo install -D -m 0644 "${DEST_DIR}/infra/systemd/vecta-healthcheck.service" /etc/systemd/system/vecta-healthcheck.service
sudo install -D -m 0644 "${DEST_DIR}/infra/systemd/vecta-healthcheck.timer" /etc/systemd/system/vecta-healthcheck.timer
sudo install -D -m 0644 "${DEST_DIR}/infra/systemd/vecta-containers.target" /etc/systemd/system/vecta-containers.target

if compgen -G "${DEST_DIR}/infra/systemd/containers/*.service" >/dev/null; then
  sudo cp "${DEST_DIR}"/infra/systemd/containers/*.service /etc/systemd/system/
fi

sudo systemctl daemon-reload
sudo systemctl enable vecta-stack.service
sudo systemctl enable vecta-deployment.path
sudo systemctl enable vecta-healthcheck.timer
