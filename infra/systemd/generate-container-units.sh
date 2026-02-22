#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST_FILE="${ROOT_DIR}/container-services.txt"
OUT_DIR="${ROOT_DIR}/containers"

mkdir -p "${OUT_DIR}"

while IFS= read -r svc; do
  [[ -z "${svc}" ]] && continue
  cat > "${OUT_DIR}/vecta-${svc}.service" <<EOF
[Unit]
Description=Vecta KMS Container (${svc})
After=docker.service network-online.target
Wants=network-online.target
PartOf=vecta-containers.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/vecta
EnvironmentFile=-/etc/vecta/vecta.env
ExecStart=/usr/bin/docker compose -f /opt/vecta/docker-compose.yml up -d ${svc}
ExecStop=/usr/bin/docker compose -f /opt/vecta/docker-compose.yml stop ${svc}
ExecReload=/usr/bin/docker compose -f /opt/vecta/docker-compose.yml up -d ${svc}
TimeoutStartSec=300
TimeoutStopSec=120

[Install]
WantedBy=vecta-containers.target
EOF
done < "${LIST_FILE}"

echo "generated container units under ${OUT_DIR}"
