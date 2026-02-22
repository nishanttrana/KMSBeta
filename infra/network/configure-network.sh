#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${1:-/etc/vecta/network.yaml}"
TEMPLATE_DIR="${2:-/opt/vecta/infra/network/templates}"
OUT_DIR="${3:-/etc/systemd/network}"

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "network config not found: ${CONFIG_FILE}" >&2
  exit 1
fi

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
  echo "template directory not found: ${TEMPLATE_DIR}" >&2
  exit 1
fi

python3 - "${CONFIG_FILE}" "${TEMPLATE_DIR}" "${OUT_DIR}" <<'PY'
import pathlib
import sys
import yaml

cfg_path = pathlib.Path(sys.argv[1])
tpl_dir = pathlib.Path(sys.argv[2])
out_dir = pathlib.Path(sys.argv[3])
cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
out_dir.mkdir(parents=True, exist_ok=True)

def render(template_name: str, values: dict[str, str], enabled: bool = True):
    tpl = (tpl_dir / template_name).read_text(encoding="utf-8")
    for k, v in values.items():
        tpl = tpl.replace(f"__{k}__", v or "")
    path = out_dir / template_name
    if enabled:
        path.write_text(tpl, encoding="utf-8")
    elif path.exists():
        path.unlink()

mgmt = cfg.get("management", {})
mgmt_mode = (mgmt.get("mode", "dhcp") or "dhcp").lower()
is_dhcp = mgmt_mode == "dhcp"
render(
    "10-management.network",
    {
        "IFACE": mgmt.get("interface", "eth0"),
        "MODE": "yes" if is_dhcp else "no",
        "ADDRESS_LINE": "" if is_dhcp else f"Address={mgmt.get('ipv4', {}).get('address', '')}",
        "GATEWAY_LINE": "" if is_dhcp else f"Gateway={mgmt.get('ipv4', {}).get('gateway', '')}",
        "DNS": " ".join(mgmt.get("ipv4", {}).get("dns", [])),
    },
    enabled=True,
)

cluster = cfg.get("cluster", {})
render(
    "20-cluster.network",
    {
        "IFACE": cluster.get("interface", "eth1"),
        "ADDR": cluster.get("ipv4", {}).get("address", ""),
        "MTU": str(cluster.get("mtu", 9000)),
    },
    enabled=bool(cluster.get("enabled", False)),
)

hsm = cfg.get("hsm", {})
render(
    "30-hsm.network",
    {
        "IFACE": hsm.get("interface", "eth2"),
        "ADDR": hsm.get("ipv4", {}).get("address", ""),
    },
    enabled=bool(hsm.get("enabled", False)),
)
PY

systemctl restart systemd-networkd
