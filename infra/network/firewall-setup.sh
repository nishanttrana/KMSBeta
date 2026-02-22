#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${1:-/etc/vecta/network.yaml}"
OUT_FILE="${2:-/etc/nftables.d/vecta-kms.nft}"

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "network config not found: ${CONFIG_FILE}" >&2
  exit 1
fi

python3 - "${CONFIG_FILE}" "${OUT_FILE}" <<'PY'
import pathlib
import sys
import yaml

cfg = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
out = pathlib.Path(sys.argv[2])
firewall = cfg.get("firewall", {})

if not firewall.get("enabled", True):
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "table inet vecta_kms {\n"
        "  chain input {\n"
        "    type filter hook input priority 0;\n"
        "    policy accept;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    raise SystemExit(0)

def ports_for(zone):
    return firewall.get("allowed_ports", {}).get(zone, [])

management_ports = ports_for("management")
cluster_ports = ports_for("cluster")
hsm_ports = ports_for("hsm")

def fmt_ports(values):
    if not values:
        return ""
    return ", ".join(str(int(v)) for v in values)

rules = f"""table inet vecta_kms {{
  chain input {{
    type filter hook input priority 0;
    policy drop;

    iif lo accept
    ct state established,related accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
"""

if management_ports:
    rules += f"    tcp dport {{ {fmt_ports(management_ports)} }} accept\n"
if cluster_ports:
    rules += f"    tcp dport {{ {fmt_ports(cluster_ports)} }} accept\n"
if hsm_ports:
    rules += f"    tcp dport {{ {fmt_ports(hsm_ports)} }} accept\n"

rules += "  }\n}\n"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(rules, encoding="utf-8")
PY

nft -f "${OUT_FILE}"
