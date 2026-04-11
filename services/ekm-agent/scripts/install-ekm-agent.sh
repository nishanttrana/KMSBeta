#!/usr/bin/env bash
# install-ekm-agent.sh — Install the Vecta EKM Agent on Linux or macOS.
# Must be run as root (sudo ./install-ekm-agent.sh ...).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./install-ekm-agent.sh [OPTIONS]

Required:
  --tenant-id          TENANT        Vecta tenant identifier
  --agent-id           AGENT_ID      Unique agent identifier
  --agent-name         NAME          Human-readable agent name
  --api-base-url       URL           Vecta KMS base URL (e.g. https://kms.acme.com)

Optional:
  --mode               MODE          tde | bitlocker | pkcs11 | azure-ekm | google-cse (default: tde)
  --db-engine          ENGINE        mssql | mysql | postgresql | oracle | mariadb (default: mssql)
  --host               IP            Database host IP (default: 127.0.0.1)
  --auth-token         TOKEN         Bearer token (optional; prefer env VECTA_AUTH_TOKEN)
  --db-dsn             DSN           Full DSN (overrides individual db-* options)
  --db-user            USER
  --db-password        PASS          (prefer env VECTA_DB_PASSWORD)
  --db-name            NAME
  --db-port            PORT          Default derived from engine
  --heartbeat-sec      N             Heartbeat interval seconds (default: 30)
  --rotation-days      N             Key rotation cycle days (default: 90)
  --pkcs11-module      PATH          PKCS#11 .so path (default: /usr/lib/opensc-pkcs11.so)
  --pkcs11-slot        N             PKCS#11 slot ID (default: 0)
  --install-dir        DIR           Install directory (default: /opt/vecta/ekm-agent)
  --no-service                       Write config only; skip systemd service installation

EOF
  exit 1
}

# ── Defaults ─────────────────────────────────────────────────────
TENANT_ID=""
AGENT_ID=""
AGENT_NAME=""
API_BASE_URL=""
MODE="tde"
DB_ENGINE="mssql"
HOST_IP="127.0.0.1"
AUTH_TOKEN="${VECTA_AUTH_TOKEN:-}"
DB_DSN=""
DB_USER=""
DB_PASSWORD="${VECTA_DB_PASSWORD:-}"
DB_NAME=""
DB_PORT=0
HEARTBEAT_SEC=30
ROTATION_DAYS=90
PKCS11_MODULE="/usr/lib/opensc-pkcs11.so"
PKCS11_SLOT=0
INSTALL_DIR="/opt/vecta/ekm-agent"
NO_SERVICE=0

# ── Parse args ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tenant-id)     TENANT_ID="$2";    shift 2 ;;
    --agent-id)      AGENT_ID="$2";     shift 2 ;;
    --agent-name)    AGENT_NAME="$2";   shift 2 ;;
    --api-base-url)  API_BASE_URL="$2"; shift 2 ;;
    --mode)          MODE="$2";         shift 2 ;;
    --db-engine)     DB_ENGINE="$2";    shift 2 ;;
    --host)          HOST_IP="$2";      shift 2 ;;
    --auth-token)    AUTH_TOKEN="$2";   shift 2 ;;
    --db-dsn)        DB_DSN="$2";       shift 2 ;;
    --db-user)       DB_USER="$2";      shift 2 ;;
    --db-password)   DB_PASSWORD="$2";  shift 2 ;;
    --db-name)       DB_NAME="$2";      shift 2 ;;
    --db-port)       DB_PORT="$2";      shift 2 ;;
    --heartbeat-sec) HEARTBEAT_SEC="$2"; shift 2 ;;
    --rotation-days) ROTATION_DAYS="$2"; shift 2 ;;
    --pkcs11-module) PKCS11_MODULE="$2"; shift 2 ;;
    --pkcs11-slot)   PKCS11_SLOT="$2";  shift 2 ;;
    --install-dir)   INSTALL_DIR="$2";  shift 2 ;;
    --no-service)    NO_SERVICE=1;      shift ;;
    -h|--help)       usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

[[ -z "$TENANT_ID" || -z "$AGENT_ID" || -z "$AGENT_NAME" || -z "$API_BASE_URL" ]] && {
  echo "ERROR: --tenant-id, --agent-id, --agent-name, and --api-base-url are required."
  usage
}

# Resolve default DB port
if [[ "$DB_PORT" -le 0 ]]; then
  case "$DB_ENGINE" in
    mssql)      DB_PORT=1433 ;;
    mysql|mariadb) DB_PORT=3306 ;;
    postgresql) DB_PORT=5432 ;;
    oracle)     DB_PORT=1521 ;;
    *)          DB_PORT=1433 ;;
  esac
fi

# ── Validate binary ───────────────────────────────────────────────
AGENT_BIN="./ekm-agent"
if [[ "$(uname -s)" == "Darwin" ]]; then
  AGENT_BIN="./ekm-agent-darwin"
fi
[[ -f "$AGENT_BIN" ]] || { echo "ERROR: $AGENT_BIN not found. Download the agent package first."; exit 1; }

echo ""
echo "Vecta EKM Agent Installer"
echo "  Mode:   $MODE"
echo "  Agent:  $AGENT_ID ($AGENT_NAME)"
echo "  Tenant: $TENANT_ID"
echo "  URL:    $API_BASE_URL"
echo ""

# ── Install binary ────────────────────────────────────────────────
install -d "$INSTALL_DIR"
install -m 0750 "$AGENT_BIN" "$INSTALL_DIR/ekm-agent"

# ── Write config ──────────────────────────────────────────────────
CFG="$INSTALL_DIR/agent-config.json"

# Build JSON with Python (available on all target platforms) or jq
build_config() {
python3 - <<PYEOF
import json, sys

cfg = {
  "tenant_id":              "$TENANT_ID",
  "agent_id":               "$AGENT_ID",
  "agent_name":             "$AGENT_NAME",
  "mode":                   "$MODE",
  "role":                   "ekm-agent",
  "db_engine":              "$DB_ENGINE",
  "host":                   "$HOST_IP",
  "version":                "",
  "api_base_url":           "$API_BASE_URL",
  "register_path":          "/ekm/agents/register",
  "heartbeat_path":         "/ekm/agents/{agent_id}/heartbeat",
  "rotate_path":            "/ekm/agents/{agent_id}/rotate",
  "auth_token":             "$AUTH_TOKEN",
  "tls_skip_verify":        False,
  "heartbeat_interval_sec": $HEARTBEAT_SEC,
  "rotation_cycle_days":    $ROTATION_DAYS,
  "auto_provision_tde":     True,
  "db_dsn":                 "$DB_DSN",
  "db_user":                "$DB_USER",
  "db_password":            "$DB_PASSWORD",
  "db_name":                "$DB_NAME",
  "db_port":                $DB_PORT,
  "active_key_id":          "",
  "active_key_version":     "v1",
  "config_version_ack":     0,
}

if "$MODE" in ("pkcs11",) or "$DB_ENGINE" in ("mssql", "oracle"):
    cfg["pkcs11"] = {
        "module_path": "$PKCS11_MODULE",
        "slot_id":     $PKCS11_SLOT,
        "pin_env":     "PKCS11_PIN",
    }

if "$MODE" == "bitlocker":
    cfg["bitlocker"] = {
        "protect_os_volume":    True,
        "protect_data_volumes": True,
        "require_tpm":          True,
        "key_rotation_days":    $ROTATION_DAYS,
        "escrow_to_vecta":      True,
    }

print(json.dumps(cfg, indent=2))
PYEOF
}

build_config > "$CFG"
chmod 0640 "$CFG"
echo "  Config written: $CFG"

# ── Systemd service (Linux only) ──────────────────────────────────
if [[ "$NO_SERVICE" -eq 0 && "$(uname -s)" == "Linux" ]]; then
  UNIT="/etc/systemd/system/vecta-ekm-agent.service"
  cat > "$UNIT" <<UNIT
[Unit]
Description=Vecta EKM Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/ekm-agent -config $CFG
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable vecta-ekm-agent
  systemctl restart vecta-ekm-agent
  sleep 2
  systemctl is-active --quiet vecta-ekm-agent && \
    echo "  Service:  vecta-ekm-agent [running]" || \
    echo "  WARNING:  service not running — check: journalctl -u vecta-ekm-agent"
fi

# ── launchd (macOS) ───────────────────────────────────────────────
if [[ "$NO_SERVICE" -eq 0 && "$(uname -s)" == "Darwin" ]]; then
  PLIST="/Library/LaunchDaemons/com.vecta.ekm-agent.plist"
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.vecta.ekm-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$INSTALL_DIR/ekm-agent</string>
    <string>-config</string>
    <string>$CFG</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/vecta-ekm-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/vecta-ekm-agent.log</string>
</dict>
</plist>
PLIST
  launchctl load -w "$PLIST"
  echo "  Service:  com.vecta.ekm-agent [launchd]"
fi

echo ""
echo "Vecta EKM Agent installed."
echo "  Install dir : $INSTALL_DIR"
echo "  Config      : $CFG"
echo "  Mode        : $MODE"
echo ""
