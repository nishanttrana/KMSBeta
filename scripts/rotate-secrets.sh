#!/usr/bin/env bash
# Rotate the bootstrap/shared dev secrets in the local .env.
#
# This rotates the CONFIGURED values only (writes a fresh .env, keeps a
# timestamped backup). It does NOT touch running containers or data volumes.
# Applying the new secrets to an already-running stack requires the operational
# steps printed at the end (and documented in docs/SECURITY/SECRET_ROTATION.md),
# because some secrets are baked into persistent volumes on first start.
#
# Usage:  ./scripts/rotate-secrets.sh [path-to-.env]
set -euo pipefail

ENV_FILE="${1:-$(cd "$(dirname "$0")/.." && pwd)/.env}"
[ -f "$ENV_FILE" ] || { echo "error: $ENV_FILE not found (copy .env.example to .env first)"; exit 1; }
command -v openssl >/dev/null || { echo "error: openssl is required"; exit 1; }

BACKUP="${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
cp "$ENV_FILE" "$BACKUP"
echo "backed up -> $BACKUP"

# URL/connection-string-safe (hex) for values that appear in DSNs or headers.
hex() { openssl rand -hex "$1"; }
# Policy-compliant password: >=12 chars, upper+lower+digit+special, no whitespace.
strong_pw() { printf 'Vk%sAa9!' "$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9')"; }

# key=generator pairs (bash 3.2 compatible — no associative arrays).
set_secret() {
  local key="$1" val="$2"
  local esc
  esc=$(printf '%s' "$val" | sed -e 's/[&|\\]/\\&/g')
  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i.tmp -E "s|^${key}=.*|${key}=${esc}|" "$ENV_FILE" && rm -f "${ENV_FILE}.tmp"
    echo "rotated ${key}"
  else
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
    echo "added   ${key}"
  fi
}

set_secret POSTGRES_PASSWORD                "$(hex 24)"
set_secret NATS_AUTH_TOKEN                  "$(hex 24)"
set_secret WORKLOAD_IDENTITY_SHARED_SECRET "$(hex 32)"
set_secret SOFTWARE_VAULT_PASSPHRASE       "$(hex 32)"
set_secret INTERNAL_API_TOKEN              "$(hex 32)"
set_secret AUTH_BOOTSTRAP_ADMIN_PASSWORD   "$(strong_pw)"
set_secret AUTH_BOOTSTRAP_CLI_PASSWORD     "$(strong_pw)"

cat <<'NEXT'

Configured secrets rotated in .env. To APPLY to a running stack (non-destructive
where possible) — see docs/SECURITY/SECRET_ROTATION.md:

  1) Postgres password (volume keeps the old one): change it in place, do NOT
     just restart:
       docker compose exec postgres \
         psql -U "$POSTGRES_USER" -c "ALTER USER \"$POSTGRES_USER\" PASSWORD '<new POSTGRES_PASSWORD>';"
  2) Shared service tokens (NATS / internal / workload identity): recreate all
     containers together so every service shares the new value:
       docker compose up -d --force-recreate
  3) Admin/CLI bootstrap passwords only seed a FRESH auth volume. For an existing
     deployment, rotate the live admin password via the dashboard / auth API.
  4) Software vault passphrase: if the vault already sealed data with the old
     passphrase, run the vault rekey/re-seal flow before restarting that service.

Old values are preserved in the backup printed above.
NEXT
