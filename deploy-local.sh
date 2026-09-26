#!/usr/bin/env bash
# One-command local deployment of Vecta KMS (macOS / Linux with Docker).
#
#   ./deploy-local.sh            build changed images and (re)start the stack
#   ./deploy-local.sh --no-build restart using the images already built
#
# Safe to re-run: it never overwrites existing secrets in .env, keeps all
# volumes (keys, certs, database), and only rebuilds what changed.
# When it finishes the dashboard is at https://localhost
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"
ENV_FILE="${ROOT_DIR}/.env"
BUILD=1
[[ "${1:-}" == "--no-build" ]] && BUILD=0

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. Prerequisites ────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
docker info >/dev/null 2>&1 || die "Docker is not running. Start Docker Desktop and re-run."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (bundled with Docker Desktop)."
command -v openssl >/dev/null 2>&1 || die "openssl is required."

# The platform scripts need Bash 4+ (macOS ships 3.2): brew install bash
pick_bash() {
  local c
  for c in "${BASH:-}" /opt/homebrew/bin/bash /usr/local/bin/bash "${HOME}/.local/bin/bash" /bin/bash; do
    [[ -n "${c}" && -x "${c}" ]] || continue
    "${c}" -c '[[ "${BASH_VERSINFO[0]}" -ge 4 ]]' >/dev/null 2>&1 && { printf '%s' "${c}"; return 0; }
  done
  return 1
}
BASH4="$(pick_bash)" || die "Bash 4+ is required. Install it with: brew install bash"
[[ -f "${ENV_FILE}" ]] || { cp .env.example "${ENV_FILE}"; warn "created .env from .env.example — review the secrets in it."; }

mem_gb="$(docker info --format '{{.MemTotal}}' 2>/dev/null | awk '{printf "%d", $1/1024/1024/1024}')"
if [[ -n "${mem_gb}" && "${mem_gb}" -lt 6 ]]; then
  warn "Docker has ${mem_gb} GB of memory; 8 GB+ is recommended (Docker Desktop → Settings → Resources)."
fi

env_get() { awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}' "${ENV_FILE}"; }
env_set() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  if grep -q "^${key}=" "${ENV_FILE}"; then
    awk -F= -v k="${key}" -v v="${value}" 'BEGIN{OFS="="} $1==k {print k, v; next} {print}' "${ENV_FILE}" > "${tmp}"
  else
    cat "${ENV_FILE}" > "${tmp}"; printf '%s=%s\n' "${key}" "${value}" >> "${tmp}"
  fi
  cat "${tmp}" > "${ENV_FILE}"; rm -f "${tmp}"
}
ensure_secret() {
  local key="$1" value="${2:-}"
  if [[ -z "$(env_get "${key}")" ]]; then
    env_set "${key}" "${value:-$(openssl rand -hex 32)}"
    say "generated ${key} in .env"
  fi
}

# ── 2. Secrets: refuse placeholders, generate anything missing ──────────
# A placeholder copied from an old .env.example ("your-...", "change-me") is a
# public value — never run with one (docs/SECURITY/SECURE_DEFAULTS.md).
placeholders="$(awk -F= '
  $1 ~ /^[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSPHRASE|API_KEY|_KEY_B64)[A-Z0-9_]*$/ && $1 != "AUTH_BOOTSTRAP_ADMIN_PASSWORD" {
    v = tolower(substr($0, index($0, "=") + 1))
    if (v ~ /^your-|change-?me|change_me|replace-?me/) print $1
  }' "${ENV_FILE}")"
[[ -z "${placeholders}" ]] || die "placeholder values in .env for: $(echo ${placeholders}). Run ./scripts/rotate-secrets.sh (see docs/SECURITY/SECRET_ROTATION.md) or set real values."

fips_mode="$(env_get VECTA_FIPS_MODE)"
case "${fips_mode:-on}" in
  on|only|off) ;;
  *) die "VECTA_FIPS_MODE=${fips_mode} is invalid; use on, only or off (docs/SECURITY/FIPS.md)" ;;
esac

cp "${ENV_FILE}" "${ENV_FILE}.bak.deploy.$(date +%s)"
ensure_secret POSTGRES_PASSWORD "$(openssl rand -hex 24)"
ensure_secret NATS_AUTH_TOKEN "$(openssl rand -hex 24)"
ensure_secret WORKLOAD_IDENTITY_SHARED_SECRET
ensure_secret SOFTWARE_VAULT_PASSPHRASE
# Existing values stored under the old built-in key are re-wrapped under this
# one when the secrets service starts (audit.secrets.dev_mek_rewrapped).
ensure_secret SECRETS_MEK_B64 "$(openssl rand -base64 32)"
ensure_secret INTERNAL_SERVICE_BOOTSTRAP_SECRET
ensure_secret INTERNAL_API_TOKEN
if [[ -z "${fips_mode}" ]]; then
  env_set VECTA_FIPS_MODE on
  say "FIPS 140-3 starts on; change it in the KMS UI (System Administration > Runtime Crypto)"
fi
ensure_secret AUTH_BOOTSTRAP_CLI_PASSWORD "Vk$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9')Aa9!"

# Tag images with the release in VERSION so upgrades are traceable.
VERSION_FILE_VALUE="$(tr -d '[:space:]' < VERSION 2>/dev/null || true)"
if [[ -n "${VERSION_FILE_VALUE}" && "$(env_get VECTA_VERSION)" != "${VERSION_FILE_VALUE}" ]]; then
  env_set VECTA_VERSION "${VERSION_FILE_VALUE}"
  say "VECTA_VERSION set to ${VERSION_FILE_VALUE}"
fi

PROJECT="$(env_get COMPOSE_PROJECT_NAME)"; PROJECT="${PROJECT:-vecta-kms}"

# ── 3. Base images (pinned; tagged under vecta-local/ for the Dockerfiles) ─
if [[ "${BUILD}" -eq 1 ]]; then
  say "preparing base images"
  for spec in \
    "vecta-local/golang:1.27.1-alpine|golang:1.27.1-alpine" \
    "vecta-local/alpine:3.24|alpine:3.24" \
    "vecta-local/node:24.21.0-alpine|node:24.21.0-alpine" \
    "vecta-local/nginx:1.30.5-alpine|nginx:1.30.5-alpine" \
    "vecta-local/trivy:0.74.0|aquasec/trivy:0.74.0"; do
    alias_ref="${spec%%|*}"; source_ref="${spec##*|}"
    docker image inspect "${source_ref}" >/dev/null 2>&1 || docker pull -q "${source_ref}" >/dev/null
    docker tag "${source_ref}" "${alias_ref}"
  done

  # Older builds were forced to amd64 (emulated on Apple Silicon). Drop the
  # generated platform pin so images rebuild natively for this machine.
  rm -f .tmp_compose.platform.override.yml

  # Building all ~30 Go services at once runs ~30 compilers in parallel inside
  # the Docker VM and gets OOM-killed ("cannot allocate memory",
  # "compile: signal: killed"). Build one service first to warm the shared Go
  # build cache, then the rest a few at a time (BUILD_JOBS, default 2) — later
  # builds mostly reuse compiled packages and only link.
  export COMPOSE_PROFILES
  COMPOSE_PROFILES="$("${BASH4}" infra/scripts/parse-deployment.sh infra/deployment/deployment.yaml)"
  export COMPOSE_BAKE=false
  BUILD_JOBS="${BUILD_JOBS:-2}"
  services="$(docker compose config --services | sort)"
  warm="sbom"; echo "${services}" | grep -qx "${warm}" || warm="keycore"
  say "building ${warm} first to warm the build cache (first run takes a while)"
  docker compose build "${warm}"
  say "building remaining images, ${BUILD_JOBS} at a time"
  echo "${services}" | grep -vx "${warm}" | xargs -n1 -P "${BUILD_JOBS}" docker compose build --quiet \
    || die "image build failed — re-run with BUILD_JOBS=1 ./deploy-local.sh, and give Docker Desktop 8 GB+ memory"
fi

# ── 4. Keep JWT verification key in sync with the auth signing key ──────
AUTH_VOL="${PROJECT}_auth-data"
sync_jwt_key() {
  local pem pub
  pem="$(docker run --rm -v "${AUTH_VOL}:/a:ro" vecta-local/alpine:3.24 cat /a/jwt_private.pem 2>/dev/null || true)"
  [[ -n "${pem}" ]] || return 1
  pub="$(printf '%s\n' "${pem}" | openssl pkey -pubout 2>/dev/null | base64 | tr -d '\r\n')"
  [[ -n "${pub}" ]] || return 1
  if [[ "$(env_get JWT_PUBLIC_KEY_B64)" != "${pub}" ]]; then
    env_set JWT_PUBLIC_KEY_B64 "${pub}"
    say "updated JWT_PUBLIC_KEY_B64 to match the auth signing key"
    return 2
  fi
  return 0
}
if docker volume inspect "${AUTH_VOL}" >/dev/null 2>&1; then
  sync_jwt_key || true
fi
# Fresh install: no signing key anywhere yet. Mint one into the auth volume so
# JWT_PUBLIC_KEY_B64 (required by compose) is real from the first start.
if [[ -z "$(env_get JWT_PUBLIC_KEY_B64)" ]]; then
  say "generating the auth JWT signing key"
  docker volume create "${AUTH_VOL}" >/dev/null
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null \
    | docker run --rm -i -v "${AUTH_VOL}:/a" vecta-local/alpine:3.24 \
        sh -c 'set -eu; umask 077; [ -s /a/jwt_private.pem ] || cat > /a/jwt_private.pem; chown 100:101 /a/jwt_private.pem' \
    || die "could not seed the auth JWT signing key"
  sync_jwt_key || true
  [[ -n "$(env_get JWT_PUBLIC_KEY_B64)" ]] || die "could not derive JWT_PUBLIC_KEY_B64 from the auth signing key"
fi

# ── 5. Start (volume prep, profiles, mesh bootstrap live in start-kms.sh) ─
say "starting the stack"
"${BASH4}" infra/scripts/start-kms.sh infra/deployment/deployment.yaml --skip-health

# First boot: auth has just generated its signing key — sync and restart verifiers.
set +e; sync_jwt_key; rc=$?; set -e
if [[ "${rc}" -eq 2 ]]; then
  say "restarting services with the new JWT verification key"
  "${BASH4}" infra/scripts/start-kms.sh infra/deployment/deployment.yaml --skip-health
fi

# ── 6. Wait for the dashboard ───────────────────────────────────────────
say "waiting for https://localhost ..."
for _ in $(seq 1 90); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/ || true)"
  [[ "${code}" == "200" ]] && break
  sleep 2
done

unhealthy="$(docker compose ps --format '{{.Service}} {{.Status}}' | grep -v '(healthy)' | grep -v '^$' || true)"
[[ -n "${unhealthy}" ]] && warn "not yet healthy:"$'\n'"${unhealthy}"

cat <<EOF

  Vecta KMS is up.

    Dashboard   https://localhost        (self-signed certificate — accept it once in the browser)
    KMIP        localhost:5696
    Login       tenant: root   user: admin
                password: AUTH_BOOTSTRAP_ADMIN_PASSWORD from .env (you'll be asked to change it on first login)

  Stop:     bash infra/scripts/stop-kms.sh infra/deployment/deployment.yaml
  Logs:     docker compose logs -f <service>

EOF
