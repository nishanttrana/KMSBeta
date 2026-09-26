#!/usr/bin/env bash
# Rotate the passphrase that seals the certs root wrapping key (CRWK)
# (docs/SECURITY/SECRET_ROTATION.md).
#
# The current passphrase is moved aside as bootstrap.passphrase.previous and a
# new one is generated inside the certs key volume; certs is then recreated.
# On start it re-keys the CRWK, rewraps every CA signer under the new key,
# deletes the previous passphrase and emits audit.certs.crwk_rotated.
# No passphrase is printed, logged or put on a command line.
#
# Usage:  ./scripts/rotate-crwk-passphrase.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
[ -f "${ENV_FILE}" ] || { echo "error: ${ENV_FILE} not found" >&2; exit 1; }
env_get() { awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}' "${ENV_FILE}"; }

project="$(env_get COMPOSE_PROJECT_NAME)"
volume="${project:-vecta-kms}_certs-key-data"
compose() { bash "${ROOT_DIR}/infra/scripts/compose-kms.sh" --profile certs "$@"; }

rotate_in_volume() {
  # An inline passphrase in .env (CERTS_CRWK_BOOTSTRAP_PASSPHRASE) takes
  # precedence over the file; it becomes the previous one and is cleared.
  local CRWK_PREVIOUS
  CRWK_PREVIOUS="$(env_get CERTS_CRWK_BOOTSTRAP_PASSPHRASE)"
  export CRWK_PREVIOUS
  docker run --rm -e CRWK_PREVIOUS -v "${volume}:/data" alpine:3.24 sh -c '
    set -eu
    umask 077
    cd /data
    if [ -e bootstrap.passphrase.previous ]; then
      echo "error: a rotation is already pending; start certs to finish it first" >&2
      exit 3
    fi
    if [ -n "${CRWK_PREVIOUS}" ]; then
      printf "%s" "${CRWK_PREVIOUS}" > bootstrap.passphrase.previous
      rm -f bootstrap.passphrase
    else
      [ -s bootstrap.passphrase ] || { echo "error: no current passphrase in the volume" >&2; exit 3; }
      mv bootstrap.passphrase bootstrap.passphrase.previous
    fi
    head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n" > bootstrap.passphrase.tmp
    mv bootstrap.passphrase.tmp bootstrap.passphrase
    chown 100:101 bootstrap.passphrase bootstrap.passphrase.previous
    chmod 600 bootstrap.passphrase bootstrap.passphrase.previous
  '
}

compose stop certs
rotate_in_volume
if [ -n "$(env_get CERTS_CRWK_BOOTSTRAP_PASSPHRASE)" ]; then
  cp "${ENV_FILE}" "${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
  tmp="$(mktemp)"
  awk -F= 'BEGIN{OFS="="} $1=="CERTS_CRWK_BOOTSTRAP_PASSPHRASE" {print $1, ""; next} {print}' "${ENV_FILE}" > "${tmp}"
  cat "${tmp}" > "${ENV_FILE}"
  rm -f "${tmp}"
  echo "cleared CERTS_CRWK_BOOTSTRAP_PASSPHRASE in .env (backup kept); the passphrase now lives only in the certs key volume"
fi
compose up -d --no-deps --force-recreate certs
echo "certs recreated; it rewraps every CA signer on start. Confirm with the audit event audit.certs.crwk_rotated (result success)."
