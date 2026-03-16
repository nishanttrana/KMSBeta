#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${ROOT_DIR}/infra/packer/kms-appliance.pkr.hcl"
ISO_CHECKSUM="${ISO_CHECKSUM:-}"
PACKER_VAR_FILE="${PACKER_VAR_FILE:-}"

if ! command -v packer >/dev/null 2>&1; then
  echo "packer is required but not installed" >&2
  exit 1
fi

if [[ -z "${ISO_CHECKSUM}" ]]; then
  echo "ISO_CHECKSUM is required (example: sha256:<ubuntu-24.04-sha256>)" >&2
  exit 1
fi

if [[ -n "${PACKER_VAR_FILE}" && ! -f "${PACKER_VAR_FILE}" ]]; then
  PACKER_VAR_FILE="${ROOT_DIR}/${PACKER_VAR_FILE}"
fi
if [[ -n "${PACKER_VAR_FILE}" && ! -f "${PACKER_VAR_FILE}" ]]; then
  echo "PACKER_VAR_FILE not found: ${PACKER_VAR_FILE}" >&2
  exit 1
fi

packer init "${TEMPLATE}"
packer fmt "${TEMPLATE}"
build_args=()
if [[ -n "${PACKER_VAR_FILE}" ]]; then
  build_args+=(-var-file "${PACKER_VAR_FILE}")
fi

packer build \
  "${build_args[@]}" \
  -var "iso_checksum=${ISO_CHECKSUM}" \
  -var "source_directory=${ROOT_DIR}" \
  -var "output_directory=${ROOT_DIR}/infra/packer/output" \
  "${TEMPLATE}"
