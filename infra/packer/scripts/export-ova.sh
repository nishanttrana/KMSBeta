#!/usr/bin/env bash
set -euo pipefail

: "${OVF_DIR:?OVF_DIR is required}"
: "${VM_NAME:?VM_NAME is required}"
: "${OUTPUT_DIR:?OUTPUT_DIR is required}"

mkdir -p "${OUTPUT_DIR}"

if ! command -v ovftool >/dev/null 2>&1; then
  echo "ovftool is not installed; skipping OVA export for ${VM_NAME}" >&2
  exit 0
fi

VMX_FILE="$(find "${OVF_DIR}" -maxdepth 2 -name '*.vmx' | head -n 1)"
if [[ -z "${VMX_FILE}" ]]; then
  echo "vmx output not found in ${OVF_DIR}" >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${OUTPUT_DIR}/${VM_NAME}-${STAMP}.ova"
ovftool "${VMX_FILE}" "${OUT_FILE}"
echo "OVA exported: ${OUT_FILE}"
