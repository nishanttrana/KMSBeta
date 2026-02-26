#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <pkcs11_library_path> [slot_id]" >&2
  exit 1
fi

library_path="$1"
slot_id="${2:-}"

if [ ! -f "${library_path}" ]; then
  echo "pkcs11 library not found: ${library_path}" >&2
  exit 1
fi

echo "== PKCS#11 Slots =="
pkcs11-tool --module "${library_path}" -L

if [ -n "${slot_id}" ]; then
  echo
  echo "== Slot ${slot_id} Token Detail =="
  pkcs11-tool --module "${library_path}" --slot "${slot_id}" -T || true
fi
