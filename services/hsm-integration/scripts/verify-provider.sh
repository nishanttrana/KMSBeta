#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <pkcs11_library_path>" >&2
  exit 1
fi

library_path="$1"
if [ ! -f "${library_path}" ]; then
  echo "pkcs11 library not found: ${library_path}" >&2
  exit 1
fi

echo "== File metadata =="
ls -l "${library_path}"
echo
echo "== SHA256 =="
sha256sum "${library_path}"
