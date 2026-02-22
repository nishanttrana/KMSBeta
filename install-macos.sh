#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SCRIPT="${SCRIPT_DIR}/install.sh"

if [[ "$(uname -s 2>/dev/null || true)" != "Darwin" ]]; then
  echo "[WARN] install-macos.sh is intended for macOS hosts."
fi

if [[ ! -f "${INSTALL_SCRIPT}" ]]; then
  echo "[ERROR] install.sh not found next to install-macos.sh" >&2
  exit 1
fi

chmod +x "${INSTALL_SCRIPT}" || true
exec "${INSTALL_SCRIPT}" "$@"
