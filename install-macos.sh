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

pick_bash() {
  local candidate
  for candidate in "${BASH:-}" /opt/homebrew/bin/bash /usr/local/bin/bash /bin/bash; do
    [[ -n "${candidate}" && -x "${candidate}" ]] || continue
    if "${candidate}" -lc '[[ "${BASH_VERSINFO[0]}" -ge 4 ]]' >/dev/null 2>&1; then
      printf "%s" "${candidate}"
      return 0
    fi
  done
  return 1
}

BASH_BIN="$(pick_bash || true)"
if [[ -z "${BASH_BIN}" ]]; then
  echo "[ERROR] install.sh requires Bash 4+." >&2
  echo "Install a newer bash first, for example: brew install bash" >&2
  exit 1
fi

chmod +x "${INSTALL_SCRIPT}" || true
exec "${BASH_BIN}" "${INSTALL_SCRIPT}" "$@"
