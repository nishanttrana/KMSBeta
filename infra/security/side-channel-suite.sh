#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=infra/security/common.sh
source "${SCRIPT_DIR}/common.sh"

CHECK_NAME="side-channel"
CHECK_DIR="$(init_check_dir "${CHECK_NAME}")"
GO_BIN="${GO_BIN:-$(detect_go_bin)}"

if [[ -z "${GO_BIN}" ]]; then
  write_status "${CHECK_NAME}" "FAIL" "go toolchain not found in PATH"
  printf 'go command is required for side-channel suite.\n' > "${CHECK_DIR}/error.txt"
  exit 1
fi

pushd "${ROOT_DIR}" >/dev/null
if "${GO_BIN}" test ./infra/security/side-channel-tests -count=1 -json > "${CHECK_DIR}/go-test.json" 2> "${CHECK_DIR}/go-test.stderr"; then
  write_status "${CHECK_NAME}" "PASS" "go test ./infra/security/side-channel-tests completed successfully"
  popd >/dev/null
  exit 0
fi
popd >/dev/null

write_status "${CHECK_NAME}" "FAIL" "side-channel timing or memory tests failed"
exit 1
