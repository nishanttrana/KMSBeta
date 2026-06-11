#!/usr/bin/env bash
# Platform conformance check: enforces the two centralization rules.
#
#   1. Single crypto library — services must not import stdlib/x crypto
#      primitives directly; everything goes through vecta-kms/pkg/crypto.
#   2. Single audit pipeline — services must not create their own audit
#      streams or publish audit events outside vecta-kms/pkg/audit.
#
# Files listed in scripts/conformance-allowlist.txt are exempted (one path
# per line, # comments allowed). The allowlist is a burn-down list: it only
# shrinks. Run with -v to list every violation.
set -euo pipefail
cd "$(dirname "$0")/.."

ALLOWLIST="scripts/conformance-allowlist.txt"
VERBOSE="${1:-}"
FAIL=0

# Imports that only pkg/crypto (and explicitly exempted providers) may use.
CRYPTO_IMPORTS='"crypto/aes"|"crypto/rsa"|"crypto/ecdsa"|"crypto/ed25519"|"crypto/elliptic"|"crypto/rand"|"crypto/des"|"crypto/rc4"|"crypto/md5"|"crypto/sha1"'

allowed() {
  [ -f "$ALLOWLIST" ] || return 1
  grep -v '^\s*#' "$ALLOWLIST" | grep -qxF "$1"
}

check() {
  local rule="$1" pattern="$2" scope="$3"
  local hits violations=()
  hits=$(grep -rlE "$pattern" $scope --include="*.go" 2>/dev/null | grep -v '_test\.go$' || true)
  for f in $hits; do
    allowed "$f" || violations+=("$f")
  done
  if [ "${#violations[@]}" -gt 0 ]; then
    FAIL=1
    echo "FAIL [$rule]: ${#violations[@]} file(s) violate"
    if [ "$VERBOSE" = "-v" ]; then printf '  %s\n' "${violations[@]}"; fi
  else
    echo "PASS [$rule]"
  fi
}

echo "== Vecta KMS conformance =="

# Rule 1: no direct crypto primitive imports in services.
check "central-crypto" "$CRYPTO_IMPORTS" "services"

# Rule 2a: no per-service audit streams; the unified AUDIT stream is owned
# by pkg/audit (canonical config) and converged by the audit service.
check "single-audit-stream" 'AddStream\(&nats\.StreamConfig\{Name: "AUDIT' "services"

# Rule 2b: no raw JetStream publishes onto audit.> outside pkg/audit and
# pkg/auditmw (services must use pkgaudit.Client.Emit).
check "single-audit-emit" 'Publish(Msg)?\((ctx, )?"audit\.' "services"

# Burn-down report.
if [ -f "$ALLOWLIST" ]; then
  COUNT=$(grep -cv '^\s*#' "$ALLOWLIST" || true)
  echo "-- allowlist burn-down: $COUNT file(s) still exempted"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "Conformance FAILED. Use pkg/crypto for primitives and pkg/audit for events,"
  echo "or (temporarily) add the file to $ALLOWLIST with a justification comment."
  exit 1
fi
echo "Conformance OK."
