#!/usr/bin/env bash
# Runs cloud BYOK against real cloud accounts, with credentials you supply
# (docs/SECURITY/CLOUD_BYOK_LIVE_VERIFICATION.md).
#
#   scripts/verify-byok-live.sh [settings-file]
#   scripts/verify-byok-live.sh --from-env     (CI: settings are already in
#                                               the environment)
#
# The settings file (default .byok-live.env, ignored by git; start from
# scripts/byok-live.env.example) holds VECTA_TEST_BYOK_* names and values.
# It is read by this shell only: no value is printed, passed on a command
# line or written anywhere.
#
# THIS CREATES A REAL KEY in each cloud you fill in: it imports fresh key
# material, uses the key, rotates, revokes and restores it, then schedules
# the key for deletion. A cloud bills for the key until it is gone. Use a
# test account.
#
# Works under macOS's bash 3.2.
set -u

FILE="${1:-.byok-live.env}"
cd "$(dirname "$0")/.." || exit 2
if [ "$FILE" = "--from-env" ]; then
  FILE="the environment"
else
  if [ ! -f "$FILE" ]; then
    echo "No settings file at $FILE. Copy scripts/byok-live.env.example to $FILE and fill in the clouds to check." >&2
    exit 2
  fi
  # A file of secrets that others can read is a leak waiting to happen.
  perms="$(stat -f '%Lp' "$FILE" 2>/dev/null || stat -c '%a' "$FILE" 2>/dev/null)"
  case "$perms" in
    600|400) ;;
    *) echo "$FILE is readable by others (mode $perms). Run: chmod 600 $FILE" >&2; exit 2 ;;
  esac
  set -a
  # shellcheck disable=SC1090
  . "$FILE"
  set +a
fi

configured=""
if [ -n "${VECTA_TEST_BYOK_AWS_ACCESS_KEY:-}" ]; then
  if [ "${VECTA_TEST_BYOK_AWS_EMULATOR:-}" = "1" ]; then
    configured="$configured aws-emulator(not-AWS)"
  else
    configured="$configured aws"
  fi
fi
[ -n "${VECTA_TEST_BYOK_GCP_SERVICE_ACCOUNT_FILE:-}" ] && configured="$configured google-cloud"
[ -n "${VECTA_TEST_BYOK_AZURE_VAULT_URL:-}" ] && configured="$configured azure-managed-hsm"
[ -n "${VECTA_TEST_BYOK_AZURE_KV_VAULT_URL:-}" ] && configured="$configured azure-key-vault-premium-rsa"
[ -n "${VECTA_TEST_BYOK_OCI_TENANCY:-}" ] && configured="$configured oci"
[ -n "${VECTA_TEST_BYOK_ALIBABA_ACCESS_KEY:-}" ] && configured="$configured alibaba"
[ -n "${VECTA_TEST_BYOK_SALESFORCE_INSTANCE_URL:-}" ] && configured="$configured salesforce-shield(import-only)"
if [ -z "$configured" ]; then
  echo "Nothing to check: $FILE names no cloud." >&2
  exit 2
fi
echo "Checking:$configured"

out="$(GOFIPS140=v1.0.0 go test ./services/cloud/ -run '^TestLiveCloudBYOK$' -count=1 -timeout 60m -v 2>&1)"
status=$?
# The test logs step names, counts and the cloud's error text, never a
# credential; the filter is a second guard for anything shaped like one.
printf '%s\n' "$out" | grep -E 'byok_live_test\.go|^ *(--- |ok|FAIL|PASS)' |
  sed -E 's/(sig|secret|token|key|password|Signature|Credential)=[^ &"]+/\1=REDACTED/g; s/^ +byok_live_test\.go:[0-9]+: //'
if printf '%s\n' "$out" | grep -q 'CLEAN UP BY HAND'; then
  echo "A key was left behind: see the CLEAN UP BY HAND line above and delete it in the cloud's console." >&2
fi
if [ "$status" -eq 0 ]; then
  echo "Verified:$configured"
  # In CI, the run's summary page is the record.
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### Cloud BYOK: live verification passed"
      echo
      echo "Commit \`${GITHUB_SHA:-unknown}\`, $(date -u '+%Y-%m-%d %H:%M UTC')."
      echo
      for s in $configured; do echo "- $s"; done
    } >> "$GITHUB_STEP_SUMMARY"
  fi
else
  echo "FAILED: see the lines above. Nothing is reported as verified." >&2
fi
exit "$status"
