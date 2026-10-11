#!/usr/bin/env bash
# Checks Crypto Discovery's object storage scan against real services, with
# credentials you supply (docs/SECURITY/STORAGE_LIVE_VERIFICATION.md).
#
#   scripts/verify-storage-live.sh [settings-file]
#   scripts/verify-storage-live.sh --from-env     (CI: settings are already
#                                                  in the environment)
#
# The settings file (default .storage-live.env, ignored by git; start from
# scripts/storage-live.env.example) holds VECTA_TEST_* names and values. It
# is read by this shell only: no value is printed, passed on a command line
# or written anywhere. Each service you fill in is scanned twice (the second
# run must download nothing) and then tried with a wrong credential, which
# the service must refuse. Nothing is written to the bucket.
#
# Works under macOS's bash 3.2.
set -u

FILE="${1:-.storage-live.env}"
cd "$(dirname "$0")/.." || exit 2
if [ "$FILE" = "--from-env" ]; then
  FILE="the environment"
else
  if [ ! -f "$FILE" ]; then
    echo "No settings file at $FILE. Copy scripts/storage-live.env.example to $FILE and fill in the services to check." >&2
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
[ -n "${VECTA_TEST_S3_ENDPOINT:-}" ] && configured="$configured s3"
[ -n "${VECTA_TEST_S3_ROLE_ARN:-}" ] && configured="$configured assumed-role"
[ -n "${VECTA_TEST_AZURE_SAS:-}" ] && configured="$configured azure-sas"
[ -n "${VECTA_TEST_AZURE_ACCOUNT_KEY:-}" ] && configured="$configured azure-shared-key"
[ -n "${VECTA_TEST_AZURE_CLIENT_SECRET:-}" ] && configured="$configured azure-entra-id"
[ -n "${VECTA_TEST_GCS_BUCKET:-}" ] && configured="$configured gcs"
[ -n "${VECTA_TEST_GCS_SERVICE_ACCOUNT_FILE:-}" ] && configured="$configured gcs-service-account"
[ -n "${VECTA_TEST_AZURE_OAUTH_EMULATOR:-}" ] && configured="$configured azurite-oauth"
if [ -z "$configured" ]; then
  echo "Nothing to check: $FILE names no service." >&2
  exit 2
fi
echo "Checking:$configured"

out="$(go test ./services/discovery/ -run '^TestLiveObjectStorage$' -count=1 -v 2>&1)"
status=$?
# The test logs counts, locations and error codes, never a credential; the
# filter is a second guard for anything shaped like one.
printf '%s\n' "$out" | grep -E 'storage_test\.go|^(--- |ok|FAIL|PASS)' |
  sed -E 's/(sig|secret|token|key|password)=[^ &"]+/\1=REDACTED/g; s/^ +storage_test\.go:[0-9]+: //'
if [ "$status" -eq 0 ]; then
  echo "Verified:$configured"
  # In CI, the run's summary page is the record.
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### Object storage scan: live verification passed"
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
