#!/usr/bin/env bash
# Platform conformance check: enforces the centralization and secure-defaults rules.
#
#   1. Single crypto library — services must not import stdlib/x crypto
#      primitives directly; everything goes through vecta-kms/pkg/crypto.
#   2. Single audit pipeline — services must not create their own audit
#      streams or publish audit events outside vecta-kms/pkg/audit.
#   3. Secure defaults — no secret falls back to a value shipped in the repo,
#      and .env.example ships no secret values.
#   4. Shell scripts parse (bash 3.2 on macOS included).
#   5. FIPS 140-3: every Go binary links the certified Go Cryptographic Module
#      and every Go service receives the customer's VECTA_FIPS_MODE.
#   6. Preview features: one catalogue (pkg/features), mirrored by the dashboard.
#   7. Route kernel: every HTTP route registers through pkg/route (auth,
#      tenant, permission and a specific audit event by construction).
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

# Rule 3: secure defaults — no secret may fall back to a value that ships in this
# repo. A missing secret must fail fast (compose ${VAR:?}) or be generated at
# random; a public default is a credential every attacker already has. Config
# knobs (_FILE/_PATH/_MODE/...) are not secrets. The only exemption is the
# bootstrap admin password, which is always seeded with a forced change on first
# login. See docs/SECURITY/SECURE_DEFAULTS.md.
SECRET_NAME='[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSPHRASE|PASSWD|API_KEY|PRIVATE_KEY|_KEY_B64|_KEY_PEM|MEK|KEK)[A-Z0-9_]*'
NOT_SECRET='_(FILE|PATH|DIR|MODE|ENABLED|IN_HSM|CHANGE|ID|URL|TTL|HEADER)[:",]'
EXEMPT_SECRET='AUTH_BOOTSTRAP_ADMIN_PASSWORD'
check_secret_defaults() {
  local rule="$1" pattern="$2"; shift 2
  local hits
  hits=$(grep -rnE "$pattern" "$@" 2>/dev/null | grep -v '_test\.go:' | grep -vE "$NOT_SECRET" | grep -vE "$EXEMPT_SECRET" || true)
  if [ -n "$hits" ]; then
    FAIL=1
    echo "FAIL [$rule]: $(printf '%s\n' "$hits" | wc -l | tr -d ' ') hardcoded secret fallback(s)"
    printf '  %s\n' "$hits"
  else
    echo "PASS [$rule]"
  fi
}
check_secret_defaults "no-secret-fallback-compose" "\\\$\\{${SECRET_NAME}:-[^}]" docker-compose*.yml
# (A second ALL_CAPS argument is another env var name, e.g. firstNonEmptyEnv, not a default.)
# Credentials hardcoded inside a URL literal (postgres://user:pass@...) are a
# secret fallback too; only ${VAR}/%s-built URLs are allowed.
check_secret_defaults "no-credential-in-url-go" '"[a-z][a-z0-9+]*://[^:"/@ %$]+:[^@"$ %]+@' services pkg --include="*.go"
check_secret_defaults "no-credential-in-url-compose" '://[^:$/ ]+:[^$@ ]+@' docker-compose*.yml
check_secret_defaults "no-secret-fallback-go" "\\(\"${SECRET_NAME}\", *\"[^\"]*[^A-Z0-9_\"][^\"]*\"\\)" services pkg --include="*.go"

# Rule 3c: .env.example ships no secret values. A filled-in example value
# ("your-...") gets copied into real deployments and runs as a public secret.
env_example_hits=$(grep -nE "^${SECRET_NAME}=.+" .env.example 2>/dev/null | sed 's/=.*/=<value>/' || true)
if [ -n "$env_example_hits" ]; then
  FAIL=1
  echo "FAIL [env-example-no-secret-values]: secret values must be empty in .env.example"
  printf '  %s\n' "$env_example_hits"
else
  echo "PASS [env-example-no-secret-values]"
fi

# Rule 5: FIPS 140-3 (docs/SECURITY/FIPS.md). Every Go binary links the
# certified Go Cryptographic Module (GOFIPS140 = pkg/fips.CertifiedModuleVersion)
# and every Go service receives the customer's VECTA_FIPS_MODE as
# GODEBUG=fips140, so the runtime mode is always the customer's choice.
FIPS_MODULE=$(sed -n 's/^const CertifiedModuleVersion = "\(.*\)"$/\1/p' pkg/fips/fips.go)
fips_fail=""
[ -n "$FIPS_MODULE" ] || fips_fail="$fips_fail pkg/fips.CertifiedModuleVersion-missing"
for f in $(grep -l 'go build' services/*/Dockerfile 2>/dev/null); do
  grep -qx "ENV GOFIPS140=$FIPS_MODULE" "$f" || fips_fail="$fips_fail $f"
done
grep -q 'GODEBUG: fips140=${VECTA_FIPS_MODE:-on}' docker-compose.yml || fips_fail="$fips_fail docker-compose.yml:GODEBUG"
grep -q 'VECTA_FIPS_MODE: ${VECTA_FIPS_MODE:-on}' docker-compose.yml || fips_fail="$fips_fail docker-compose.yml:VECTA_FIPS_MODE"
# Each compose service built from a Go Dockerfile must merge the common env.
fips_fail="$fips_fail$(python3 - <<'PY'
import re, os
text = open("docker-compose.yml").read()
body = text.split("\nservices:\n", 1)[1].split("\nvolumes:\n", 1)[0]
for m in re.finditer(r"^  ([a-z0-9-]+):\n((?:    .*\n|\n)*)", body, re.M):
    name, block = m.group(1), m.group(2)
    df = re.search(r"dockerfile:\s*(\S+)", block)
    if not df or not os.path.exists(df.group(1)):
        continue
    if "go build" in open(df.group(1)).read():
        if "*kms-common-env" not in block:
            print(" docker-compose.yml:" + name, end="")
        # FIPS mode changes restart services by self-SIGTERM; a supervisor
        # restart policy is what brings them back in the new mode.
        if "*kms-service" not in block and not re.search(r"restart:\s*(always|unless-stopped|on-failure)", block):
            print(" docker-compose.yml:" + name + ":no-restart-policy", end="")
PY
)"
if [ -n "$fips_fail" ]; then
  FAIL=1
  echo "FAIL [fips-module]: not wired to the certified module / customer FIPS mode:$fips_fail"
else
  echo "PASS [fips-module]"
fi

# Rule 6: preview features are declared in one catalogue (pkg/features) and the
# dashboard mirrors it exactly, so nothing record-only is shown as finished.
go_preview=$(sed -n 's/^[[:space:]]*{"\([a-z0-9._]*\)", "[a-z-]*", ".*/\1/p' pkg/features/features.go | sort)
ts_preview=$(sed -n 's/^[[:space:]]*{ id: "\([a-z0-9._]*\)".*/\1/p' web/dashboard/src/lib/featureStatus.ts | sort)
if [ -z "$go_preview" ] || [ "$go_preview" != "$ts_preview" ]; then
  FAIL=1
  echo "FAIL [preview-catalogue]: pkg/features.Preview and web/dashboard/src/lib/featureStatus.ts differ"
  diff <(echo "$go_preview") <(echo "$ts_preview") | sed 's/^/  /'
else
  echo "PASS [preview-catalogue] ($(echo "$go_preview" | wc -l | tr -d ' ') preview features)"
fi

# Rule 7: route kernel (docs/PLATFORM_CONTRACT.md). Services register HTTP
# routes through pkg/route, which applies authentication, tenancy, permission
# and a specific audit event (refusals included) to every route. A raw
# http.ServeMux is allowed only in files on the burn-down list, which only
# shrinks: an unlisted raw mux fails, and so does a listed file that no
# longer has one (remove it from the list when you migrate it).
BURNDOWN="scripts/route-kernel-burndown.txt"
route_fail=""
raw_mux=$(grep -rlE 'http\.NewServeMux\(\)|\.HandleFunc\(' services --include="*.go" 2>/dev/null | grep -v '_test\.go$' | sort || true)
listed=$(grep -v '^\s*#' "$BURNDOWN" | grep -v '^\s*$' | sort)
for f in $raw_mux; do
  printf '%s\n' "$listed" | grep -qxF "$f" || route_fail="$route_fail $f(raw-mux)"
done
for f in $listed; do
  printf '%s\n' "$raw_mux" | grep -qxF "$f" || route_fail="$route_fail $f(stale-entry)"
done
if [ -n "$route_fail" ]; then
  FAIL=1
  echo "FAIL [route-kernel]: register routes with pkg/route, and keep $BURNDOWN exact:$route_fail"
else
  echo "PASS [route-kernel] ($(printf '%s\n' "$listed" | grep -c . | tr -d ' ') legacy file(s) left to migrate)"
fi

# Rule 4: every shell script parses. Checked with /bin/bash when present,
# which is bash 3.2 on macOS, the oldest shell the installers must run on.
SH_BIN=/bin/bash; [ -x "$SH_BIN" ] || SH_BIN=bash
sh_fail=""
for f in $(git ls-files '*.sh'); do
  "$SH_BIN" -n "$f" 2>/dev/null || sh_fail="$sh_fail $f"
done
if [ -n "$sh_fail" ]; then
  FAIL=1
  echo "FAIL [shell-syntax]: $SH_BIN -n fails for:$sh_fail"
else
  echo "PASS [shell-syntax]"
fi

# Burn-down report.
if [ -f "$ALLOWLIST" ]; then
  COUNT=$(grep -cv '^\s*#' "$ALLOWLIST" || true)
  echo "-- allowlist burn-down: $COUNT file(s) still exempted"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "Conformance FAILED. Use pkg/crypto for primitives, pkg/audit for events, and"
  echo "fail-fast or random generation for secrets (docs/SECURITY/SECURE_DEFAULTS.md),"
  echo "or (temporarily) add the file to $ALLOWLIST with a justification comment."
  exit 1
fi
echo "Conformance OK."
