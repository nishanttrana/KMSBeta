#!/usr/bin/env bash
# Platform conformance check: enforces the centralization and secure-defaults rules.
#
#   1. Single crypto library — services must not import stdlib/x crypto
#      primitives directly; everything goes through vecta-kms/pkg/crypto.
#   2. Single audit pipeline — services must not create their own audit
#      streams or publish audit events outside vecta-kms/pkg/audit.
#   3. Secure defaults — no secret falls back to a value shipped in the repo,
#      no key material is derived from a repo literal, and .env.example ships
#      no secret values.
#   4. Shell scripts parse (bash 3.2 on macOS included).
#   4b. Compose volumes: scripts create volumes with Compose's labels and
#      never create runtime-certs (it is tmpfs, made by Compose).
#   5. FIPS 140-3: every Go binary links the certified Go Cryptographic Module
#      and every Go service receives the customer's VECTA_FIPS_MODE.
#   6. Preview features: one catalogue (pkg/features), mirrored by the dashboard.
#   6b. Real capability: no simulated/synthetic result generators outside tests.
#   6c. TLS only: no plain listeners or http:// to platform hosts.
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
# A password written into an infrastructure config file is a repo-visible
# secret too (Valkey's requirepass comes from VALKEY_PASSWORD on the command line).
check_secret_defaults "no-password-in-infra-config" '^[[:space:]]*(requirepass|masterauth)[[:space:]]+[^[:space:]$]' infra --include=*.conf
check_secret_defaults "no-secret-fallback-go" "\\(\"${SECRET_NAME}\", *\"[^\"]*[^A-Z0-9_\"][^\"]*\"\\)" services pkg --include="*.go"
# Installers and start scripts: a secret falls back to a generated value
# ($(openssl rand ...)), never a literal. (The CRWK passphrase fell back to a
# literal in start-kms.sh until 1.10.0-beta.)
check_secret_defaults "no-secret-fallback-scripts" "\\\$\\{${SECRET_NAME}:-[^}\$]" install.sh deploy-local.sh run-local.sh infra/scripts scripts --include="*.sh"

# Rule 3e: a secret that once shipped in the repo is public forever. None of
# these may reappear outside the history that records their removal
# (CHANGELOG.md, learning.md, docs/) and tests that prove they're refused;
# READMEs are checked too. Code recognising one compares a SHA-256 digest; a
# value needed in plaintext (to verify stored password hashes against it) sits
# on one line marked conformance:retired-public-secret in
# services/auth/cli_password.go (docs/SECURITY/SECURE_DEFAULTS.md).
RETIRED_PUBLIC_SECRETS='vecta-dev-passphrase|vecta-valkey-secret|VectaCLI@2026'
retired_hits=$(git ls-files -co --exclude-standard 2>/dev/null \
  | grep -vE '^CHANGELOG\.md$|^learning\.md$|_test\.go$|^scripts/conformance\.sh$|^docs/|node_modules/' \
  | while IFS= read -r f; do [ -f "$f" ] && grep -nHE "$RETIRED_PUBLIC_SECRETS" "$f" 2>/dev/null; done \
  | grep -vE '^services/auth/cli_password\.go:[0-9]+:.*// conformance:retired-public-secret$' || true)
if [ -n "$retired_hits" ]; then
  FAIL=1
  echo "FAIL [no-retired-public-secret]: a secret value that shipped in the repo is back:"
  printf '%s\n' "$retired_hits" | sed 's/^/  /'
else
  echo "PASS [no-retired-public-secret]"
fi

# Rule 3d: no key material from a string in the repo. Hashing a literal, an
# HMAC or KDF keyed by a literal, or a key assigned from a literal all yield a
# value anyone with the source can compute. Service master keys come from
# keycore (pkg/mek). The one exception is recognising a retired public key to
# migrate data off it: that line carries "conformance:legacy-public-key" and
# must be in pkg/mek/catalog.go (docs/SECURITY/SERVICE_MASTER_KEYS.md).
LITERAL_KEY='(Hash\("[^"]*", *|Sum(224|256|384|512)\()\[\]byte\("[^"]*"\)\)|(HMAC\("[^"]*", *|hmac\.New\([^,]+, *)\[\]byte\("|(pbkdf2\.Key|argon2\.I?D?Key|HKDF[A-Za-z]*)\(\[\]byte\("|([Mm][Ee][Kk]|[Kk][Ee][Kk]|[Mm]aster_?[Kk]ey)[A-Za-z_]*[[:space:]]*:?=[[:space:]]*\[\]byte\("|\[\]byte\("[^"]*"\)[^/]*// conformance:legacy-public-key'
key_hits=$(grep -rnE "$LITERAL_KEY" services pkg/mek --include="*.go" 2>/dev/null | grep -v '_test\.go:' || true)
key_bad=$(printf '%s\n' "$key_hits" | grep . | grep -v '^pkg/mek/catalog\.go:[0-9]*:.*conformance:legacy-public-key' || true)
if [ -n "$key_bad" ]; then
  FAIL=1
  echo "FAIL [no-literal-key-material]: key material derived from a repo literal (get keys from keycore via pkg/mek):"
  printf '%s\n' "$key_bad" | sed 's/^/  /'
else
  echo "PASS [no-literal-key-material]"
fi

# Rule 3f: no passwordless sudo or sudo package in a service image or
# entrypoint. hsm-integration granted its SSH user NOPASSWD:ALL until
# 1.11.0-beta; nothing in the platform needs root after start.
sudo_hits=$(grep -rnE 'NOPASSWD|apt-get install[^#]*[[:space:]]sudo([[:space:]]|$)|^[[:space:]]+sudo[[:space:]]*\\?$|usermod[^#]*-aG[[:space:]]*sudo' services infra --include=Dockerfile --include='*.sh' 2>/dev/null || true)
if [ -n "$sudo_hits" ]; then
  FAIL=1
  echo "FAIL [no-sudo-in-images]: sudo in a service image or entrypoint:"
  printf '%s\n' "$sudo_hits" | sed 's/^/  /'
else
  echo "PASS [no-sudo-in-images]"
fi

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

# Rule 6b: real capability only (CLAUDE.md rule 8). Features that returned
# invented results were named for it (simulateCTFetch, syntheticDrillSteps,
# simulateDrillCompletion). Such a function outside tests fails; security
# nonces and keys never use Math.random.
# 2026-09-27: also newMock/newFake constructors (a cloud mock provider sat in
# a non-test file), which the word boundary above missed. Test doubles live in
# _test files only.
fake_hits=$( {
  grep -rnE '\b(simulate|synthetic|fabricate|fake|mock)[A-Z][A-Za-z0-9]*[[:space:]]*\(' services pkg web/dashboard/src \
    --include='*.go' --include='*.ts' --include='*.tsx' 2>/dev/null
  grep -rnE '\b(new|New)(Mock|Fake|Simulated|Synthetic|Dummy)[A-Za-z0-9]*[[:space:]]*\(' services pkg web/dashboard/src \
    --include='*.go' --include='*.ts' --include='*.tsx' 2>/dev/null
} | grep -vE '_test\.go:|\.test\.tsx?:|/tests?/|/generated/' || true)
rand_hits=$(grep -rnE 'Math\.random\(\)[[:space:]]*\*[[:space:]]*256|nonce-\$\{Date\.now' web/dashboard/src --include='*.ts' --include='*.tsx' 2>/dev/null || true)
# Built-in sample data shown when a backend call fails (MOCK_SCORE,
# MOCK_WEBHOOKS, MOCK_TARGETS...) presents invented rows as the customer's
# own. Such constants, or mock/demo/fake/dummy data variables, fail outside
# tests; a failed fetch renders "not assessed / unavailable" with the error.
# 2026-09-28: also any variable named simulat*/synthetic* (a `let simulation`
# timer pushed invented audit.dashboard.heartbeat events into the live audit
# feed whenever the stream failed); a real replay says so (`replayed`).
sample_hits=$(grep -rnE '\b(MOCK|DEMO|SAMPLE|FAKE|DUMMY)_[A-Z0-9_]+\b|\b(const|let|var)[[:space:]]+(mock|demo|fake|dummy)[A-Z][A-Za-z0-9]*[[:space:]]*[:=]|\b(const|let|var)[[:space:]]+(simulat|synthetic)[A-Za-z0-9]*\b|\b(simulat|synthetic)[A-Za-z0-9]*[[:space:]]*:=' services pkg web/dashboard/src \
  --include='*.go' --include='*.ts' --include='*.tsx' 2>/dev/null \
  | grep -vE '_test\.go:|\.test\.tsx?:|/tests?/|/generated/' || true)
if [ -n "$fake_hits$rand_hits$sample_hits" ]; then
  FAIL=1
  echo "FAIL [real-capability]: simulated results, built-in sample data or Math.random security values (CLAUDE.md rules 7 and 8)"
  printf '%s\n' "$fake_hits" "$rand_hits" "$sample_hits" | grep -v '^$' | sed 's/^/  /'
else
  echo "PASS [real-capability]"
fi

# No PagerDuty integration (owner, 2026-09-28: "no one uses it"; removed
# completely in 2.11.0-beta). Nothing in code, tests, migrations or the
# dashboard may name it; outbound notification goes through connections
# (docs/SECURITY/CONNECTIONS.md). Migrations that removed it are exempt.
pager_hits=$(grep -rniE 'pager[ _-]?duty|send_pager' services pkg web/dashboard/src web/dashboard/tests \
  --include='*.go' --include='*.ts' --include='*.tsx' --include='*.js' 2>/dev/null || true)
if [ -n "$pager_hits" ]; then
  FAIL=1
  echo "FAIL [no-pagerduty]: PagerDuty was removed; don't add it back"
  printf '%s\n' "$pager_hits" | sed 's/^/  /'
else
  echo "PASS [no-pagerduty]"
fi

# Every internal service client sends the caller's service token. Services
# refuse tokenless callers, and a client without one fails silently: the
# Alert Center was empty for this reason (7.6.0-beta). A client that
# authenticates some other way says so with a `servicetoken-exempt:` comment.
tokenless=""
for f in services/*/*client*.go; do
  case "$f" in *_test.go) continue ;; esac
  grep -q 'http.NewRequest' "$f" || continue
  grep -qE 'servicetoken\.|servicetoken-exempt:' "$f" || tokenless="$tokenless $f"
done
if [ -n "$tokenless" ]; then
  FAIL=1
  echo "FAIL [service-token]: internal clients without servicetoken.Authorize:$tokenless"
else
  echo "PASS [service-token]"
fi

# Rule 6c: every connection is TLS, every internal one mTLS (CLAUDE.md rule
# 10, docs/SECURITY/INTERNAL_TLS.md). No plain listener, no insecure gRPC
# credentials, and no http:// to a platform host in code or deployment files.
internal_hosts=$(sed -n 's/^[[:space:]]*"[a-z-]*":[[:space:]]*"\([a-z-]*\)",.*/\1/p' pkg/svctls/svctls.go | sort -u | paste -sd'|' -)
tls_hits=$( {
  grep -rnE '\.ListenAndServe\(\)|insecure\.NewCredentials\(' services pkg --include='*.go' 2>/dev/null | grep -v '_test\.go:'
  grep -rnE "http://(${internal_hosts})[:/\"]" services pkg --include='*.go' 2>/dev/null | grep -v '_test\.go:'
  grep -nE "http://(${internal_hosts})[:/}\"[:space:]]" docker-compose*.yml infra/envoy/envoy.yaml web/dashboard/nginx.conf infra/scripts/*.sh deploy-local.sh install.sh 2>/dev/null
} || true)
# No plain-HTTP listener at the edge either, not even a redirect to HTTPS
# (removed in 6.14.0-beta): nothing publishes port 80 or redirects.
tls_hits="$tls_hits$( {
  grep -nE '"80:80"|:80:80"|- "?[0-9.]*:?80:80' docker-compose*.yml 2>/dev/null
  grep -nE 'https_redirect|port_value: 80$' infra/envoy/envoy.yaml 2>/dev/null
} || true)"
if [ -n "$tls_hits" ]; then
  FAIL=1
  echo "FAIL [tls-only]: plain HTTP or insecure transport to a platform component (CLAUDE.md rule 10)"
  printf '%s\n' "$tls_hits" | sed 's/^/  /'
else
  echo "PASS [tls-only]"
fi

# Test hooks stay in tests: svctls.ResetForTests forgets the process's
# internal mTLS identity.
reset_hits=$(grep -rn "svctls\.ResetForTests" services pkg --include="*.go" 2>/dev/null | grep -v "_test\.go:" || true)
if [ -n "$reset_hits" ]; then
  FAIL=1
  echo "FAIL [test-hooks-in-tests]: svctls.ResetForTests outside a test:"
  printf '%s\n' "$reset_hits" | sed 's/^/  /'
else
  echo "PASS [test-hooks-in-tests]"
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

# Docs name only routes that exist (CLAUDE.md rule 8: no invented APIs).
if python3 scripts/check-doc-routes.py; then :; else FAIL=1; fi

# The generated route and product map (docs/generated) matches the source:
# it drifted for five releases when regenerating was left to memory.
if python3 scripts/generate_product_map.py --check; then :; else FAIL=1; fi

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

# Rule 4b: a volume a script creates ahead of Compose carries Compose's
# labels, and no script names the runtime-certs volume. Compose doesn't adopt
# an unlabelled volume: it warns on every `up` and drops the options
# docker-compose.yml declares, which left the runtime TLS keys on disk
# instead of tmpfs (learning.md, 2026-10-01).
vol_scripts=$(git ls-files '*.sh' | grep -vE '^scripts/(conformance|test-volume-repair)\.sh$')
vol_fail=$(grep -nE 'volume create' $vol_scripts 2>/dev/null | grep -v 'com\.docker\.compose\.project=' || true)
vol_fail="$vol_fail$(grep -nE '_runtime-certs' $vol_scripts 2>/dev/null | grep -v '^infra/scripts/compose-volumes\.sh:' || true)"
if [ -n "$vol_fail" ]; then
  FAIL=1
  echo "FAIL [compose-volumes]: create volumes with Compose's labels (compose_volume_create) and leave runtime-certs to Compose"
  if [ "$VERBOSE" = "-v" ]; then printf '  %s\n' "$vol_fail"; fi
else
  echo "PASS [compose-volumes]"
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
