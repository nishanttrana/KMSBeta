#!/usr/bin/env bash
# Tests infra/scripts/compose-volumes.sh against real Docker volumes in a
# throwaway Compose project: an unlabelled volume is adopted with its
# contents, owners and modes unchanged; an on-disk runtime-certs volume is
# replaced by the tmpfs one docker-compose.yml declares; a volume in use is
# refused and left intact; an interrupted adoption resumes; a copy that does
# not match is rejected; an external edge certificate on the old runtime-certs
# volume is kept. Cleans up afterwards.
# Usage: ./scripts/test-volume-repair.sh
set -euo pipefail
cd "$(dirname "$0")/.."

P="vecta-voltest-$$"
IMAGE="alpine:3.24"
WORK="$(mktemp -d)"
BASH_BIN="${BASH:-bash}"
STOP_SCRIPT="${WORK}/stop.sh"
DEPLOYMENT_FILE="none"
# shellcheck source=infra/scripts/compose-volumes.sh
source infra/scripts/compose-volumes.sh

compose() { docker compose -f "${WORK}/docker-compose.yml" "$@"; }
cleanup() {
  compose down -v >/dev/null 2>&1 || true
  docker volume ls -q --filter "name=${P}_" | while read -r v; do docker volume rm "${v}" >/dev/null 2>&1 || true; done
  rm -rf "${WORK}"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# The runtime-certs declaration is the one in the real compose file.
tmpfs_opts="$(awk '/^  runtime-certs:/{f=1;next} f&&/^  [^ ]/{f=0} f' docker-compose.yml)"
[[ "${tmpfs_opts}" == *"type: tmpfs"* ]] || fail "docker-compose.yml no longer declares runtime-certs as tmpfs"
cat > "${WORK}/docker-compose.yml" <<EOF
name: ${P}
services:
  app:
    image: ${IMAGE}
    command: ["sleep", "600"]
    volumes:
      - certs-key-data:/data
      - runtime-certs:/runtime
volumes:
  certs-key-data:
  runtime-certs:
${tmpfs_opts}
EOF
printf '#!/usr/bin/env bash\ndocker compose -f "%s" down >/dev/null 2>&1\n' "${WORK}/docker-compose.yml" > "${STOP_SCRIPT}"

snapshot() {
  docker run --rm --network none -v "$1:/d:ro" "${IMAGE}" sh -c \
    'cd /d && find . -exec stat -c "%n %u:%g %a" {} + | sort && find . -type f -exec cksum {} + | sort -k3'
}
warnings() { compose up -d 2>&1 | grep -c "not created by Docker Compose" || true; }

# Volumes as the scripts made them before 7.21.0-beta: no labels, on disk.
docker volume create "${P}_certs-key-data" >/dev/null
docker volume create "${P}_runtime-certs" >/dev/null
docker run --rm --network none -v "${P}_certs-key-data:/data" -v "${P}_runtime-certs:/runtime" "${IMAGE}" sh -c '
  set -eu; umask 077
  mkdir -p /data/sub/deep /runtime/envoy
  head -c 4096 /dev/urandom > /data/a.bin; echo x > /data/sub/deep/b; echo y > /data/.hidden
  chmod 640 /data/sub/deep/b; chown -R 100:101 /data; chown 10001 /data/sub; chmod 700 /data
  echo k > /runtime/envoy/tls.key'
before="$(snapshot "${P}_certs-key-data")"

[[ "$(warnings)" == "2" ]] || fail "expected Compose to warn about both old-style volumes"
compose exec -T app sh -c 'mount | grep " /runtime "' | grep -q tmpfs && fail "old-style runtime-certs should be on disk"

# Refused while in use, and nothing is lost.
if adopt_volume "${P}" certs-key-data 2>/dev/null; then fail "adopted a volume that is in use"; fi
[[ "$(snapshot "${P}_certs-key-data")" == "${before}" ]] || fail "refused adoption changed the volume"

# A stale scratch volume from an interrupted run is discarded, not merged.
docker run --rm --network none -v "${P}_certs-key-data-adopting:/to" "${IMAGE}" sh -c 'echo stale > /to/stale'

repair_volumes "${P}" >/dev/null
volume_is_labelled "${P}_certs-key-data" || fail "adopted volume has no Compose labels"
volume_exists "${P}_certs-key-data-adopting" && fail "scratch volume left behind"
volume_exists "${P}_runtime-certs" && fail "on-disk runtime-certs was not removed"
[[ "$(snapshot "${P}_certs-key-data")" == "${before}" ]] || fail "adoption changed contents, owners or modes"

[[ "$(warnings)" == "0" ]] || fail "Compose still warns after the repair"
compose exec -T app sh -c 'mount | grep " /runtime "' | grep -q tmpfs || fail "runtime-certs is not tmpfs after the repair"
[[ "$(compose exec -T app stat -c '%u:%g %a' /runtime)" == "100:101 700" ]] || fail "tmpfs runtime-certs has the wrong owner or mode"
compose exec -T app test ! -e /runtime/envoy/tls.key || fail "the on-disk key survived in runtime-certs"

# Nothing left to repair: the running stack is not stopped.
repair_volumes "${P}" >/dev/null
[[ "$(compose ps --status running -q | wc -l | tr -d ' ')" == "1" ]] || fail "a repair with nothing to do stopped the stack"

# Interrupted after the original was removed: resumes from the scratch copy.
compose down >/dev/null 2>&1
copy_volume "${P}_certs-key-data" "${P}_certs-key-data-adopting"
docker volume rm "${P}_certs-key-data" >/dev/null
repair_volumes "${P}" >/dev/null
[[ "$(snapshot "${P}_certs-key-data")" == "${before}" ]] || fail "resumed adoption changed the volume"
volume_is_labelled "${P}_certs-key-data" || fail "resumed adoption has no Compose labels"

# A copy that does not match its source is rejected.
docker run --rm --network none -v "${P}_bad:/d" "${IMAGE}" sh -c 'echo extra > /d/other'
if copy_volume "${P}_certs-key-data" "${P}_bad" 2>/dev/null; then fail "copy_volume accepted a target that differs from its source"; fi

# An external certificate and a pending CSR key on an on-disk runtime-certs
# volume move to the certs key volume before it is removed. A listener
# without the external marker has a certificate certs issues again: not kept.
docker volume rm "${P}_runtime-certs" >/dev/null
docker run --rm --network none -v "${P}_runtime-certs:/r" "${IMAGE}" sh -c '
  set -eu; umask 077
  mkdir -p /r/envoy /r/kmip /r/kmip-pending
  echo ext-key > /r/envoy/tls.key; echo ext-crt > /r/envoy/tls.crt; echo 4d2 > /r/envoy-external.serial
  echo issued-key > /r/kmip/tls.key; echo csr-key > /r/kmip-pending/tls.key
  chown -R 100:101 /r'
repair_volumes "${P}" >/dev/null
volume_exists "${P}_runtime-certs" && fail "on-disk runtime-certs with an external certificate was not removed"
kept="$(docker run --rm --network none -v "${P}_certs-key-data:/d:ro" "${IMAGE}" sh -c \
  'cd /d/edge && find . -exec stat -c "%n %u:%g %a" {} + | sort && cat envoy/tls.key envoy/tls.crt envoy-external.serial kmip-pending/tls.key')"
expected="$(printf '%s\n' ". 100:101 700" "./envoy 100:101 700" "./envoy-external.serial 100:101 600" "./envoy/tls.crt 100:101 600" \
  "./envoy/tls.key 100:101 600" "./kmip-pending 100:101 700" "./kmip-pending/tls.key 100:101 600" ext-key ext-crt 4d2 csr-key)"
[[ "${kept}" == "${expected}" ]] || fail "external edge material was not kept as certs expects: ${kept}"

echo "PASS: volume repair"
