#!/usr/bin/env bash
# Docker volume helpers for start-kms.sh and install.sh (sourced, not run).
# repair_volumes uses the caller's BASH_BIN, STOP_SCRIPT and DEPLOYMENT_FILE.
# Tested by scripts/test-volume-repair.sh.

# Compose adopts a volume only if it carries Compose's labels. Without them
# every `compose up` warns that the volume "was not created by Docker
# Compose", and the options the compose file declares for it are never
# applied. A volume this script makes ahead of Compose carries them.
compose_volume_create() {
  local project="$1" key="$2"
  docker volume create --label "com.docker.compose.project=${project}" --label "com.docker.compose.volume=${key}" "${project}_${key}" >/dev/null
}

volume_exists() {
  docker volume inspect "$1" >/dev/null 2>&1
}

volume_is_labelled() {
  [[ -n "$(docker volume inspect -f '{{ index .Labels "com.docker.compose.project" }}' "$1" 2>/dev/null)" ]]
}

volume_is_tmpfs() {
  [[ "$(docker volume inspect -f '{{ index .Options "type" }}' "$1" 2>/dev/null)" == "tmpfs" ]]
}

# Volumes that start, install or deploy scripts have created ahead of Compose.
SCRIPT_MADE_VOLUMES="certs-key-data internal-trust dashboard-tls infra-tls platform-state auth-data"

# helper_image names a small image with a shell that is already on this
# host: an air-gapped install has postgres but may not have the others.
helper_image() {
  local image
  for image in postgres:16.13-alpine alpine:3.24 busybox:1.36; do
    docker image inspect "${image}" >/dev/null 2>&1 && break
  done
  printf '%s' "${image}"
}

# prepare_shared_volumes creates the volumes that must be laid out before the
# first start, and gives each the owner, mode and subdirectories its users
# expect. Every path that starts the stack calls it (start-kms.sh,
# install.sh): until 7.22.0-beta install.sh did not, and a fresh install
# stopped at Postgres, whose mount needs infra-tls/postgres to exist.
#   certs-key-data  certs (100:101): sealed CRWK, passphrase, kept edge files
#   internal-trust  written by certs, read by every service
#   dashboard-tls   written by certs, read by the dashboard (group 101)
#   infra-tls       one subdirectory per daemon; each mounts only its own
#   platform-state  FIPS mode, written by governance (uid 10001)
# runtime-certs is not made here: Compose creates it as tmpfs, already owned
# by the certs user (docker-compose.yml).
prepare_shared_volumes() {
  local project="$1" key
  for key in certs-key-data internal-trust dashboard-tls infra-tls platform-state; do
    volume_exists "${project}_${key}" || compose_volume_create "${project}" "${key}"
  done
  docker run --rm --network none \
    --volume "${project}_certs-key-data:/data" \
    --volume "${project}_internal-trust:/trust" \
    --volume "${project}_dashboard-tls:/dashboard-tls" \
    --volume "${project}_infra-tls:/infra-tls" \
    --volume "${project}_platform-state:/platform-state" \
    "$(helper_image)" sh -c '
      set -eu
      chown -R 100:101 /data
      chmod 700 /data
      chown 100:101 /trust /dashboard-tls
      chmod 755 /trust
      chmod 750 /dashboard-tls
      mkdir -p /infra-tls/postgres /infra-tls/nats /infra-tls/valkey /infra-tls/consul
      chown -R 100:101 /infra-tls
      chmod 700 /infra-tls /infra-tls/postgres /infra-tls/nats /infra-tls/valkey /infra-tls/consul
      chown 10001 /platform-state
      chmod 755 /platform-state
    ' >/dev/null
}

# copy_volume copies one volume into another and fails unless the contents,
# owners and modes then match.
copy_volume() {
  docker run --rm --network none --volume "$1:/from:ro" --volume "$2:/to" "$(helper_image)" sh -c '
    set -eu
    cp -a /from/. /to/
    chown "$(stat -c %u:%g /from)" /to
    chmod "$(stat -c %a /from)" /to
    diff -r /from /to >/dev/null
    listing() { cd "$1" && find . -exec stat -c "%n %u:%g %a" {} + | sort; }
    [ "$(listing /from)" = "$(listing /to)" ]
  ' >/dev/null
}

# adopt_volume gives a volume made by an older script Compose's labels. Labels
# can't be changed in place, so the volume is re-created: its contents go to a
# scratch volume and are verified before the original is removed, then come
# back and are verified before the scratch volume is removed. A verified copy
# exists at every step, and an interrupted run resumes from the scratch
# volume. Nothing may be using the volume.
adopt_volume() {
  local project="$1" key="$2"
  local name="${project}_${key}" scratch="${project}_${key}-adopting"
  if volume_exists "${name}" && ! volume_is_labelled "${name}"; then
    docker volume rm "${scratch}" >/dev/null 2>&1 || true
    copy_volume "${name}" "${scratch}" || return 1
    docker volume rm "${name}" >/dev/null || return 1
  fi
  volume_exists "${scratch}" || return 0
  compose_volume_create "${project}" "${key}" || return 1
  copy_volume "${scratch}" "${name}" || return 1
  docker volume rm "${scratch}" >/dev/null
}

# keep_external_edge copies what certs can't issue again from an on-disk
# runtime-certs volume to the certs key volume, where certs keeps it from
# 7.21.0-beta (docs/SECURITY/INTERNAL_TLS.md, "Edge certificate"): each
# listener's external certificate with its key and serial marker, and the key
# of a pending CSR.
keep_external_edge() {
  docker run --rm --network none --volume "$1:/from:ro" --volume "$2:/to" "$(helper_image)" sh -c '
    set -eu
    umask 077
    for name in envoy kmip; do
      if [ -s "/from/${name}-external.serial" ] && [ -s "/from/${name}/tls.key" ]; then
        mkdir -p /to/edge
        rm -rf "/to/edge/${name}"
        cp -a "/from/${name}" "/from/${name}-external.serial" /to/edge/
        echo "kept the external ${name} certificate"
      fi
      if [ -s "/from/${name}-pending/tls.key" ]; then
        mkdir -p /to/edge
        rm -rf "/to/edge/${name}-pending"
        cp -a "/from/${name}-pending" /to/edge/
        echo "kept the pending ${name} CSR key"
      fi
    done
    if [ -d /to/edge ]; then chown -R 100:101 /to/edge; chmod 700 /to/edge; fi
  '
}

# Until 7.21.0-beta the scripts created volumes without Compose's labels, and
# created runtime-certs as an ordinary volume, so the TLS private keys that
# docker-compose.yml places in memory (tmpfs) were written to disk. Both are
# repaired here once: the stack is stopped, the unlabelled volumes are
# adopted, and a runtime-certs volume that isn't tmpfs is removed (Compose
# re-creates it from the compose file, and certs issues its contents again;
# an external certificate is kept first).
repair_volumes() {
  local project="$1" key pending="" runtime_volume="${1}_runtime-certs"
  for key in ${SCRIPT_MADE_VOLUMES}; do
    if volume_exists "${project}_${key}-adopting" || { volume_exists "${project}_${key}" && ! volume_is_labelled "${project}_${key}"; }; then
      pending="${pending} ${key}"
    fi
  done
  if volume_exists "${runtime_volume}" && ! volume_is_tmpfs "${runtime_volume}"; then
    pending="${pending} runtime-certs"
  fi
  [[ -n "${pending}" ]] || return 0

  echo "one-time volume repair (${pending# }): stopping the stack to re-create them as docker-compose.yml declares"
  "${BASH_BIN}" "${STOP_SCRIPT}" "${DEPLOYMENT_FILE}" --force
  for key in ${pending}; do
    if [[ "${key}" == "runtime-certs" ]]; then
      keep_external_edge "${runtime_volume}" "${project}_certs-key-data"
      docker volume rm "${runtime_volume}" >/dev/null
      echo "removed the on-disk ${runtime_volume}; Compose re-creates it in memory (tmpfs)"
    elif adopt_volume "${project}" "${key}"; then
      echo "adopted ${project}_${key}"
    else
      echo "could not adopt ${project}_${key}: its contents are intact in ${project}_${key} or ${project}_${key}-adopting; fix the error and start again" >&2
      return 1
    fi
  done
}
