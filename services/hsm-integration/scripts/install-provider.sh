#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <tenant_id> <library_file_path>" >&2
  exit 1
fi

tenant_id="$1"
library_file="$2"
workspace_root="${HSM_INTEGRATION_WORKSPACE_ROOT:-/var/lib/vecta/hsm/providers}"

tenant_slug="$(printf "%s" "${tenant_id}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//')"
if [ -z "${tenant_slug}" ]; then
  tenant_slug="tenant"
fi

incoming_dir="${workspace_root}/${tenant_slug}/incoming"
provider_dir="${workspace_root}/${tenant_slug}/provider"
checksum_file="${workspace_root}/${tenant_slug}/sha256sum.txt"

mkdir -p "${incoming_dir}" "${provider_dir}"

if [ ! -f "${library_file}" ]; then
  echo "library file not found: ${library_file}" >&2
  exit 1
fi

basename_file="$(basename "${library_file}")"
target_file="${provider_dir}/${basename_file}"

cp "${library_file}" "${target_file}"
chmod 0640 "${target_file}"
sha256sum "${target_file}" | tee -a "${checksum_file}"

echo "installed_provider=${target_file}"
echo "checksum_file=${checksum_file}"
