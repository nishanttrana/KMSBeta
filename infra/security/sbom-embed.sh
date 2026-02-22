#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=infra/security/common.sh
source "${SCRIPT_DIR}/common.sh"

CHECK_NAME="sbom"
CHECK_DIR="$(init_check_dir "${CHECK_NAME}")"
IMAGE_SUFFIX="${SBOM_IMAGE_SUFFIX:-}"

if ! has_cmd docker; then
  write_status "${CHECK_NAME}" "FAIL" "docker command not found in PATH"
  printf 'docker command is required for SBOM image embedding.\n' > "${CHECK_DIR}/error.txt"
  exit 1
fi

if ! has_cmd syft; then
  write_status "${CHECK_NAME}" "FAIL" "syft command not found in PATH"
  printf 'syft is required to generate CycloneDX SBOM documents.\n' > "${CHECK_DIR}/error.txt"
  exit 1
fi

if ! sha256_file "${SCRIPT_DIR}/blocked-licenses.txt" >/dev/null 2>&1; then
  write_status "${CHECK_NAME}" "FAIL" "no checksum tool available (sha256sum/shasum/openssl)"
  printf 'checksum tool is required to label embedded SBOM digest.\n' > "${CHECK_DIR}/error.txt"
  exit 1
fi

mapfile -t IMAGES < <(extract_vecta_images)
if (( ${#IMAGES[@]} == 0 )); then
  write_status "${CHECK_NAME}" "FAIL" "no vecta/* images found in docker-compose.yml"
  exit 1
fi

mkdir -p "${CHECK_DIR}/sbom" "${CHECK_DIR}/tmp"
printf 'source_image,target_image,sbom_file,sbom_digest,status\n' > "${CHECK_DIR}/sbom-results.csv"

embedded=0
failures=0
missing=0

for image in "${IMAGES[@]}"; do
  image_safe="$(echo "${image}" | tr '/:' '__')"
  sbom_file="${CHECK_DIR}/sbom/${image_safe}.cyclonedx.json"
  work_dir="${CHECK_DIR}/tmp/${image_safe}"
  target_image="${image}${IMAGE_SUFFIX}"

  rm -rf "${work_dir}"
  mkdir -p "${work_dir}"

  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    printf '%s,%s,%s,%s,%s\n' "${image}" "${target_image}" "N/A" "N/A" "FAIL" >> "${CHECK_DIR}/sbom-results.csv"
    failures=$((failures + 1))
    missing=$((missing + 1))
    continue
  fi

  if ! syft "${image}" -o cyclonedx-json > "${sbom_file}"; then
    printf '%s,%s,%s,%s,%s\n' "${image}" "${target_image}" "${sbom_file}" "N/A" "FAIL" >> "${CHECK_DIR}/sbom-results.csv"
    failures=$((failures + 1))
    continue
  fi

  digest="$(sha256_file "${sbom_file}")"
  cp "${sbom_file}" "${work_dir}/sbom.cdx.json"

  cat > "${work_dir}/Dockerfile" <<'EOF'
ARG BASE_IMAGE
ARG SBOM_DIGEST
FROM ${BASE_IMAGE}
COPY sbom.cdx.json /opt/vecta/sbom/cyclonedx.json
LABEL org.opencontainers.image.sbom.path="/opt/vecta/sbom/cyclonedx.json"
LABEL org.opencontainers.image.sbom.format="CycloneDX-JSON"
LABEL org.opencontainers.image.sbom.digest="${SBOM_DIGEST}"
EOF

  if ! docker build -q -t "${target_image}" --build-arg BASE_IMAGE="${image}" --build-arg SBOM_DIGEST="${digest}" "${work_dir}" > "${work_dir}/docker-build.log" 2>&1; then
    printf '%s,%s,%s,%s,%s\n' "${image}" "${target_image}" "${sbom_file}" "${digest}" "FAIL" >> "${CHECK_DIR}/sbom-results.csv"
    failures=$((failures + 1))
    continue
  fi

  embedded_digest="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.sbom.digest" }}' "${target_image}" 2>/dev/null || true)"
  if [[ "${embedded_digest}" != "${digest}" ]]; then
    printf '%s,%s,%s,%s,%s\n' "${image}" "${target_image}" "${sbom_file}" "${digest}" "FAIL" >> "${CHECK_DIR}/sbom-results.csv"
    failures=$((failures + 1))
    continue
  fi

  printf '%s,%s,%s,%s,%s\n' "${image}" "${target_image}" "${sbom_file}" "${digest}" "PASS" >> "${CHECK_DIR}/sbom-results.csv"
  embedded=$((embedded + 1))
done

summary="images=${#IMAGES[@]}, embedded=${embedded}, missing=${missing}, failures=${failures}"
printf '%s\n' "${summary}" > "${CHECK_DIR}/summary.txt"

if (( failures > 0 )); then
  write_status "${CHECK_NAME}" "FAIL" "${summary}"
  exit 1
fi

write_status "${CHECK_NAME}" "PASS" "${summary}"
