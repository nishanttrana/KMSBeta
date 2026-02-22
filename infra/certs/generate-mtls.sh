#!/usr/bin/env bash
set -euo pipefail

umask 077

OUT_DIR="${1:-${VECTA_CERTS_OUT:-infra/certs/out}}"
DAYS="${DAYS:-825}"
CA_DAYS="${CA_DAYS:-3650}"
ORG="${ORG:-Vecta KMS}"
ORG_DN="${ORG// /\\ }"

# Prevent Git Bash path rewriting of OpenSSL -subj values (e.g. /C=CH/...).
if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
  export MSYS_NO_PATHCONV=1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

SERVICES=(
  envoy
  auth
  keycore
  audit
  policy
  secrets
  certs
  governance
  cloud
  hyok
  kmip
  qkd
  ekm
  payment
  compliance
  sbom
  reporting
  ai
  pqc
  discovery
  mpc
  dataprotect
  cluster-manager
  hsm-connector
  software-vault
)

mkdir -p "${OUT_DIR}/ca" "${OUT_DIR}/trust"
chmod 700 "${OUT_DIR}" "${OUT_DIR}/ca" "${OUT_DIR}/trust" || true

CA_KEY="${OUT_DIR}/ca/ca.key"
CA_CRT="${OUT_DIR}/ca/ca.crt"
CA_SRL="${OUT_DIR}/ca/ca.srl"

if [[ ! -f "${CA_KEY}" || ! -f "${CA_CRT}" ]]; then
  openssl genrsa -out "${CA_KEY}" 4096
  openssl req -x509 -new -key "${CA_KEY}" -sha256 -days "${CA_DAYS}" \
    -subj "/C=CH/O=${ORG_DN}/CN=vecta-kms-internal-ca" \
    -out "${CA_CRT}"
fi
chmod 600 "${CA_KEY}" "${CA_SRL}" 2>/dev/null || true
chmod 644 "${CA_CRT}" 2>/dev/null || true

for svc in "${SERVICES[@]}"; do
  svc_dir="${OUT_DIR}/${svc}"
  mkdir -p "${svc_dir}"
  chmod 700 "${svc_dir}" || true

  key_file="${svc_dir}/tls.key"
  csr_file="${svc_dir}/tls.csr"
  crt_file="${svc_dir}/tls.crt"
  chain_file="${svc_dir}/tls-chain.crt"
  ext_file="${svc_dir}/openssl-ext.cnf"

  cat >"${ext_file}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:${svc},DNS:localhost,IP:127.0.0.1,URI:spiffe://vecta-kms/internal/${svc}
EOF

  openssl genrsa -out "${key_file}" 2048
  openssl req -new -key "${key_file}" \
    -subj "/C=CH/O=${ORG_DN}/CN=${svc}" \
    -out "${csr_file}"
  openssl x509 -req -in "${csr_file}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" \
    -CAserial "${CA_SRL}" -CAcreateserial -out "${crt_file}" -days "${DAYS}" \
    -sha256 -extfile "${ext_file}"

  cat "${crt_file}" "${CA_CRT}" >"${chain_file}"
  rm -f "${csr_file}" "${ext_file}"
  chmod 600 "${key_file}"
  chmod 644 "${crt_file}" "${chain_file}" 2>/dev/null || true
done

cp "${CA_CRT}" "${OUT_DIR}/trust/ca-bundle.pem"
chmod 644 "${OUT_DIR}/trust/ca-bundle.pem" 2>/dev/null || true
echo "generated mTLS materials in ${OUT_DIR}"
