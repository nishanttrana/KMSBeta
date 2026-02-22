#!/usr/bin/env bash
set -euo pipefail

umask 077

CERTS_ROOT="${VECTA_CERTS_OUT:-infra/certs/out}"
OUT_DIR="${1:-${CERTS_ROOT}/kmip-client}"
CLIENT_CN="${2:-bank-alpha:kmip-client}"
ORG="${ORG:-Vecta KMS}"
ORG_DN="${ORG// /\\ }"
DAYS="${DAYS:-825}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

CA_DIR="${CA_DIR:-${CERTS_ROOT}/ca}"
CA_CRT="${CA_DIR}/ca.crt"
CA_KEY="${CA_DIR}/ca.key"
CA_SRL="${CA_DIR}/ca.srl"

if [[ ! -f "${CA_CRT}" || ! -f "${CA_KEY}" ]]; then
  echo "missing CA materials at ${CA_DIR} (run infra/certs/generate-mtls.sh first)" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}" || true

KEY_FILE="${OUT_DIR}/tls.key"
CSR_FILE="${OUT_DIR}/tls.csr"
CRT_FILE="${OUT_DIR}/tls.crt"
CHAIN_FILE="${OUT_DIR}/tls-chain.crt"
EXT_FILE="${OUT_DIR}/openssl-ext.cnf"

cat >"${EXT_FILE}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,URI:spiffe://vecta-kms/internal/kmip-client
EOF

openssl genrsa -out "${KEY_FILE}" 2048
openssl req -new -key "${KEY_FILE}" \
  -subj "/C=CH/O=${ORG_DN}/CN=${CLIENT_CN}" \
  -out "${CSR_FILE}"
openssl x509 -req -in "${CSR_FILE}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" \
  -CAserial "${CA_SRL}" -CAcreateserial -out "${CRT_FILE}" -days "${DAYS}" \
  -sha256 -extfile "${EXT_FILE}"

cat "${CRT_FILE}" "${CA_CRT}" >"${CHAIN_FILE}"
rm -f "${CSR_FILE}" "${EXT_FILE}"
chmod 600 "${KEY_FILE}"
chmod 644 "${CRT_FILE}" "${CHAIN_FILE}" 2>/dev/null || true

echo "generated KMIP client cert in ${OUT_DIR} with CN=${CLIENT_CN}"
