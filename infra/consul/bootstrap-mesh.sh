#!/usr/bin/env sh
set -eu

CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR:-http://consul:8500}"
WAIT_SECONDS="${WAIT_SECONDS:-60}"

wait_for_consul() {
  i=0
  while [ "$i" -lt "$WAIT_SECONDS" ]; do
    if command -v consul >/dev/null 2>&1; then
      if CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR}" consul status leader >/dev/null 2>&1; then
        return 0
      fi
    elif command -v curl >/dev/null 2>&1; then
      if curl -fsS "${CONSUL_HTTP_ADDR}/v1/status/leader" >/dev/null 2>&1; then
        return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -q -O- "${CONSUL_HTTP_ADDR}/v1/status/leader" >/dev/null 2>&1; then
        return 0
      fi
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "timed out waiting for consul at ${CONSUL_HTTP_ADDR}" >&2
  return 1
}

put_entry() {
  kind="$1"
  payload="$2"
  if command -v consul >/dev/null 2>&1; then
    printf "%s\n" "$payload" | CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR}" consul config write - >/dev/null
    return 0
  fi

  if command -v curl >/dev/null 2>&1; then
    name=$(printf "%s" "$payload" | awk -F'"' '/"Name":/ { print $4; exit }')
    curl -fsS -X PUT \
      -H "Content-Type: application/json" \
      -d "$payload" \
      "${CONSUL_HTTP_ADDR}/v1/config/${kind}/${name}" >/dev/null
    return 0
  fi

  echo "consul or curl is required to apply mesh config entries" >&2
  return 1
}

service_defaults_json() {
  name="$1"
  cat <<EOF
{"Kind":"service-defaults","Name":"${name}","Protocol":"grpc","MutualTLSMode":"strict"}
EOF
}

service_intentions_json() {
  name="$1"
  cat <<EOF
{"Kind":"service-intentions","Name":"${name}","Sources":[{"Name":"*","Action":"allow"}]}
EOF
}

SERVICES="
kms-auth
kms-keycore
kms-audit
kms-policy
kms-secrets
kms-certs
kms-governance
kms-cloud
kms-hyok-proxy
kms-kmip
kms-qkd
kms-ekm
kms-payment
kms-compliance
kms-sbom
kms-reporting
kms-ai
kms-pqc
kms-discovery
kms-mpc
kms-dataprotect
kms-cluster
kms-hsm-connector
kms-software-vault
"

wait_for_consul

for svc in $SERVICES; do
  put_entry service-defaults "$(service_defaults_json "$svc")"
  put_entry service-intentions "$(service_intentions_json "$svc")"
done

echo "consul mesh defaults applied for KMS services"
