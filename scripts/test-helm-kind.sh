#!/usr/bin/env bash
# Installs the Helm chart (deploy/helm/vecta-kms) on a throwaway kind cluster
# and proves the node works: every container ready, the HTTPS edge answers
# with a certificate from the node's own CA, and the bootstrap administrator
# signs in (and is told to change the password). Upgrades the release and
# checks the generated secrets survive. Deletes the cluster afterwards.
#
# Usage: scripts/test-helm-kind.sh [image tag]   (default: VERSION)
# Needs docker, kind and helm (KIND, HELM to override), and the vecta/*
# images of that tag built locally (deploy-local.sh builds them).
set -euo pipefail
cd "$(dirname "$0")/.."
TAG="${1:-$(tr -d '[:space:]' < VERSION)}"
KIND="${KIND:-kind}"
HELM="${HELM:-helm}"
NAME="vecta-helm-test"
NS="vecta"
CHART=deploy/helm/vecta-kms
work="$(mktemp -d)"
KUBECONFIG_FILE="${work}/kubeconfig"
k() { docker exec -i "${NAME}-control-plane" kubectl --kubeconfig /etc/kubernetes/admin.conf -n "${NS}" "$@"; }
h() { "${HELM}" --kubeconfig "${KUBECONFIG_FILE}" -n "${NS}" "$@"; }
cleanup() {
  rc=$?
  if [ "${rc}" -ne 0 ]; then
    echo "--- pod state"; k get pod -o wide 2>/dev/null || true
    k get pod vecta-vecta-kms-0 -o jsonpath='{range .status.initContainerStatuses[*]}{.name}{" ready="}{.ready}{" restarts="}{.restartCount}{"\n"}{end}{range .status.containerStatuses[*]}{.name}{" ready="}{.ready}{" restarts="}{.restartCount}{"\n"}{end}' 2>/dev/null || true
  fi
  if [ -z "${KEEP:-}" ]; then
    "${KIND}" delete cluster --name "${NAME}" >/dev/null 2>&1 || true
    docker rm -f "${REG}" >/dev/null 2>&1 || true
  fi
  rm -rf "${work}"
  exit "${rc}"
}
trap cleanup EXIT

REG="vecta-kind-registry"
REG_PORT="${REG_PORT:-5001}"
"${KIND}" delete cluster --name "${NAME}" >/dev/null 2>&1 || true
# A local registry on the kind network (kind's documented pattern): Vecta
# images are pushed to it; public images are pulled as usual.
docker inspect "${REG}" >/dev/null 2>&1 || docker run -d --restart=no --name "${REG}" -p "127.0.0.1:${REG_PORT}:5000" registry:2 >/dev/null
cat > "${work}/kind.yaml" <<KINDCFG
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
KINDCFG
"${KIND}" create cluster --name "${NAME}" --config "${work}/kind.yaml" --wait 180s
"${KIND}" get kubeconfig --name "${NAME}" > "${KUBECONFIG_FILE}"
docker network connect kind "${REG}" >/dev/null 2>&1 || true
docker exec "${NAME}-control-plane" sh -c "mkdir -p /etc/containerd/certs.d/localhost:${REG_PORT} && printf '[host.\"http://${REG}:5000\"]\n' > /etc/containerd/certs.d/localhost:${REG_PORT}/hosts.toml"
k create namespace "${NS}" >/dev/null 2>&1 || true

# Every Vecta image the chart will run, pushed to the registry.
"${HELM}" template vecta "${CHART}" --kube-version 1.31.0 --set image.tag="${TAG}" \
  | sed -n 's/^ *image: *//p' | tr -d '"' | grep '^vecta/' | sort -u > "${work}/images"
while read -r img; do
  docker tag "${img}" "localhost:${REG_PORT}/${img}"
  docker push -q "localhost:${REG_PORT}/${img}" >/dev/null
done < "${work}/images"
echo "pushed $(wc -l < "${work}/images" | tr -d ' ') images"
SET=(--set image.tag="${TAG}" --set image.registry="localhost:${REG_PORT}/")

h install vecta "${CHART}" "${SET[@]}"
echo "waiting for every container of the node to be ready"
k wait pod/vecta-vecta-kms-0 --for=condition=Ready --timeout=900s

# The edge, verified against the node's internal CA.
k exec vecta-vecta-kms-0 -c envoy -- cat /run/vecta/runtime-certs/ca/ca.crt > "${work}/ca.crt"
ip="$(k get svc vecta-vecta-kms -o jsonpath='{.spec.clusterIP}')"
# (docker cp into the node's /tmp, a tmpfs, silently writes nothing.)
docker exec -i "${NAME}-control-plane" sh -c 'cat > /root/vecta-ca.crt' < "${work}/ca.crt"
login() {
  docker exec "${NAME}-control-plane" curl -sS --cacert /root/vecta-ca.crt --resolve "localhost:443:${ip}" \
    -H 'Content-Type: application/json' -w ' %{http_code}' \
    --data '{"tenant_id":"root","username":"admin","password":"changeit"}' https://localhost/svc/auth/auth/login 2>&1 \
    | tr -d '\n' | sed -n -e 's/.*"must_change_password":\([a-z]*\).* \([0-9]*\)$/\2 must_change_password=\1/p' -e 't' -e 's/.* \([0-9][0-9][0-9]\)$/\1/p'
}
# Ready means every container answers its probe; auth may still be seeding
# the bootstrap accounts. Up to three minutes.
signin() {
  local i code=""
  for i in $(seq 1 36); do
    code="$(login)"
    [ "${code}" = "200 must_change_password=true" ] && break
    sleep 5
  done
  printf '%s' "${code}"
}
# (Only the status and the must_change_password flag are kept: the token
# never reaches the output.)
code="$(signin)"
echo "admin sign-in through the edge: HTTP ${code}"
[ "${code}" = "200 must_change_password=true" ] || { echo "FAIL: sign-in answered '${code}'" >&2; exit 1; }

# An upgrade keeps the generated secrets (the node's data is sealed by them).
before="$(k get secret vecta-vecta-kms-secrets -o jsonpath='{.data.POSTGRES_PASSWORD}{.data.jwt_private\.pem}' | sha256sum)"
h upgrade vecta "${CHART}" "${SET[@]}" --set podAnnotations.upgraded=yes
k rollout status statefulset/vecta-vecta-kms --timeout=900s
after="$(k get secret vecta-vecta-kms-secrets -o jsonpath='{.data.POSTGRES_PASSWORD}{.data.jwt_private\.pem}' | sha256sum)"
[ "${before}" = "${after}" ] || { echo "FAIL: an upgrade changed the generated secrets" >&2; exit 1; }
code="$(signin)"
echo "after upgrade: HTTP ${code}"
[ "${code}" = "200 must_change_password=true" ] || { echo "FAIL: sign-in after upgrade answered '${code}'" >&2; exit 1; }
echo "PASS: the chart installs, serves and upgrades a working node"
