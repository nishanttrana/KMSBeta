#!/usr/bin/env bash
# The Helm chart gate (CI job helm-chart, docs/KUBERNETES.md): the chart is
# generated from the current docker-compose.yml, lints, and renders manifests
# that validate against the Kubernetes schema, with every feature on and with
# hardware HSM mode. HELM and KUBECONFORM name the binaries.
set -euo pipefail
cd "$(dirname "$0")/.."
HELM="${HELM:-helm}"
KUBECONFORM="${KUBECONFORM:-kubeconform}"
CHART=deploy/helm/vecta-kms
bash scripts/helm-chart.sh --check
"${HELM}" lint "${CHART}" --kube-version 1.31.0
out="$(mktemp -d)"
trap 'rm -rf "${out}"' EXIT
"${HELM}" template kms "${CHART}" --kube-version 1.31.0 > "${out}/default.yaml"
"${HELM}" template kms "${CHART}" --kube-version 1.31.0 --set deployment.hsm_mode=hardware \
  --set deployment.features.clustering=true --set existingSecret=mine > "${out}/hardware.yaml"
"${KUBECONFORM}" -strict -summary -kubernetes-version 1.31.0 "${out}/default.yaml" "${out}/hardware.yaml"
# The enabled features decide the containers.
grep -q '^        - name: hsm-connector$' "${out}/hardware.yaml" || { echo "FAIL: hsm_mode hardware runs no hsm-connector" >&2; exit 1; }
if grep -q '^        - name: hsm-connector$' "${out}/default.yaml"; then echo "FAIL: software mode runs hsm-connector" >&2; exit 1; fi
grep -q '^        - name: cluster-manager$' "${out}/hardware.yaml" || { echo "FAIL: clustering on runs no cluster-manager" >&2; exit 1; }
# With existingSecret the chart creates no Secret.
if grep -q '^kind: Secret$' "${out}/hardware.yaml"; then echo "FAIL: existingSecret still renders a Secret" >&2; exit 1; fi
# No secret value is ever written into the pod spec.
if grep -q '__VECTA_SECRET_' "${out}/default.yaml"; then echo "FAIL: a secret placeholder reached the manifests" >&2; exit 1; fi
echo "PASS: Helm chart"
