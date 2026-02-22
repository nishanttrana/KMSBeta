param(
    [string]$Network = "vecta-kms_kms_net",
    [string]$Host = "envoy",
    [int]$Port = 5696,
    [string]$Version = "1.4"
)

$ErrorActionPreference = "Stop"

$clientDir = (Resolve-Path "infra/certs/out/kmip-client").Path
$caDir = (Resolve-Path "infra/certs/out/ca").Path
$scriptDir = (Resolve-Path "services/kmip/scripts").Path

docker run --rm --network $Network `
  --mount "type=bind,source=$clientDir,target=/certs/client,readonly" `
  --mount "type=bind,source=$caDir,target=/certs/ca,readonly" `
  --mount "type=bind,source=$scriptDir,target=/scripts,readonly" `
  python:3.11-slim sh -lc `
  "pip install -q pykmip && python /scripts/pykmip_smoke.py --host $Host --port $Port --cert /certs/client/tls.crt --key /certs/client/tls.key --ca /certs/ca/ca.crt --version $Version"
