#!/usr/bin/env bash
# Runs the Go test suite in a container with no network at all (loopback
# only): a test that needs the Internet or DNS fails here every time, instead
# of failing in CI whenever the network does. CI runs it; so can you.
#
#   scripts/test-hermetic.sh [go test arguments]     default ./pkg/... ./services/...
#
# Needs Docker and the modules already downloaded (`go mod download`). The
# image is the Go toolchain go.mod names. Works under macOS's bash 3.2.
set -euo pipefail

cd "$(dirname "$0")/.."
version="$(sed -n 's/^toolchain go//p' go.mod)"
if [ -z "$version" ]; then
  echo "go.mod names no toolchain" >&2
  exit 2
fi
if [ "$#" -eq 0 ]; then
  set -- ./pkg/... ./services/...
fi
modcache="$(go env GOMODCACHE)"
docker run --rm --network none \
  -v "$PWD":/src:ro -v "$modcache":/go/pkg/mod:ro \
  -e GOFLAGS=-buildvcs=false -e GOPROXY=off -e GOTOOLCHAIN=local -e GOFIPS140=v1.0.0 \
  -w /src "golang:${version}" go test -count=1 "$@"
