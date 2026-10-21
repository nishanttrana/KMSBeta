FROM vecta-local/golang:1.27.3-alpine AS build
# Link the CMVP-certified Go Cryptographic Module (docs/SECURITY/FIPS.md).
ENV GOFIPS140=v1.0.0
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod sh -ec 'for attempt in 1 2 3 4 5; do go mod download && exit 0; sleep $((attempt * 2)); done; exit 1'
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/vecta-k8s-kms-plugin ./services/k8s-kms-plugin

FROM vecta-local/alpine:3.24
# Runs as root on the control-plane node: kube-apiserver reads the socket
# from a hostPath it owns.
COPY --from=build /out/vecta-k8s-kms-plugin /usr/local/bin/vecta-k8s-kms-plugin
ENTRYPOINT ["/usr/local/bin/vecta-k8s-kms-plugin"]
