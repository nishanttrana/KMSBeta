FROM golang:1.27.1-bookworm AS build
# Link the CMVP-certified Go Cryptographic Module (docs/SECURITY/FIPS.md).
# The customer picks the runtime mode with VECTA_FIPS_MODE (on | only | off).
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
# cgo: the connector dlopen()s the customer's PKCS#11 library, and vendor
# libraries (Securosys Primus, Thales Luna, Entrust nShield, Utimaco, AWS
# CloudHSM) are glibc builds, so this image is Debian, not Alpine.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=1 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/kms-hsm-connector ./services/hsm-connector

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
  && groupadd -r app && useradd -r -g app -d /app app
WORKDIR /app
COPY --from=build /out/kms-hsm-connector /app/kms-hsm-connector
USER app
EXPOSE 8430 18430
ENTRYPOINT ["/app/kms-hsm-connector"]
