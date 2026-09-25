FROM vecta-local/golang:1.27.1-alpine AS build
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
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/kms-sbom ./services/sbom

FROM vecta-local/trivy:0.74.0 AS trivybin

FROM vecta-local/alpine:3.24
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
ENV WORKSPACE_ROOT=/workspace
ENV TRIVY_BIN=/usr/local/bin/trivy
ENV TRIVY_TARGET=/workspace
ENV TRIVY_CACHE_DIR=/tmp/trivy-cache
COPY --from=build /out/kms-sbom /app/kms-sbom
COPY --from=trivybin /usr/local/bin/trivy /usr/local/bin/trivy
COPY services/sbom/migrations /app/migrations
COPY go.mod go.sum /workspace/
COPY docker-compose.yml docker-compose.dev.yml /workspace/
COPY services /workspace/services
COPY web/dashboard/package.json web/dashboard/package-lock.json /workspace/web/dashboard/
RUN mkdir -p /tmp/trivy-cache && chown -R app:app /tmp/trivy-cache /workspace
USER app
EXPOSE 8180 18180
ENTRYPOINT ["/app/kms-sbom"]
