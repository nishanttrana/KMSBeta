FROM golang:1.27.1-bookworm AS build
# Link the CMVP-certified Go Cryptographic Module (docs/SECURITY/FIPS.md).
# The customer picks the runtime mode with VECTA_FIPS_MODE (on | only | off).
ENV GOFIPS140=v1.0.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/kms-autokey ./services/autokey

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/kms-autokey /usr/local/bin/kms-autokey
COPY services/autokey/migrations /app/migrations
EXPOSE 8260 18260
ENTRYPOINT ["/usr/local/bin/kms-autokey"]
