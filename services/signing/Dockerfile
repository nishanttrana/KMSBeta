FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/kms-signing ./services/signing

FROM debian:bookworm-slim
RUN apt-get update >/dev/null 2>&1 && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd >/dev/null 2>&1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/kms-signing /app/kms-signing
COPY services/signing/migrations /app/migrations
EXPOSE 8280 18280
ENTRYPOINT ["/app/kms-signing"]
