FROM golang:1.27.1-alpine AS build
# Link the CMVP-certified Go Cryptographic Module (docs/SECURITY/FIPS.md).
# The customer picks the runtime mode with VECTA_FIPS_MODE (on | only | off).
ENV GOFIPS140=v1.0.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/kms-backup ./services/backup

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-backup /app/kms-backup
COPY services/backup/migrations /app/migrations
EXPOSE 8250 18250
ENTRYPOINT ["/app/kms-backup"]
