FROM golang:1.26.0-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-autokey ./services/autokey

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/kms-autokey /usr/local/bin/kms-autokey
COPY services/autokey/migrations /app/migrations
EXPOSE 8260 18260
ENTRYPOINT ["/usr/local/bin/kms-autokey"]
