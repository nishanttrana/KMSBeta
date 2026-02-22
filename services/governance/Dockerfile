FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-governance ./services/governance

FROM alpine:3.21
RUN adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /out/kms-governance /usr/local/bin/kms-governance
COPY services/governance/migrations /app/migrations
USER app
EXPOSE 8050 18050
ENTRYPOINT ["/usr/local/bin/kms-governance"]
