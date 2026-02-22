FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-secrets ./services/secrets

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-secrets /app/kms-secrets
COPY services/secrets/migrations /app/migrations
EXPOSE 8020 18020
ENTRYPOINT ["/app/kms-secrets"]

