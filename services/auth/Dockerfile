FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-auth ./services/auth

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app && addgroup app root && mkdir -p /var/lib/vecta/auth && chown -R app:app /var/lib/vecta
USER app
WORKDIR /app
COPY --from=build /out/kms-auth /app/kms-auth
COPY services/auth/migrations /app/migrations
EXPOSE 8001 18001
ENTRYPOINT ["/app/kms-auth"]
