FROM vecta-local/golang:1.26-alpine AS build
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN sh -ec 'for attempt in 1 2 3 4 5; do go mod download && exit 0; sleep $((attempt * 2)); done; exit 1'
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-auth ./services/auth

FROM vecta-local/alpine:3.21
RUN addgroup -S app && adduser -S app -G app && addgroup app root && mkdir -p /var/lib/vecta/auth && chown -R app:app /var/lib/vecta
USER app
WORKDIR /app
COPY --from=build /out/kms-auth /app/kms-auth
COPY services/auth/migrations /app/migrations
EXPOSE 8001 18001
ENTRYPOINT ["/app/kms-auth"]
