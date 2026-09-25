FROM vecta-local/golang:1.27.1-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod sh -ec 'for attempt in 1 2 3 4 5; do go mod download && exit 0; sleep $((attempt * 2)); done; exit 1'
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/kms-ai-gateway ./services/ai-gateway

FROM vecta-local/alpine:3.24
RUN addgroup -S app && adduser -S app -G app && addgroup app root && mkdir -p /var/lib/vecta/ai-gateway && chown -R app:app /var/lib/vecta
USER app
WORKDIR /app
COPY --from=build /out/kms-ai-gateway /app/kms-ai-gateway
COPY services/ai-gateway/migrations /app/migrations
EXPOSE 8320 18320
ENTRYPOINT ["/app/kms-ai-gateway"]
