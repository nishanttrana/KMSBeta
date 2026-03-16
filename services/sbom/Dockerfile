FROM vecta-local/golang:1.26-alpine AS build
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN sh -ec 'for attempt in 1 2 3 4 5; do go mod download && exit 0; sleep $((attempt * 2)); done; exit 1'
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-sbom ./services/sbom

FROM vecta-local/trivy:0.69.3 AS trivybin

FROM vecta-local/alpine:3.21
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
