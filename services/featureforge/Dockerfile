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
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/kms-featureforge ./services/featureforge

FROM vecta-local/alpine:3.24
RUN adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /out/kms-featureforge /usr/local/bin/kms-featureforge
COPY services/featureforge/migrations /app/migrations
USER app
EXPOSE 8300 18300
ENTRYPOINT ["/usr/local/bin/kms-featureforge"]
