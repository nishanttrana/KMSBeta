FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-sbom ./services/sbom

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
ENV WORKSPACE_ROOT=/workspace
COPY --from=build /out/kms-sbom /app/kms-sbom
COPY services/sbom/migrations /app/migrations
COPY go.mod go.sum /workspace/
COPY docker-compose.yml docker-compose.dev.yml /workspace/
COPY services /workspace/services
COPY web/dashboard/package.json web/dashboard/package-lock.json /workspace/web/dashboard/
USER app
EXPOSE 8180 18180
ENTRYPOINT ["/app/kms-sbom"]
