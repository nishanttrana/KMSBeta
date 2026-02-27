FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-cluster-manager ./services/cluster-manager

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-cluster-manager /app/kms-cluster-manager
COPY services/cluster-manager/migrations /app/migrations
EXPOSE 8210 18210
ENTRYPOINT ["/app/kms-cluster-manager"]
