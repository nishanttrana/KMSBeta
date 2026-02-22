FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-certs ./services/certs

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-certs /app/kms-certs
COPY services/certs/migrations /app/migrations
EXPOSE 8030 18030
ENTRYPOINT ["/app/kms-certs"]

