FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-keycore ./services/keycore

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
RUN mkdir -p /app/data && chown -R app:app /app
USER app
COPY --from=build /out/kms-keycore /app/kms-keycore
COPY services/keycore/migrations /app/migrations
EXPOSE 8010 18010
ENTRYPOINT ["/app/kms-keycore"]
