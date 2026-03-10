FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-qrng ./services/qrng

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-qrng /app/kms-qrng
COPY services/qrng/migrations /app/migrations
EXPOSE 8230 18230
ENTRYPOINT ["/app/kms-qrng"]
