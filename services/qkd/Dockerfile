FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-qkd ./services/qkd

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-qkd /app/kms-qkd
COPY services/qkd/migrations /app/migrations
EXPOSE 8150 18150
ENTRYPOINT ["/app/kms-qkd"]
