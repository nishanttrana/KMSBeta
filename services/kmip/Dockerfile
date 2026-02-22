FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-kmip ./services/kmip

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-kmip /app/kms-kmip
COPY services/kmip/migrations /app/migrations
EXPOSE 5696 8160 15696
ENTRYPOINT ["/app/kms-kmip"]
