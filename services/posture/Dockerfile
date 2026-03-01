FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-posture ./services/posture

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-posture /app/kms-posture
COPY services/posture/migrations /app/migrations
EXPOSE 8220 18220
ENTRYPOINT ["/app/kms-posture"]

