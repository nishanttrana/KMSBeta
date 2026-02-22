FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-hyok ./services/hyok

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-hyok /app/kms-hyok
COPY services/hyok/migrations /app/migrations
EXPOSE 8120 18120
ENTRYPOINT ["/app/kms-hyok"]
