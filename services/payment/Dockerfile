FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-payment ./services/payment

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-payment /app/kms-payment
COPY services/payment/migrations /app/migrations
EXPOSE 8170 18170
ENTRYPOINT ["/app/kms-payment"]
