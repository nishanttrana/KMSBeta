FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-reporting ./services/reporting

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-reporting /app/kms-reporting
COPY services/reporting/migrations /app/migrations
EXPOSE 8140 18140
ENTRYPOINT ["/app/kms-reporting"]
