FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-audit ./services/audit

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-audit /app/kms-audit
COPY services/audit/migrations /app/migrations
EXPOSE 8070 18070
ENTRYPOINT ["/app/kms-audit"]

