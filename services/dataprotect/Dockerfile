FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-dataprotect ./services/dataprotect

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-dataprotect /app/kms-dataprotect
COPY services/dataprotect/migrations /app/migrations
EXPOSE 8200 18200
ENTRYPOINT ["/app/kms-dataprotect"]
