FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-cloud ./services/cloud

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-cloud /app/kms-cloud
COPY services/cloud/migrations /app/migrations
EXPOSE 8080 18080
ENTRYPOINT ["/app/kms-cloud"]
