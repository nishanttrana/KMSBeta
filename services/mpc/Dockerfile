FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-mpc ./services/mpc

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-mpc /app/kms-mpc
COPY services/mpc/migrations /app/migrations
EXPOSE 8190 18190
ENTRYPOINT ["/app/kms-mpc"]
