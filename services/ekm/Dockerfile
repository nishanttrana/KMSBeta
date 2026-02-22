FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-ekm ./services/ekm

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-ekm /app/kms-ekm
COPY services/ekm/migrations /app/migrations
EXPOSE 8130 18130
ENTRYPOINT ["/app/kms-ekm"]

