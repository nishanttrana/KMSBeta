FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-ai ./services/ai

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-ai /app/kms-ai
COPY services/ai/migrations /app/migrations
EXPOSE 8090 18090
ENTRYPOINT ["/app/kms-ai"]
