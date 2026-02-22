FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-compliance ./services/compliance

FROM alpine:3.21
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /out/kms-compliance /app/kms-compliance
COPY services/compliance/migrations /app/migrations
EXPOSE 8110 18110
ENTRYPOINT ["/app/kms-compliance"]
