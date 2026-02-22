FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-policy ./services/policy

FROM alpine:3.21
RUN adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /out/kms-policy /usr/local/bin/kms-policy
COPY services/policy/migrations /app/migrations
USER app
EXPOSE 8040 18040
ENTRYPOINT ["/usr/local/bin/kms-policy"]
