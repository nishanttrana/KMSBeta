FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/kms-pqc ./services/pqc

FROM alpine:3.20
RUN adduser -D -u 10001 app
WORKDIR /app
COPY --from=build /out/kms-pqc /app/kms-pqc
COPY services/pqc/migrations /app/migrations
USER app
EXPOSE 8060 18060
ENTRYPOINT ["/app/kms-pqc"]
