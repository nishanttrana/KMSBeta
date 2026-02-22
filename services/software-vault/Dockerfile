FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/kms-software-vault ./services/software-vault

FROM alpine:3.20
RUN adduser -D -u 10001 app
WORKDIR /app
COPY --from=build /out/kms-software-vault /app/kms-software-vault
USER app
EXPOSE 8440 18440
ENTRYPOINT ["/app/kms-software-vault"]
