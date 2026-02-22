FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-firstboot ./services/firstboot

FROM alpine:3.20
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build /out/kms-firstboot /app/kms-firstboot
USER app
EXPOSE 9443
ENTRYPOINT ["/app/kms-firstboot"]
