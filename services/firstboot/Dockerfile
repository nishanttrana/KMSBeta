FROM vecta-local/golang:1.26-alpine AS build
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org \
    GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN sh -ec 'for attempt in 1 2 3 4 5; do go mod download && exit 0; sleep $((attempt * 2)); done; exit 1'
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/kms-firstboot ./services/firstboot

FROM vecta-local/alpine:3.20
RUN apk add --no-cache bash docker-cli docker-cli-compose
WORKDIR /app
COPY --from=build /out/kms-firstboot /app/kms-firstboot
EXPOSE 9443
ENTRYPOINT ["/app/kms-firstboot"]
