FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.Dirty=false" \
    -o /bridge \
    ./cmd/bridge

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata iptables ip6tables openssl

RUN addgroup -g 1000 bridge && \
    adduser -u 1000 -G bridge -s /bin/sh -D bridge

WORKDIR /app

RUN mkdir -p /app/configs /app/peers /app/cache /app/data && \
    chown -R bridge:bridge /app

COPY --from=builder /bridge /app/bridge
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER bridge

EXPOSE 51820/udp
EXPOSE 1080/tcp
EXPOSE 443/tcp
EXPOSE 8443/tcp
EXPOSE 6060/tcp

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/bridge", "run", "-config", "/app/configs/bridge.yaml"]
