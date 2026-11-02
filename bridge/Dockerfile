FROM golang:1.27-alpine AS builder
RUN apk add --no-cache git
RUN git clone --depth 1 --branch v1.14.4 https://github.com/SagerNet/sing-box.git /src \
    && test "$(git -C /src rev-parse HEAD)" = c005f35300ce76427dc285481ec5695f5b179cd2
WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -tags with_quic,with_v2ray_api -o /out/sing-box ./cmd/sing-box
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["sing-box"]
