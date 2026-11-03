FROM golang:1.27-alpine AS builder
RUN apk add --no-cache git python3
RUN git clone --depth 1 --branch v1.14.4 https://github.com/SagerNet/sing-box.git /src \
    && test "$(git -C /src rev-parse HEAD)" = c005f35300ce76427dc285481ec5695f5b179cd2
WORKDIR /src
COPY bridge/patch_singbox.py bridge/final_stats.go bridge/final_stats_test.go /patch/
RUN python3 /patch/patch_singbox.py /src \
    && gofmt -w experimental/v2rayapi/final_stats*.go experimental/v2rayapi/stats.go experimental/v2rayapi/server.go \
    && CGO_ENABLED=0 go test ./experimental/v2rayapi -run '^TestFinal' -count=1
RUN CGO_ENABLED=0 go build -trimpath -tags with_quic,with_v2ray_api -o /out/sing-box ./cmd/sing-box
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata python3
COPY --from=builder /out/sing-box /usr/local/bin/sing-box
COPY --from=builder /src/LICENSE /usr/share/licenses/sing-box/LICENSE
COPY vpngate_bridge/__init__.py vpngate_bridge/lease.py /app/vpngate_bridge/
COPY bridge/entrypoint.py /app/entrypoint.py
ENTRYPOINT ["python3", "/app/entrypoint.py"]
