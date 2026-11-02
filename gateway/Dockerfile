FROM python:3.12-alpine3.21
RUN apk add --no-cache openvpn iptables iproute2 dante-server
WORKDIR /app
COPY vpngate_bridge /app/vpngate_bridge
COPY gateway/gateway.py /app/gateway.py
COPY gateway/sockd.conf /etc/sockd.conf
ENTRYPOINT ["python", "/app/gateway.py"]
