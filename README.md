# VPNGate Bridge

**Work in progress. Not production-ready.** This project is intended to turn VPNGate OpenVPN relays into country-specific sing-box entries managed through 3x-ui. It does not yet provide an operational deployment, authenticated subscription endpoint, accounting, expiry enforcement, or automated healing.

Implemented components:

- Fetch and parse VPNGate's public OpenVPN list; dynamically discover countries.
- Rebuild relay configurations from an allowlist and pin their remote IP. A Docker gateway installs default-deny IPv4/IPv6 rules and exposes private SOCKS5 after the tunnel is ready.
- Probe through disposable, CPU/memory-limited gateways. Reject timeouts, mismatched country, hosting exits, duplicate IPs and blacklisted subnets; score eligible exits. Non-hosting classification does **not** prove residential ownership.
- Generate sing-box VLESS/WS/TLS and Hysteria2 configurations, client links and persistent country port assignments. A staged gateway pool re-probes before invoking a route-publisher callback and retains the previous gateway when the callback fails.

The pool is an experimental in-process component, not a deployment service. A route publisher and a restart/crash recovery mechanism do not exist yet; an abruptly killed controller can leave Docker containers behind. The pool does not enforce the transactional behavior of its publisher. The gateway currently supports TCP SOCKS CONNECT only, not UDP destinations. VPNGate server-certificate purpose is checked, but its certificate identity is not pinned to a hostname. Do not expose the generated inbounds or run this in production.

VPNGate servers are operated by volunteers. Its [logging policy](https://www.vpngate.net/en/about_abuse.aspx) describes connection and destination metadata logging. Subscription content contains client credentials: base64 is not encryption.

## Evaluation scan

Requires Linux, local Docker with `/dev/net/tun`, curl, Python 3.9+, and a dedicated Docker bridge network. Docker access is privileged. Build `docker build -f gateway/Dockerfile -t vpngate-gateway .`, create a network such as `docker network create vgb-private`, then run:

```sh
python3 -m vpngate_bridge --network vgb-private --state-dir ./state --max-countries 8
```

This produces `state/scan-results.json` containing **candidates only**; it does not leave qualifying gateways running or publish subscriptions. Saved listener ports are not checked against unrelated host services. The scan may take a long time and uses third-party IP and speed-test services. [WhatsMyIP.now](https://whatsmyip.now/api) is the default keyless classification provider and documents 30 lookups per minute per source IP; set `IPAPI_IS_KEY` to use [ipapi.is](https://ipapi.is/developers.html) instead. Missing data, rate limits and provider errors reject candidates. IP classification is approximate.

Run unit tests with `python3 -m unittest discover -s tests -v`. The opt-in `live-gateway.yml` GitHub Actions workflow connects to public VPNGate volunteers and tests the actual tunnel; it can fail when suitable relays are unavailable. The regular CI also builds the gateway, exercises basic firewall restrictions and checks generated configuration with sing-box.
