# VPNGate Bridge

**Work in progress. Not production-ready.** This project is intended to turn VPNGate OpenVPN relays into country-specific sing-box entries managed through 3x-ui. It does not yet provide an operational deployment or an integrated healing service. Accounting, authenticated subscriptions and lease-based revocation are implemented as components and exercised together in opt-in Linux acceptance tests.

Implemented components:

- Fetch and parse VPNGate's public OpenVPN list; dynamically discover countries.
- Rebuild relay configurations from an allowlist and pin their remote IP. A Docker gateway installs default-deny IPv4/IPv6 rules and exposes private SOCKS5 after the tunnel is ready.
- Probe through disposable, CPU/memory-limited gateways. Reject timeouts, mismatched country, hosting exits, duplicate IPs and blacklisted subnets; score eligible exits. Scan and healer persist failed relay /24s (IPv4) or /64s (IPv6) for 24 hours and skip matching candidates immediately; metadata-provider outages reject candidates without poisoning relay subnets. Non-hosting classification does **not** prove residential ownership.
- Generate sing-box VLESS/WS/TLS and Hysteria2 configurations, client links and persistent country port assignments. A staged gateway pool re-probes before invoking a route-publisher callback and retains the previous gateway when the callback fails.
- A 3x-ui adapter logs in over HTTPS (or local loopback HTTP). A cumulative SQLite ledger and sing-box gRPC collector synchronize absolute bridge-only traffic totals to disabled management inbounds. A lease coordinator stops a fixed bridge configuration on failed accounting, expiry, quota exhaustion or changed user identities.
- A healer component runs health checks every 10 minutes, removes a route after two consecutive failures, records failed subnets, and retries same-country selection until a replacement qualifies. It is not yet connected to a route publisher or deployment service.

The pool is an experimental in-process component, not a deployment service. A route publisher and a restart/crash recovery mechanism do not exist yet; an abruptly killed controller can leave Docker containers behind. The pool does not enforce the transactional behavior of its publisher. `GatewayPool.close()` withdraws all routes before attempting every gateway cleanup and permanently rejects new activation; publisher failure leaves gateways available for a retry. Cleanup failures remain visible on subsequent close calls and require operator recovery. The gateway currently supports TCP SOCKS CONNECT only, not UDP destinations. VPNGate server-certificate purpose is checked, but its certificate identity is not pinned to a hostname. Do not expose the generated inbounds or run this in production.

VPNGate servers are operated by volunteers. Its [logging policy](https://www.vpngate.net/en/about_abuse.aspx) describes connection and destination metadata logging. Subscription content contains client credentials: base64 is not encryption.

## Evaluation scan

Requires Linux, local Docker with `/dev/net/tun`, curl, Python 3.9+, and a dedicated Docker bridge network. Docker access is privileged. Build `docker build -f gateway/Dockerfile -t vpngate-gateway .`, create a network such as `docker network create vgb-private`, then run:

```sh
python3 -m vpngate_bridge --network vgb-private --state-dir ./state --max-countries 8
```

This produces `state/scan-results.json` containing **candidates only**; it does not leave qualifying gateways running or publish subscriptions. Saved listener ports are not checked against unrelated host services. The scan may take a long time and uses third-party IP and speed-test services. [WhatsMyIP.now](https://whatsmyip.now/api) is the default keyless classification provider and documents 30 lookups per minute per source IP; set `IPAPI_IS_KEY` to use [ipapi.is](https://ipapi.is/developers.html) instead. Missing data, rate limits and provider errors reject candidates. IP classification is approximate.

Run unit tests with `python3 -m unittest discover -s tests -v`. The opt-in `live-gateway.yml` GitHub Actions workflow connects to public VPNGate volunteers and tests the actual tunnel; it can fail when suitable relays are unavailable. The regular CI also builds the gateway, exercises basic firewall restrictions and checks generated configuration with sing-box.

The experimental `subscription_http.subscription_server` listens only on `127.0.0.1` and serves `/sub/<HMAC token>` with `no-store` headers and URL logging disabled. It requires a persisted signing key of at least 32 bytes, an authorization callback that performs fresh verified accounting/panel checks, and a subscription renderer. Tokens remain stable across gateway changes and rotate when client identity/subscription ID changes. It is not wired into a daemon or TLS reverse proxy yet; downloading a subscription does not revoke credentials already cached by clients, so bridge runtime enforcement remains mandatory.

## Live acceptance evidence

The opt-in [`live-stack.yml`](.github/workflows/live-stack.yml) workflow builds both images and a disposable 3x-ui panel, connects a qualified real VPNGate gateway, downloads an authenticated subscription, imports its links into two sing-box clients, and checks:

- VLESS + WebSocket + verified TLS and Hysteria2 + verified TLS both use the selected exit rather than the runner IP.
- Actual client traffic reaches the SQLite ledger and the panel's absolute traffic overlay.
- Terminating OpenVPN prevents further traffic through either subscribed client.
- Higher panel traffic than the ledger revokes subscription access and terminates the bridge container.

[Run 41441487326 passed](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41441487326) on 2026-11-02 with a qualified KR relay. This is a short acceptance test, not a stability or residential-ownership guarantee. It exposes client/server listeners only on runner loopback, uses an ephemeral trusted test certificate, and does not prove public DNS, certificate issuance, subscription HTTPS or production startup safety.

Still required before deployment: a service entrypoint and route publisher, safe initial admission and drained configuration changes, panel renewal/reset reconciliation, crash recovery, destination UDP support, public TLS deployment and long-running failover/load verification. The live test uses temporary bootstrap leases in a loopback-only environment; do not adapt that startup sequence to public listeners.
