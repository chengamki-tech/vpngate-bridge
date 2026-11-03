# VPNGate Bridge

**Work in progress. Not production-ready.** This project is intended to turn VPNGate OpenVPN relays into country-specific sing-box entries managed through 3x-ui. An experimental Linux service now joins discovery, private gateway routing, sing-box, authenticated subscriptions, accounting and healing. Normal shutdown accounting and client-roster reconciliation are now implemented and exercised live; panel reset reconciliation and crash recovery remain incomplete.

Implemented components:

- Fetch and parse VPNGate's public OpenVPN list; dynamically discover countries.
- Rebuild relay configurations from an allowlist and pin their remote IP. A Docker gateway installs default-deny IPv4/IPv6 rules and exposes private SOCKS5 after the tunnel is ready.
- Probe through disposable, CPU/memory-limited gateways. Reject timeouts, mismatched country, hosting exits, duplicate IPs and blacklisted subnets; score eligible exits. Scan and healer persist failed relay /24s (IPv4) or /64s (IPv6) for 24 hours and skip matching candidates immediately; metadata-provider outages reject candidates without poisoning relay subnets. Non-hosting classification does **not** prove residential ownership.
- Generate sing-box VLESS/WS/TLS and Hysteria2 configurations, client links and persistent country port assignments. A staged gateway pool re-probes before invoking a route-publisher callback and retains the previous gateway when the callback fails.
- A 3x-ui adapter logs in over HTTPS (or local loopback HTTP). A cumulative SQLite ledger and sing-box gRPC collector synchronize absolute bridge-only traffic totals to disabled management inbounds. A lease coordinator stops the current generation on failed accounting, expiry, quota exhaustion or a client-roster change; the service finalizes it and opens a new generation.
- A healer component runs health checks every 10 minutes, removes a route after two consecutive failures, records failed subnets, and retries same-country selection until a replacement qualifies. The Linux service wires it to the router publisher and stops its worker during shutdown.

The gateway pool and Linux service remain experimental. A TCP router publisher maintains stable host-private SOCKS listeners across gateway replacement, without reloading sing-box. On normal shutdown the bridge freezes counted I/O, writes a run-UUID snapshot, and the runtime closes the meter epoch clean only after that snapshot validates; a missing or invalid snapshot remains blocked for reconciliation. Live two-generation restart and acceptance through HTTPS subscriptions both pass (see below). A 3x-ui client addition is detected within five seconds, the current generation is finalized, and the persistent subscription listener opens a new generation with the new user. Client removal and expiry use the same unit-tested rotation path. Crash recovery is still not implemented; an abruptly killed controller can leave Docker containers behind. The pool does not enforce the transactional behavior of its publisher. `GatewayPool.close()` withdraws all routes before attempting every gateway cleanup and permanently rejects new activation; publisher failure leaves gateways available for a retry. Cleanup failures remain visible on subsequent close calls and require operator recovery. The gateway currently supports TCP SOCKS CONNECT only, not UDP destinations. VPNGate server-certificate purpose is checked, but its certificate identity is not pinned to a hostname. Do not expose the generated inbounds or run this in production.

VPNGate servers are operated by volunteers. Its [logging policy](https://www.vpngate.net/en/about_abuse.aspx) describes connection and destination metadata logging. Subscription content contains client credentials: base64 is not encryption.

## Evaluation scan

Requires Linux, local Docker with `/dev/net/tun`, curl, Python 3.9+, and a dedicated Docker bridge network. Docker access is privileged. Build `docker build -f gateway/Dockerfile -t vpngate-gateway .`, create a network such as `docker network create vgb-private`, then run:

```sh
python3 -m vpngate_bridge --network vgb-private --state-dir ./state --max-countries 8
```

This produces `state/scan-results.json` containing **candidates only**; it does not leave qualifying gateways running or publish subscriptions. Saved listener ports are not checked against unrelated host services. The scan may take a long time and uses third-party IP and speed-test services. [WhatsMyIP.now](https://whatsmyip.now/api) is the default keyless classification provider and documents 30 lookups per minute per source IP; set `IPAPI_IS_KEY` to use [ipapi.is](https://ipapi.is/developers.html) instead. Missing data, rate limits and provider errors reject candidates. IP classification is approximate.

Run unit tests with `python3 -m unittest discover -s tests -v`. The opt-in `live-gateway.yml` GitHub Actions workflow connects to public VPNGate volunteers and tests the actual tunnel; it can fail when suitable relays are unavailable. The regular CI also builds the gateway, exercises basic firewall restrictions and checks generated configuration with sing-box.

The experimental `subscription_http.subscription_server` listens only on `127.0.0.1` and serves `/sub/<HMAC token>` with `no-store` headers and URL logging disabled. It requires a persisted signing key of at least 32 bytes, an authorization callback that performs fresh verified accounting/panel checks, and a subscription renderer. Tokens remain stable across gateway changes and rotate when client identity/subscription ID changes. The service wires it to fresh coordinator authorization, and an Nginx HTTPS deployment template is provided; downloading a subscription does not revoke credentials already cached by clients, so bridge runtime enforcement remains mandatory.

## Live acceptance evidence

The opt-in [`live-stack.yml`](.github/workflows/live-stack.yml) workflow builds both images and a disposable 3x-ui panel, connects a qualified real VPNGate gateway, downloads an authenticated subscription, imports its links into two sing-box clients, and checks:

- VLESS + WebSocket + verified TLS and Hysteria2 + verified TLS both use the selected exit rather than the runner IP.
- Actual client traffic reaches the SQLite ledger and the panel's absolute traffic overlay.
- Terminating OpenVPN prevents further traffic through either subscribed client.
- Higher panel traffic than the ledger revokes subscription access and terminates the bridge container.

[Run 41441487326 passed](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41441487326) on 2026-11-02 with a qualified KR relay. This is a short acceptance test, not a stability or residential-ownership guarantee. It exposes client/server listeners only on runner loopback, uses an ephemeral trusted test certificate, and does not prove public DNS, certificate issuance, subscription HTTPS or production startup safety.

Still required before production: panel renewal/reset reconciliation, crash recovery, destination UDP, verified certificate rotation and long-running failover/load validation. [Deployment instructions](docs/deployment.md) describe the experimental CLI, systemd and HTTPS templates, including the unclean-epoch restart boundary.

`router.GatewayRouter` is a callable pool publisher for same-host sing-box. On Linux with iproute2, bind it to the host's private Docker bridge gateway address, pass `router.publish` to `GatewayPool`, then build bridge configuration from `router.countries()`. It allocates unique internal TCP listener ports, writes a private atomic route manifest before switching targets, accepts only the bind address and exact IPv4 addresses assigned to this host (including Docker NAT source rewrites), and caps concurrent streams (256 by default). Replacing or removing a backend closes its old streams. A removed country's internal listener is retained but refuses connections, so reactivation reuses its port. Adding/removing public country inbounds still requires the missing service reconfiguration lifecycle; the router does not reload sing-box or recover from process crashes.

The [real replacement acceptance run 41444855011](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41444855011) passed with two different JP relays, unchanged subscription contents and no sing-box restart. [Run 41479673920](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41479673920) subsequently passed the same stack using the pre-authorized, resource-limited `runtime.open_bridge` launcher.

[Run 41574382327](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41574382327) passed deterministic batched discovery and two clean service generations. Both TLS protocols and HTTPS subscription were exercised in each generation; final counters accumulated and synchronized to the panel instead of resetting. [Run 41575307782](https://github.com/chengamki-tech/vpngate-bridge/actions/runs/41575307782) then passed live addition of a second 3x-ui client and reopened the bridge generation without changing the subscription listener or cached links for the existing user.

Start the controller with `python3 -m vpngate_bridge.service --help`. It reads panel credentials from the environment and writes bearer subscription paths only to private `state/access.json`. Service activation tries qualified candidates in score order, skips already-active countries and duplicate exits, and falls back when a scan winner fails its activation probe.
