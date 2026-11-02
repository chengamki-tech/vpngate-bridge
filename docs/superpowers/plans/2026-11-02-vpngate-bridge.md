# VPNGate bridge implementation plan

**Goal:** Connect selected VPNGate OpenVPN exits to authenticated sing-box subscriptions, with 3x-ui as management plane.

**Architecture:** Discover and validate public VPNGate configurations; probe through isolated, fail-closed OpenVPN gateways; publish only healthy gateways through sing-box. Synchronize client identity, quota, expiry and measured usage with 3x-ui; preserve public endpoint identities through replacement.

**Constraints:** Dynamic countries; one winning exit per country; 10-second connection timeout; three stability probes; reject wrong country, hosting, duplicate exit and blocked subnets; weighted score 30/30/25/15; private SOCKS, resource limits and max countries; VLESS WS TLS and Hysteria2; 10-minute health checks and replace after two failures.

**Review focus:** Untrusted OpenVPN directives cannot execute host commands or bypass isolation; tunnels fail closed including DNS and IPv6; traffic accounting and expiry must be enforced even when the panel or metrics fail; replacement cannot leak traffic or change subscriptions; crash/restart and stale discovery never advertise broken endpoints.

1. Fetch and validate VPNGate CSV, group candidates dynamically and test malformed inputs.
2. Build isolated gateway and actual tunnel probes, trustworthy exit metadata and measurable scoring; test fail-closed network and duplicate/blacklist rules.
3. Build reconciliation and healer, stable port manifest and limits; verify replacement and restart behaviour.
4. Build sing-box and 3x-ui synchronization, traffic accounting and quota enforcement; validate revocation and failure cases.
5. Build authenticated subscriptions, deployment configuration and documentation; run unit, config and real network end-to-end checks, then publish.
