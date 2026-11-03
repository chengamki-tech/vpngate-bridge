# Experimental Linux deployment

The service joins discovery, measured selection, gateway activation, stable private routing, sing-box leases, subscriptions, dynamic client-roster reconciliation and the ten-minute healer. It is not production-ready: crashed bridge epochs require reconciliation before another start. A normally stopped epoch may start again only if its final snapshot validated and closed it clean; otherwise it stays unconfirmed and also requires reconciliation. Do not delete the ledger to bypass that check. The systemd template deliberately uses `Restart=no`.

## Prerequisites

- Linux with local rootful Docker, `/dev/net/tun`, Python 3.9+, curl, iproute2 and grpcurl on the controller PATH. Docker access grants host-level privileges.
- A 3x-ui management-only panel with **every inbound disabled**, pre-created VLESS clients, and HTTPS access (numeric loopback HTTP is supported). Existing panel traffic must agree with the preserved local ledger; a fresh installation cannot silently adopt nonzero usage.
- A domain pointing to the controller and its valid PEM certificate/private key, readable by the controller UID. TLS issuance and rotation are not automated. The bridge currently bind-mounts the selected certificate/key files; replacing symlinks or inodes does not constitute a tested certificate renewal procedure.

Build the two images and create the private bridge network:

```sh
docker build -f gateway/Dockerfile -t vpngate-gateway .
docker build -f bridge/Dockerfile -t vpngate-sing-box .
docker network create vgb-private
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.4
sudo install -m 0755 "$(go env GOPATH)/bin/grpcurl" /usr/local/bin/grpcurl
```

Ensure grpcurl is also on the systemd service PATH (the template uses the system PATH, not an interactive shell's Go bin directory).

## Foreground evaluation

Supply `PANEL_URL`, `PANEL_USERNAME` and `PANEL_PASSWORD` through the environment. `PANEL_2FA_CODE` optionally supplies the initial one-time login code. Start with loopback listeners on an isolated evaluation host:

```sh
python3 -m vpngate_bridge.service \
  --state-dir ./state --network vgb-private \
  --hostname bridge.example.com \
  --certificate /etc/vpngate-bridge/tls/fullchain.pem \
  --key /etc/vpngate-bridge/tls/privkey.pem \
  --listen 127.0.0.1 --max-countries 8
```

The state directory must be private (0700). `subscription.key` persists the HMAC signing key, Hysteria2 credential derivation and panel source identity; preserve it with `ports.sqlite3` and `meter.sqlite3`. Never publish state files. `access.json` contains the loopback subscription listener and per-client bearer paths; combine those paths with the public HTTPS origin only after configuring the reverse proxy. The service removes readiness credentials on normal shutdown and before a subsequent startup attempt.

`routes.json` records current private SOCKS endpoints and public country ports. Each gateway is limited to 0.5 CPU and 128 MiB by default; the active-country cap defaults to eight. Flags configure those limits and the country port range. The bridge has a read-only root filesystem, no Linux capabilities, the controller's UID/GID, one CPU, 256 MiB and 128 PIDs. The private TCP router caps streams at 256.

Initial discovery probes the live list serially and may take several minutes. If no country qualifies, startup exits without opening bridge listeners. The initial country set is discovered dynamically; healing can remove or reactivate those countries without changing their subscriptions. The service polls 3x-ui clients every five seconds. An added, removed, expired or identity-changed client ends the current accounted generation and opens a reconciled generation without changing the loopback subscription listener; cached links remain unchanged only while client identity/subscription ID remains unchanged. Discovery of additional countries during runtime still requires the service to be restarted.

## Deployment templates

The systemd unit assumes a checkout at `/opt/vpngate-bridge`, state at `/var/lib/vpngate-bridge`, and a dedicated `vgb-private` Docker network. Replace the example domain and TLS paths. Copy the environment example to `/etc/vpngate-bridge/panel.env`, fill its values, and restrict it to mode 0600. The unit must have a PATH containing docker, curl, ip and grpcurl.

`deploy/nginx.conf` serves only subscriptions on HTTPS port 443 and redirects port 80 to HTTPS. Replace its example domain and certificate paths and match its loopback upstream to `--subscription-port` (8080 by default). Request and error logging are disabled because subscription URLs contain credentials. Validate with `nginx -t` before reloading. The controller defaults to IPv4 public bridge listeners; VLESS/WS/TLS country ports need TCP, Hysteria2 ports need UDP. Keep the panel, subscription backend, stats endpoint and private SOCKS endpoints off public listeners.

## Stop and recovery boundary

SIGINT/SIGTERM stops subscription admission and lease renewal, waits for the current probe to clean up, and removes owned containers. A failed candidate staging attempt preserves the old active route. Forced controller termination can leave private gateway containers behind; on the next service start, only gateways carrying this deployment's instance label are removed. That instance id is derived from the persisted subscription secret for this state directory with its own HMAC domain, it is not the secret itself, and a container is removed only when its probe label also names the container itself, so another instance with a different state directory on the same host is not touched. Instance identity follows the state directory: do not copy a state directory to run a second instance on the same host, because the copy would be treated as the same deployment. Containers created before this label existed, or by a scan without an instance id, carry no instance label; they are logged as legacy on startup and are not removed automatically, so an operator can review them instead of deleting another instance's gateway by mistake. Bridge containers are not covered by this gateway path; they are recovered through their private run manifests. The independent bridge guard expires its lease after at most ten seconds of normal coordinator renewal.

Neither a hard crash nor a normal shutdown without a valid final snapshot has a verified final drained counter snapshot. A normal shutdown attempts one: the runtime stops the bridge, verifies its incarnation, and closes the epoch clean only after the run-UUID snapshot validates; this path has passed two live generations. The runtime records an unclean hard-crash epoch and refuses to reuse it as zero traffic. Panel renewal/reset, operator reconciliation, automatic bridge crash recovery, certificate renewal, destination UDP and long-running load/failover validation remain required before production.
