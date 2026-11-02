"""Linux service joining discovery, private gateways, bridge leases and subscriptions."""
import argparse
import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import signal
import stat
import sys
import tempfile
import threading
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

from .docker_gateway import DockerGateway, GatewayError, _docker
from .fetcher import fetch
from .healer import Healer
from .meter import CounterLedger, MeterError
from .panel import Panel, PanelError
from .pool import GatewayPool
from .ports import PortRegistry
from .probe import ClassificationError, ProbeError
from .coordinator import AccessRevoked
from .router import GatewayRouter
from .runtime import open_bridge
from .scanner import scan_ranked
from .selection import Blacklist
from .subscription import subscription, subscription_hostname
from .subscription_http import client_token, subscription_server


def parser():
    command = argparse.ArgumentParser(description='Run the experimental VPNGate bridge service on Linux')
    command.add_argument('--state-dir', required=True, type=Path)
    command.add_argument('--network', required=True, help='dedicated local Docker bridge network')
    command.add_argument('--hostname', required=True, type=subscription_hostname)
    command.add_argument('--certificate', required=True, type=Path)
    command.add_argument('--key', required=True, type=Path)
    command.add_argument('--listen', default='0.0.0.0', type=ipaddress.IPv4Address)
    command.add_argument('--subscription-port', default=8080, type=int)
    command.add_argument('--stats-port', default=10085, type=int)
    command.add_argument('--first-port', default=20000, type=int)
    command.add_argument('--last-port', default=60000, type=int)
    command.add_argument('--max-countries', default=8, type=int)
    command.add_argument('--cpus', default=.5, type=float)
    command.add_argument('--memory-mb', default=128, type=int)
    command.add_argument('--gateway-image', default='vpngate-gateway')
    command.add_argument('--bridge-image', default='vpngate-sing-box')
    return command


def _secret(path):
    if path.exists():
        secret = path.read_bytes()
        if len(secret) != 32:
            raise ValueError('persisted subscription secret must contain exactly 32 bytes')
        return secret
    secret = secrets.token_bytes(32)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(secret)
        output.flush()
        os.fsync(output.fileno())
    return secret


def _write_access(path, value):
    filename = None
    try:
        with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='.access-', delete=False) as output:
            filename = output.name
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(filename, path)
    finally:
        if filename and os.path.exists(filename):
            os.unlink(filename)


def serve(args, stop_event):
    if sys.platform != 'linux':
        raise RuntimeError('the service requires a Linux host with local Docker')
    if (not 0 <= args.subscription_port <= 65535 or not 1 <= args.stats_port <= 65535
            or args.subscription_port == args.stats_port or args.max_countries < 1):
        raise ValueError('invalid listener ports or country limit')
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.state_dir.is_symlink() or stat.S_IMODE(args.state_dir.stat().st_mode) & 0o077:
        raise ValueError('state directory must be private (mode 0700) and not a symlink')
    with (args.state_dir / 'scan.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('another scan or service owns this state directory') from None
        access_path = args.state_dir / 'access.json'
        access_path.unlink(missing_ok=True)
        host = os.environ.get('DOCKER_HOST', '')
        context = _docker('context', 'inspect', '--format', '{{.Endpoints.docker.Host}}')
        if (host and not host.startswith('unix://')) or not context.startswith('unix://'):
            raise RuntimeError('a local Docker Unix socket is required')
        gateways = DockerGateway(args.network, args.gateway_image, args.cpus, args.memory_mb)
        addresses = _docker('network', 'inspect', '--format', '{{range .IPAM.Config}}{{println .Gateway}}{{end}}', args.network)
        bind = next((address for address in addresses.splitlines() if ipaddress.ip_address(address).version == 4), None)
        if bind is None:
            raise ValueError('Docker network has no IPv4 gateway')
        secret = _secret(args.state_dir / 'subscription.key')
        source = str(uuid.uuid5(uuid.NAMESPACE_URL, hmac.new(secret, b'panel-source', hashlib.sha256).hexdigest()))
        panel = Panel(os.environ['PANEL_URL'], os.environ['PANEL_USERNAME'], os.environ['PANEL_PASSWORD'])
        panel.login(two_factor_code=os.environ.get('PANEL_2FA_CODE'))
        blacklist = Blacklist(args.state_dir / 'blacklist.sqlite3')
        registry = PortRegistry(args.state_dir / 'ports.sqlite3', args.first_port, args.last_port,
                                {port for port in (args.stats_port, args.subscription_port) if port})
        ranked = scan_ranked(fetch(), gateways, os.environ.get('IPAPI_IS_KEY'), blacklist.active(time.time()),
                             blacklist=blacklist, stop_event=stop_event)
        if stop_event.is_set():
            return
        if not ranked:
            raise RuntimeError('no qualified VPNGate country available')
        with ExitStack() as resources:
            router = GatewayRouter(bind, args.state_dir / 'routes.json')
            resources.callback(router.close)
            pool = GatewayPool(gateways, registry, os.environ.get('IPAPI_IS_KEY'), args.max_countries, router.publish)
            resources.callback(pool.close)
            for candidate, measurement in ranked:
                if stop_event.is_set():
                    return
                active = pool.routes()
                if len(active) >= args.max_countries:
                    break
                if candidate.country in active or measurement.exit_ip in {route.exit_ip for route in active.values()}:
                    continue
                try:
                    pool.replace(candidate, blacklist.active(time.time()))
                except (ProbeError, ValueError) as exc:
                    logging.warning('country %s failed activation; trying next qualified candidate: %s', candidate.country, exc)
                    if isinstance(exc, ProbeError) and not isinstance(exc, ClassificationError):
                        blacklist.add(candidate.ip, 'activation probe failed', time.time())
            if stop_event.is_set():
                return
            if not pool.routes():
                raise RuntimeError('no country passed activation checks')
            ledger = CounterLedger(args.state_dir / 'meter.sqlite3')
            proto = Path(__file__).resolve().parent.parent / 'bridge' / 'stats.proto'
            with open_bridge(panel, ledger, source, router.countries(), secret, args.certificate, args.key,
                             args.state_dir, proto, image=args.bridge_image, listen=str(args.listen),
                             stats_port=args.stats_port, stop_event=stop_event) as runtime:
                def authorize():
                    if stop_event.is_set():
                        raise RuntimeError('service is stopping')
                    clients = runtime.coordinator.tick()
                    if stop_event.is_set():
                        runtime.coordinator.revoke()
                        raise RuntimeError('service is stopping')
                    return clients

                def render(name):
                    active = pool.routes()
                    config = dict(runtime.config)
                    config['inbounds'] = [row for row in config['inbounds'] if row['tag'].rsplit('-', 1)[1] in active]
                    return subscription(config, name, args.hostname)

                http = subscription_server(args.subscription_port, secret, authorize, render)
                http_thread = threading.Thread(target=http.serve_forever, daemon=True)
                healer = Healer(pool, blacklist, args.state_dir / 'health.sqlite3')
                healer_thread = threading.Thread(target=healer.run, args=(stop_event,), daemon=True)
                try:
                    http_thread.start()
                    healer_thread.start()
                    clients = authorize()
                    _write_access(access_path, {'status': 'ready', 'listen': f'127.0.0.1:{http.server_port}',
                                               'hostname': args.hostname,
                                               'subscriptions': {client.email: '/sub/' + client_token(secret, client)
                                                                 for client in clients}})
                    logging.info('service ready with %d qualified countries; access details are private', len(pool.routes()))
                    while not stop_event.is_set():
                        started = time.monotonic()
                        if not http_thread.is_alive() or not healer_thread.is_alive():
                            raise RuntimeError('service worker stopped unexpectedly')
                        runtime.coordinator.tick()
                        stop_event.wait(max(0, 5 - (time.monotonic() - started)))
                finally:
                    stop_event.set()
                    runtime.coordinator.revoke()
                    access_path.unlink(missing_ok=True)
                    if http_thread.is_alive():
                        http.shutdown()
                        http_thread.join()
                    http.server_close()
                    if healer_thread.is_alive():
                        healer_thread.join()


def main(argv=None):
    args = parser().parse_args(argv)
    stop = threading.Event()
    for event in (signal.SIGINT, signal.SIGTERM):
        signal.signal(event, lambda *_: stop.set())
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    try:
        serve(args, stop)
    except Exception as exc:
        if isinstance(exc, InterruptedError) and stop.is_set():
            return 0
        # Underlying exceptions can embed panel credentials or subscription URLs.
        detail = str(exc) if isinstance(exc, (AccessRevoked, GatewayError, MeterError, PanelError)) else type(exc).__name__
        logging.error('service stopped (%s); no runtime restart attempted', detail)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
