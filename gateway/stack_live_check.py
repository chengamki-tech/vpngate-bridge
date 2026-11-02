"""Opt-in Linux acceptance check: subscribed TLS clients through a real VPNGate exit."""
import base64
import ipaddress
import json
import os
import random
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from contextlib import ExitStack
from urllib.parse import parse_qs, unquote, urlsplit

from vpngate_bridge.docker_gateway import DockerGateway
from vpngate_bridge.fetcher import fetch
from vpngate_bridge.lease import renew
from vpngate_bridge.meter import CounterLedger
from vpngate_bridge.panel import Panel, PanelError
from vpngate_bridge.pool import GatewayPool
from vpngate_bridge.ports import PortRegistry
from vpngate_bridge.probe import ProbeError
from vpngate_bridge.process import docker_epoch
from vpngate_bridge.router import GatewayRouter
from vpngate_bridge.runtime import open_bridge
from vpngate_bridge.subscription import subscription
from vpngate_bridge.subscription_http import client_token, subscription_server


def exit_ip(port=None, host='127.0.0.1'):
    args = ['curl', '--disable', '-fsS', '--max-time', '10', '--noproxy', '' if port else '*']
    if port:
        args += ['--socks5-hostname', f'{host}:{port}']
    result = subprocess.run([*args, 'https://api.ipify.org/'], capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise ProbeError('subscribed client request failed')
    return str(ipaddress.ip_address(result.stdout.strip()))


def outbound_from_link(link, certificate_path='/work/cert.pem'):
    """Import the generated link, keeping certificate verification enabled."""
    parsed = urlsplit(link)
    query = parse_qs(parsed.query)
    if parsed.hostname != 'bridge.test' or query.get('sni') != ['bridge.test']:
        raise ValueError('unexpected subscription destination')
    outbound = {'type': parsed.scheme, 'server': '127.0.0.1', 'server_port': parsed.port,
                'tls': {'enabled': True, 'server_name': 'bridge.test', 'certificate_path': certificate_path}}
    if parsed.scheme == 'vless':
        if query.get('security') != ['tls'] or query.get('type') != ['ws'] or query.get('path') != ['/ws']:
            raise ValueError('missing VLESS WS TLS parameters')
        outbound.update(uuid=unquote(parsed.username), transport={'type': 'ws', 'path': query['path'][0]})
    elif parsed.scheme == 'hysteria2':
        outbound['password'] = unquote(parsed.username)
    else:
        raise ValueError('unexpected subscription protocol')
    return outbound


def main():
    direct = exit_ip()
    panel = Panel(os.environ['PANEL_URL'], 'vgb-ci', 'vgb-ci-password')
    for attempt in range(30):
        try:
            panel.login()
            break
        except PanelError:
            if attempt == 29:
                raise
            time.sleep(1)
    identity = str(uuid.uuid4())
    inbound = panel._request('panel/api/inbounds/add', {
        'enable': False, 'remark': 'stack-ci', 'port': 23456, 'protocol': 'vless',
        'settings': {'clients': [], 'decryption': 'none'},
        'streamSettings': {'network': 'tcp', 'security': 'none'},
    })['obj']
    panel._request('panel/api/clients/add', {
        'client': {'id': identity, 'email': 'stack-ci', 'subId': 'stack-ci', 'enable': True,
                   'totalGB': 10000000, 'expiryTime': 0}, 'inboundIds': [inbound['id']],
    })
    grouped = fetch()
    candidates = [candidate for group in grouped.values() for candidate in group]
    random.shuffle(candidates)
    # Prefer a dynamically discovered country with enough volunteers for replacement.
    candidates.sort(key=lambda candidate: -len(grouped[candidate.country]))
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        host = subprocess.check_output(['docker', 'network', 'inspect', '--format',
                                        '{{(index .IPAM.Config 0).Gateway}}', 'bridge'], text=True).strip()
        router = GatewayRouter(host, root / 'routes.json')
        pool = GatewayPool(DockerGateway('bridge'), PortRegistry(root / 'ports.sqlite', 20000, 60000, {10085}),
                           None, 1, router.publish)
        try:
            for candidate in candidates[:6]:
                try:
                    route = pool.replace(candidate, ())
                    break
                except (ProbeError, ValueError) as exc:
                    print(f'candidate rejected: {exc}', flush=True)
            else:
                raise RuntimeError('no real qualified VPNGate relay available')
            print(f'qualified {route.country}; testing subscribed TLS clients', flush=True)
            endpoint = router.countries()[0]
            if exit_ip(endpoint.socks_port, endpoint.socks_host) != route.exit_ip:
                raise RuntimeError('private router did not preserve the selected gateway exit')
            check_stack(root, route, panel, direct, pool, router, candidates)
        finally:
            try:
                pool.close()
            finally:
                router.close()


def check_stack(root, route, panel, direct, pool, router, candidates):
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                    '-subj', '/CN=bridge.test', '-addext', 'subjectAltName=DNS:bridge.test', '-days', '1'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    countries = router.countries()
    containers, leases, errors = [], {}, []
    lock, stop = threading.Lock(), threading.Event()
    controller, http, http_thread = None, None, None
    managed, server = ExitStack(), None

    def refresh():
        while not stop.wait(1):
            try:
                with lock:
                    for path, run_id in leases.values():
                        renew(path, run_id, duration=10)
                if controller is not None:
                    controller.tick()
            except Exception as exc:
                errors.append(type(exc).__name__)
                stop.set()

    def start(name, content):
        config_path = root / (name + '.json')
        config_path.write_text(json.dumps(content))
        lease_dir = root / name
        lease_dir.mkdir()
        run_id = str(uuid.uuid4())
        path = lease_dir / 'lease.json'
        renew(path, run_id, duration=10)
        with lock:
            leases[name] = (path, run_id)
        container = subprocess.check_output([
            'docker', 'run', '-d', '--network', 'host', '-e', 'BRIDGE_RUN_ID=' + run_id,
            '-v', f'{lease_dir}:/run/vgb:ro', '-v', f'{root}:/work:ro',
            'vpngate-sing-box', 'run', '-c', '/work/' + config_path.name,
        ], text=True).strip()
        containers.append(container)
        return container

    refresher = threading.Thread(target=refresh, daemon=True)
    refresher.start()
    try:
        ledger = CounterLedger(root / 'meter.sqlite')
        secret = secrets.token_bytes(32)
        runtime = managed.enter_context(open_bridge(
            panel, ledger, str(uuid.uuid4()), countries, secret, root / 'cert.pem', root / 'key.pem',
            root, os.environ['STATS_PROTO'], listen='127.0.0.1'))
        server, config, controller = runtime.container_id, runtime.config, runtime.coordinator
        epoch = docker_epoch(server)
        eligible = controller.tick()
        http = subscription_server(0, secret, controller.tick,
                                   lambda name: subscription(config, name, 'bridge.test'))
        http_thread = threading.Thread(target=http.serve_forever, daemon=True)
        http_thread.start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f'http://127.0.0.1:{http.server_port}/sub/' + client_token(secret, eligible[0])
        with opener.open(url, timeout=15) as response:
            links = base64.b64decode(response.read(), validate=True).decode().splitlines()
        if len(links) != 2 or {urlsplit(link).scheme for link in links} != {'vless', 'hysteria2'}:
            raise RuntimeError('subscription did not contain both protocols')
        for index, link in enumerate(links):
            port = 1081 + index
            start('client-' + str(index), {
                'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': port}],
                'outbounds': [outbound_from_link(link)],
            })
            for attempt in range(10):
                try:
                    actual = exit_ip(port)
                    break
                except ProbeError:
                    if attempt == 9:
                        raise
                    time.sleep(.3)
            if actual != route.exit_ip or actual == direct:
                raise RuntimeError('subscribed client bypassed the selected gateway')
            print(urlsplit(link).scheme + ' TLS verified; selected VPNGate exit matched', flush=True)
        replacements = [candidate for candidate in candidates
                        if candidate.country == route.country and candidate.ip != route.server_ip]
        for candidate in replacements[:6]:
            try:
                replacement = pool.replace(candidate, ())
                break
            except (ProbeError, ValueError) as exc:
                if pool.routes().get(route.country) != route or router.countries() != countries:
                    raise RuntimeError('failed staging changed the active route') from exc
                print(f'replacement candidate rejected; old route retained: {exc}', flush=True)
        else:
            raise RuntimeError('no second qualified same-country relay available')
        if router.countries() != countries or docker_epoch(server) != epoch:
            raise RuntimeError('gateway replacement changed listeners or restarted sing-box')
        for port in (1081, 1082):
            if exit_ip(port) != replacement.exit_ip:
                raise RuntimeError('subscribed client failed after gateway replacement')
        with opener.open(url, timeout=15) as response:
            if base64.b64decode(response.read(), validate=True).decode().splitlines() != links:
                raise RuntimeError('gateway replacement changed subscription credentials or endpoints')
        print('real OpenVPN gateway replaced; both subscribed clients survived without sing-box restart', flush=True)
        controller.tick()
        usage = ledger.usage('stack-ci')
        if usage is None or min(usage) <= 0 or panel.clients()[0].panel_bytes != sum(usage):
            raise RuntimeError('real client traffic did not reach panel accounting')
        names = subprocess.check_output([
            'docker', 'ps', '--filter', 'label=org.vpngate-bridge.probe', '--format', '{{.Names}}',
        ], text=True).splitlines()
        if len(names) != 1:
            raise RuntimeError('unexpected gateway count')
        subprocess.run(['docker', 'exec', names[0], 'pkill', '-9', 'openvpn'], check=True)
        time.sleep(2)
        for port in (1081, 1082):
            try:
                exit_ip(port)
            except ProbeError:
                continue
            raise RuntimeError('subscribed client retained traffic after tunnel loss')
        # A higher panel total must withdraw subscription access and stop the same bridge.
        panel.push_global_totals(controller.source_guid, {'stack-ci': (usage[0] + 100000, usage[1] + 100000)})
        if not stop.wait(10) or not errors:
            raise RuntimeError('accounting mismatch did not stop lease renewal')
        try:
            opener.open(url, timeout=15)
        except urllib.error.HTTPError as exc:
            if exc.code != 503:
                raise
        else:
            raise RuntimeError('revoked subscription remained available')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            running = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.Running}}', server], text=True).strip()
            if running == 'false':
                break
            time.sleep(.2)
        else:
            raise RuntimeError('revoked bridge did not stop')
        print('full live stack passed: TLS subscription import, both protocols, real exit, accounting and fail-closed checks', flush=True)
    finally:
        stop.set()
        refresher.join(timeout=40)
        if http is not None:
            http.shutdown()
            http_thread.join()
            http.server_close()
        if server is not None:
            subprocess.run(['docker', 'logs', '--tail', '4', server])
        managed.close()
        for container in reversed(containers):
            subprocess.run(['docker', 'logs', '--tail', '4', container])
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
