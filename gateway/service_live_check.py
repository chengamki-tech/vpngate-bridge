"""Run the actual service with a bounded, live-discovered acceptance candidate set."""
import base64
import json
import logging
import os
import random
import socket
import ssl
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from unittest.mock import patch

from gateway.stack_live_check import exit_ip, outbound_from_link
from vpngate_bridge.fetcher import fetch
from vpngate_bridge.panel import Panel, PanelError
from vpngate_bridge.meter import CounterLedger
from vpngate_bridge.service import parser, serve


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    panel = Panel(os.environ['PANEL_URL'], 'vgb-ci', 'vgb-ci-password')
    for attempt in range(30):
        try:
            panel.login()
            break
        except PanelError:
            if attempt == 29:
                raise
            time.sleep(1)
    inbound = panel._request('panel/api/inbounds/add', {
        'enable': False, 'remark': 'service-ci', 'port': 23456, 'protocol': 'vless',
        'settings': {'clients': [], 'decryption': 'none'},
        'streamSettings': {'network': 'tcp', 'security': 'none'},
    })['obj']
    panel._request('panel/api/clients/add', {'client': {
        'id': str(uuid.uuid4()), 'email': 'service-ci', 'subId': 'service-ci', 'enable': True,
        'totalGB': 10000000, 'expiryTime': 0}, 'inboundIds': [inbound['id']]})
    grouped = fetch()
    country = max(grouped, key=lambda code: len(grouped[code]))
    random.shuffle(grouped[country])
    candidates = {country: grouped[country][:8]}
    direct = exit_ip()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                        '-subj', '/CN=bridge.test', '-addext', 'subjectAltName=DNS:bridge.test,IP:127.0.0.1', '-days', '1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        binary = root / 'sing-box'
        with binary.open('wb') as output:
            subprocess.run(['docker', 'run', '--rm', '--entrypoint', 'cat', 'vpngate-sing-box',
                            '/usr/local/bin/sing-box'], check=True, stdout=output)
        binary.chmod(0o700)
        args = parser().parse_args(['--state-dir', str(root / 'state'), '--network', 'bridge',
                                    '--hostname', 'bridge.test', '--certificate', str(root / 'cert.pem'),
                                    '--key', str(root / 'key.pem'), '--listen', '127.0.0.1',
                                    '--subscription-port', '0', '--max-countries', '1'])
        previous_usage, previous_links, previous_paths = 0, None, None
        for round_index in range(2):
            stop, errors, clients = threading.Event(), [], []
            frontend = None

            def run():
                try:
                    serve(args, stop)
                except Exception as exc:
                    errors.append(exc)
                    stop.set()

            with patch.dict(os.environ, {'PANEL_USERNAME': 'vgb-ci', 'PANEL_PASSWORD': 'vgb-ci-password'}), \
                    patch('vpngate_bridge.service.fetch', return_value=candidates):
                worker = threading.Thread(target=run, daemon=True)
                worker.start()
                access = args.state_dir / 'access.json'
                try:
                    deadline = time.monotonic() + 600
                    while not access.exists():
                        if errors:
                            raise errors[0]
                        if time.monotonic() > deadline:
                            raise RuntimeError('service did not become ready')
                        time.sleep(.5)
                    ready = json.loads(access.read_text())
                    route = json.loads((args.state_dir / 'routes.json').read_text())['countries'][country]
                    proxy = (Path(__file__).resolve().parent.parent / 'deploy' / 'nginx.conf').read_text()
                    proxy = proxy.replace('listen 80;', 'listen 127.0.0.1:80;').replace(
                        'listen 443 ssl;', 'listen 127.0.0.1:443 ssl;').replace(
                        'bridge.example.com', 'bridge.test').replace('127.0.0.1:8080', ready['listen'])
                    (root / 'nginx.conf').write_text(proxy)
                    mounts = ['--mount', f'type=bind,src={root / "nginx.conf"},dst=/etc/nginx/conf.d/default.conf,readonly',
                              '--mount', f'type=bind,src={root / "cert.pem"},dst=/etc/vpngate-bridge/tls/fullchain.pem,readonly',
                              '--mount', f'type=bind,src={root / "key.pem"},dst=/etc/vpngate-bridge/tls/privkey.pem,readonly']
                    subprocess.run(['docker', 'run', '--rm', '--entrypoint', 'nginx', *mounts,
                                    'nginx:stable-alpine', '-t'], check=True)
                    frontend = subprocess.check_output(['docker', 'run', '-d', '--network', 'host',
                                                         '--entrypoint', 'nginx', *mounts,
                                                         'nginx:stable-alpine', '-g', 'daemon off;'], text=True).strip()
                    context = ssl.create_default_context(cafile=str(root / 'cert.pem'))
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                         urllib.request.HTTPSHandler(context=context))
                    url = 'https://127.0.0.1/sub/' + ready['subscriptions']['service-ci'].rsplit('/', 1)[1]
                    for attempt in range(20):
                        try:
                            with opener.open(url, timeout=15) as response:
                                links = base64.b64decode(response.read(), validate=True).decode().splitlines()
                            break
                        except urllib.error.HTTPError:
                            raise
                        except urllib.error.URLError:
                            if attempt == 19:
                                raise
                            time.sleep(.1)
                    print('actual service: verified HTTPS subscription through deployment Nginx template', flush=True)
                    if previous_links is not None and (links != previous_links or ready['subscriptions'] != previous_paths):
                        raise RuntimeError('normal service restart changed cached subscription credentials or endpoints')
                    if len(links) != 2:
                        raise RuntimeError('service subscription missing a protocol')
                    for index, link in enumerate(links):
                        port = 1081 + index
                        path = root / f'client-{index}.json'
                        path.write_text(json.dumps({
                            'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': port}],
                            'outbounds': [outbound_from_link(link, certificate_path=str(root / 'cert.pem'))],
                        }))
                        log = root / f'client-{index}.log'
                        with log.open('wb') as output:
                            clients.append(subprocess.Popen([str(binary), 'run', '-c', str(path)],
                                                            stdout=output, stderr=subprocess.STDOUT))
                        for attempt in range(30):
                            if clients[-1].poll() is not None:
                                raise RuntimeError('subscription client exited before opening SOCKS')
                            try:
                                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                                    break
                            except OSError:
                                time.sleep(.1)
                        else:
                            raise RuntimeError('subscription client did not open SOCKS')
                        actual = exit_ip(port)
                        if actual != route['exit_ip'] or actual == direct:
                            raise RuntimeError('service client did not use the selected VPNGate exit')
                        print(f'actual service: protocol {index + 1} imported and exit matched', flush=True)
                    deadline = time.monotonic() + 15
                    while panel.clients()[0].panel_bytes <= previous_usage:
                        if errors:
                            raise errors[0]
                        if time.monotonic() > deadline:
                            raise RuntimeError('service failed to synchronize client traffic')
                        time.sleep(.5)
                    print('actual service: real client usage synchronized to 3x-ui', flush=True)
                    logs = subprocess.check_output(['docker', 'logs', frontend], stderr=subprocess.STDOUT, text=True)
                    if any(path in logs for path in ready['subscriptions'].values()):
                        raise RuntimeError('reverse proxy logged subscription credentials')
                finally:
                    stop.set()
                    if frontend is not None:
                        subprocess.run(['docker', 'rm', '-f', frontend], stdout=subprocess.DEVNULL)
                    worker.join(timeout=120)
                    for client in clients:
                        client.terminate()
                        try:
                            client.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            client.kill()
                            client.wait()
                    for path in root.glob('client-*.log'):
                        print('\n'.join(path.read_text().splitlines()[-4:]), flush=True)
                    if worker.is_alive():
                        raise RuntimeError('service did not finish shutdown')
                    if errors:
                        raise errors[0]
                if errors:
                    raise errors[0]
                if access.exists():
                    raise RuntimeError('stopped service retained ready credentials')
                for label in ('org.vpngate-bridge.bridge', 'org.vpngate-bridge.probe'):
                    remaining = subprocess.check_output(['docker', 'ps', '-aq', '--filter', 'label=' + label], text=True).strip()
                    if remaining:
                        raise RuntimeError('service shutdown left owned containers')
                with sqlite3.connect(args.state_dir / 'meter.sqlite3') as database:
                    epoch, clean, certain = database.execute('SELECT epoch, clean, certain FROM meter_state WHERE id=1').fetchone()
                if (clean, certain) != (1, 1):
                    raise RuntimeError('normal service shutdown did not produce a verified final snapshot')
                totals = CounterLedger(args.state_dir / 'meter.sqlite3').closed_totals(epoch)
                usage = sum(totals['service-ci'])
                if usage <= previous_usage or panel.clients()[0].panel_bytes != usage:
                    raise RuntimeError('final service counters were reset or not synchronized')
                previous_usage, previous_links, previous_paths = usage, links, ready['subscriptions']
                print(f'actual service round {round_index + 1}: final counters preserved and synchronized', flush=True)

        print('actual service passed: HTTPS subscriptions, both TLS clients, two clean generations, cumulative accounting and stable cached links', flush=True)


if __name__ == '__main__':
    main()
