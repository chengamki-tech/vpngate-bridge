"""Run the actual service with a bounded, live-discovered acceptance candidate set."""
import base64
import json
import logging
import os
import random
import socket
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
                        '-subj', '/CN=bridge.test', '-addext', 'subjectAltName=DNS:bridge.test', '-days', '1'],
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
        stop, errors, clients = threading.Event(), [], []

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
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                url = 'http://' + ready['listen'] + ready['subscriptions']['service-ci']
                with opener.open(url, timeout=15) as response:
                    links = base64.b64decode(response.read(), validate=True).decode().splitlines()
                if len(links) != 2:
                    raise RuntimeError('service subscription missing a protocol')
                for index, link in enumerate(links):
                    port = 1081 + index
                    path = root / f'client-{index}.json'
                    path.write_text(json.dumps({
                        'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': port}],
                        'outbounds': [outbound_from_link(link)],
                    }))
                    log = root / f'client-{index}.log'
                    with log.open('wb') as output:
                        clients.append(subprocess.Popen([str(binary), 'run', '-c', str(path)],
                                                        stdout=output, stderr=subprocess.STDOUT))
                    for attempt in range(30):
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                                break
                        except OSError:
                            time.sleep(.1)
                    actual = exit_ip(port)
                    if actual != route['exit_ip'] or actual == direct:
                        raise RuntimeError('service client did not use the selected VPNGate exit')
                    print(f'actual service: protocol {index + 1} imported and exit matched', flush=True)
                deadline = time.monotonic() + 15
                while panel.clients()[0].panel_bytes == 0:
                    if errors:
                        raise errors[0]
                    if time.monotonic() > deadline:
                        raise RuntimeError('service failed to synchronize client traffic')
                    time.sleep(.5)
                print('actual service: real client usage synchronized to 3x-ui', flush=True)
            finally:
                stop.set()
                worker.join(timeout=120)
                for client in clients:
                    client.terminate()
                    try:
                        client.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        client.kill()
                        client.wait()
                if worker.is_alive():
                    raise RuntimeError('service did not finish shutdown')
            if errors:
                raise errors[0]
            if access.exists():
                raise RuntimeError('stopped service retained ready credentials')
            for label in ('org.vpngate-bridge.bridge', 'org.vpngate-bridge.probe'):
                remaining = subprocess.check_output(['docker', 'ps', '-aq', '--filter', 'label=' + label], text=True).strip()
                if remaining:
                    raise RuntimeError('service shutdown left owned containers')
            print('actual service passed: discovery, activation, authenticated subscription, both TLS clients, accounting and cleanup', flush=True)


if __name__ == '__main__':
    main()
