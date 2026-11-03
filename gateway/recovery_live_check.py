"""Prove an unclean bridge generation can be finalized after controller loss."""
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from vpngate_bridge.collector import collect
from vpngate_bridge.lease import renew
from vpngate_bridge.meter import CounterLedger, MeterError
from vpngate_bridge.panel import Panel, PanelError
from vpngate_bridge.process import docker_epoch
from vpngate_bridge.runtime import recover_bridges
from vpngate_bridge.sync import sync_bridge_usage


IMAGE = 'vpngate-sing-box'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b'x' * 65536
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def transfer(port):
    return subprocess.run(
        ['curl', '--disable', '-fsS', '--noproxy', '', '--socks5-hostname',
         f'127.0.0.1:{port}', '--max-time', '5', 'http://127.0.0.1:18081/'],
        capture_output=True, timeout=7)


def main():
    email = 'recovery-ci'
    identity = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    source = str(uuid.uuid4())
    container_name = 'vgb-bridge-' + uuid.uuid4().hex
    http = ThreadingHTTPServer(('127.0.0.1', 18081), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    client_container = None
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            run_dir = root / ('run-' + run_id)
            run_dir.mkdir(mode=0o700)
            final_dir = run_dir / 'final'
            final_dir.mkdir(mode=0o700)
            server = {
                'inbounds': [{'type': 'vless', 'tag': 'recovery', 'listen': '127.0.0.1',
                              'listen_port': 20001, 'users': [{'name': email, 'uuid': identity}]}],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                'experimental': {'v2ray_api': {'listen': '127.0.0.1:10086', 'stats': {
                    'enabled': True, 'users': [email]}}},
            }
            client_config = {
                'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': 1082}],
                'outbounds': [{'type': 'vless', 'server': '127.0.0.1', 'server_port': 20001,
                               'uuid': identity}],
            }
            server_path = run_dir / 'config.json'
            server_path.write_text(json.dumps(server))
            client_path = root / 'client.json'
            client_path.write_text(json.dumps(client_config))
            renew(run_dir / 'lease.json', run_id, duration=30)
            container = subprocess.check_output([
                'docker', 'run', '-d', '--name', container_name,
                '--label', 'org.vpngate-bridge.bridge=' + container_name,
                '--network', 'host', '-e', 'BRIDGE_RUN_ID=' + run_id,
                '-e', 'VGB_FINAL_STATS=/run/vgb-final/counters.json',
                '-v', f'{run_dir}:/run/vgb:ro', '-v', f'{final_dir}:/run/vgb-final',
                '-v', f'{server_path}:/config.json:ro', IMAGE, 'run', '-c', '/config.json',
            ], text=True).strip()
            incarnation = docker_epoch(container)
            (root / ('recovery-' + run_id + '.json')).write_text(json.dumps({
                'version': 1, 'run_id': run_id, 'container': container_name,
                'source_guid': source, 'identities': {email: [identity, 'recovery-ci']},
                'status': 'running', 'incarnation': incarnation,
            }))
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(('127.0.0.1', 10086), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('recovery StatsService did not become ready')
            client_container = subprocess.check_output([
                'docker', 'run', '-d', '--name', 'vgb-recovery-client',
                '--rm', '--network', 'host',
                '-v', f'{client_path}:/config.json:ro', IMAGE, 'run', '-c', '/config.json',
            ], text=True).strip()
            for attempt in range(30):
                result = transfer(1082)
                if result.returncode == 0 and len(result.stdout) == 65536:
                    break
                time.sleep(.2)
            else:
                raise RuntimeError('recovery traffic did not flow')

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
                'enable': False, 'remark': 'recovery-ci', 'port': 23457, 'protocol': 'vless',
                'settings': {'clients': [], 'decryption': 'none'},
                'streamSettings': {'network': 'tcp', 'security': 'none'},
            })['obj']
            panel._request('panel/api/clients/add', {'client': {
                'id': identity, 'email': email, 'subId': 'recovery-ci', 'enable': True,
                'totalGB': 10000000, 'expiryTime': 0,
            }, 'inboundIds': [inbound['id']]})

            ledger = CounterLedger(root / 'meter.sqlite')
            ledger.begin(run_id, [email])

            def process_epoch():
                if docker_epoch(container) != incarnation:
                    raise MeterError('recovery process changed')
                return run_id

            collect(ledger, run_id, '127.0.0.1:10086', os.environ['STATS_PROTO'],
                    [email], process_epoch)
            initial = ledger.usage(email)
            if initial is None or initial[0] <= 0 or initial[1] < 65536:
                raise RuntimeError('recovery metering did not observe traffic')
            sync_bridge_usage(panel, ledger, source, {email: (identity, 'recovery-ci')},
                              now=int(time.time()))

            # Removing the lease simulates controller loss; the in-container guard
            # must stop sing-box and emit its final counted snapshot by itself.
            (run_dir / 'lease.json').unlink()
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                running = subprocess.check_output(
                    ['docker', 'inspect', '--format', '{{.State.Running}}', container], text=True).strip()
                if running == 'false':
                    break
                time.sleep(.2)
            else:
                raise RuntimeError('bridge survived lease expiry')
            if not (final_dir / 'counters.json').exists():
                raise RuntimeError('bridge did not emit a final counter snapshot')

            recover_bridges(panel, ledger, root, os.environ['STATS_PROTO'])
            final = ledger.closed_totals(run_id)
            panel_total = next(row for row in panel.clients() if row.email == email).panel_bytes
            if panel_total != sum(final[email]) or sum(final[email]) < sum(initial):
                raise RuntimeError('recovered final counters were not synchronized')
            if run_dir.exists() or (root / ('recovery-' + run_id + '.json')).exists():
                raise RuntimeError('successful recovery retained its private run manifest')
            print('real recovery passed: guard-finalized snapshot, unclean epoch close, panel sync and cleanup',
                  flush=True)
    finally:
        if client_container is not None:
            subprocess.run(['docker', 'rm', '-f', client_container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['docker', 'rm', '-f', container_name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        http.shutdown()
        thread.join()
        http.server_close()


if __name__ == '__main__':
    main()
