"""Local-only real sing-box VLESS/StatsService integration check for Linux CI."""
import json
import os
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from vpngate_bridge.collector import collect
from vpngate_bridge.meter import CounterLedger
from vpngate_bridge.process import docker_epoch
from vpngate_bridge.lease import renew
from vpngate_bridge.panel import Panel
from vpngate_bridge.coordinator import LeaseCoordinator
from vpngate_bridge.meter import MeterError

IMAGE = 'vpngate-sing-box'
IDENTITY = 'bf000d23-0752-40b4-affe-68f7707a9661'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        body = b'x' * 65536
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    http = ThreadingHTTPServer(('127.0.0.1', 18080), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    containers = []
    leases = []
    stop = threading.Event()
    lease_lock = threading.Lock()
    def refresh():
        while not stop.wait(1):
            with lease_lock:
                for path, identity in tuple(leases): renew(path, identity, duration=5)
    refresher = threading.Thread(target=refresh, daemon=True)
    refresher.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs = {
                'server': {'inbounds': [{'type': 'vless', 'tag': 'test', 'listen': '127.0.0.1', 'listen_port': 20000, 'users': [{'name': 'alice', 'uuid': IDENTITY}]}], 'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'experimental': {'v2ray_api': {'listen': '127.0.0.1:10085', 'stats': {'enabled': True, 'users': ['alice']}}}},
                'client': {'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': 1081}], 'outbounds': [{'type': 'vless', 'server': '127.0.0.1', 'server_port': 20000, 'uuid': IDENTITY}]},
            }
            for name, config in configs.items():
                path = root / (name + '.json')
                path.write_text(json.dumps(config))
                lease_dir = root / name
                lease_dir.mkdir()
                identity = str(uuid.uuid4())
                renew(lease_dir / 'lease.json', identity, duration=5)
                leases.append((lease_dir / 'lease.json', identity))
                container = subprocess.check_output(['docker', 'run', '-d', '--network', 'host', '-e', 'BRIDGE_RUN_ID=' + identity, '-v', f'{lease_dir}:/run/vgb:ro', '-v', f'{path}:/config.json:ro', IMAGE, 'run', '-c', '/config.json'], text=True).strip()
                containers.append(container)
            for attempt in range(20):
                result = subprocess.run(['curl', '--disable', '-fsS', '--noproxy', '', '--socks5-hostname', '127.0.0.1:1081', '--max-time', '2', 'http://127.0.0.1:18080/'], capture_output=True)
                if result.returncode == 0 and len(result.stdout) == 65536:
                    break
                time.sleep(.5)
            else:
                raise RuntimeError('local VLESS transfer failed')
            ledger = CounterLedger(root / 'meter.sqlite')
            epoch = docker_epoch(containers[0])
            ledger.begin(epoch, ['alice'])
            diagnostic = subprocess.run(['grpcurl', '-plaintext', '-import-path', str(Path(os.environ['STATS_PROTO']).parent), '-proto', 'stats.proto', '-d', '{"patterns":["user>>>"],"reset":false}', '127.0.0.1:10085', 'v2ray.core.app.stats.command.StatsService/QueryStats'], capture_output=True, text=True)
            print('test RPC status:', diagnostic.returncode, 'response:', diagnostic.stdout[:2000], 'error:', diagnostic.stderr[:2000], flush=True)
            collect(ledger, epoch, '127.0.0.1:10085', os.environ['STATS_PROTO'], ['alice'], lambda: docker_epoch(containers[0]))
            usage = ledger.usage('alice')
            assert usage is not None and usage[0] > 0 and usage[1] >= 65536, usage
            collect(ledger, epoch, '127.0.0.1:10085', os.environ['STATS_PROTO'], ['alice'], lambda: docker_epoch(containers[0]))
            assert ledger.usage('alice') == usage, 'repeated collection double counted usage'
            if os.environ.get('PANEL_URL'):
                panel = Panel(os.environ['PANEL_URL'], 'vgb-ci', 'vgb-ci-password')
                for attempt in range(30):
                    try:
                        panel.login()
                        break
                    except Exception:
                        if attempt == 29: raise
                        time.sleep(1)
                inbound = panel._request('panel/api/inbounds/add', {'enable': False, 'remark': 'meter-ci', 'port': 23456, 'protocol': 'vless', 'settings': {'clients': [], 'decryption': 'none'}, 'streamSettings': {'network': 'tcp', 'security': 'none'}})['obj']
                panel._request('panel/api/clients/add', {'client': {'id': IDENTITY, 'email': 'alice', 'subId': 'meter-ci', 'enable': True, 'totalGB': 10000000, 'expiryTime': 0}, 'inboundIds': [inbound['id']]})
                with lease_lock:
                    server_lease, server_run = leases.pop(0)
                source = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
                controller = LeaseCoordinator(panel, ledger, source, {'alice': (IDENTITY, 'meter-ci')}, epoch, lambda: docker_epoch(containers[0]), '127.0.0.1:10085', os.environ['STATS_PROTO'], server_lease, server_run)
                assert len(controller.tick()) == 1
                panel.push_global_totals(source, {'alice': (usage[0] + 1000, usage[1] + 1000)})
                try:
                    controller.tick()
                except MeterError:
                    pass
                else:
                    raise RuntimeError('inconsistent panel usage did not revoke runtime')
                assert not server_lease.exists()
                print('real panel/accounting mismatch revoked runtime lease', flush=True)
            stop.set()
            refresher.join()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                running = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.Running}}', containers[0]], text=True).strip()
                if running == 'false': break
                time.sleep(.2)
            else: raise RuntimeError('bridge survived lease expiration')
            print('real VLESS transfer, gRPC collection, idempotent persistence and lease shutdown passed')
    finally:
        stop.set()
        refresher.join()
        for container in containers:
            subprocess.run(['docker', 'logs', '--tail', '5', container])
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL)
        http.shutdown()
        thread.join()
        http.server_close()


if __name__ == '__main__': main()
