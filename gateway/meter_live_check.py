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
                container = subprocess.check_output(['docker', 'run', '-d', '--network', 'host', '-v', f'{path}:/config.json:ro', IMAGE, 'run', '-c', '/config.json'], text=True).strip()
                containers.append(container)
            for attempt in range(20):
                result = subprocess.run(['curl', '--disable', '-fsS', '--noproxy', '', '--socks5-hostname', '127.0.0.1:1081', '--max-time', '2', 'http://127.0.0.1:18080/'], capture_output=True)
                if result.returncode == 0 and len(result.stdout) == 65536:
                    break
                time.sleep(.5)
            else:
                raise RuntimeError('local VLESS transfer failed')
            ledger = CounterLedger(root / 'meter.sqlite')
            epoch = str(uuid.uuid4())
            ledger.begin(epoch, ['alice'])
            diagnostic = subprocess.run(['grpcurl', '-plaintext', '-import-path', str(Path(os.environ['STATS_PROTO']).parent), '-proto', 'stats.proto', '-d', '{"patterns":["user>>>"],"reset":false}', '127.0.0.1:10085', 'v2ray.core.app.stats.command.StatsService/QueryStats'], capture_output=True, text=True)
            print('test RPC status:', diagnostic.returncode, 'response:', diagnostic.stdout[:2000], 'error:', diagnostic.stderr[:2000], flush=True)
            collect(ledger, epoch, '127.0.0.1:10085', os.environ['STATS_PROTO'], ['alice'], lambda: epoch)
            usage = ledger.usage('alice')
            assert usage is not None and usage[0] > 0 and usage[1] >= 65536, usage
            collect(ledger, epoch, '127.0.0.1:10085', os.environ['STATS_PROTO'], ['alice'], lambda: epoch)
            assert ledger.usage('alice') == usage, 'repeated collection double counted usage'
            print('real VLESS transfer, gRPC collection and idempotent persistence passed')
    finally:
        for container in containers:
            subprocess.run(['docker', 'logs', '--tail', '5', container])
            subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL)
        http.shutdown()
        thread.join()
        http.server_close()


if __name__ == '__main__': main()
