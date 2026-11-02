"""Scan candidates; results are not live gateways or subscriptions."""
import argparse
import fcntl
import json
import os
import tempfile
import time
from pathlib import Path

from .docker_gateway import DockerGateway
from .fetcher import fetch
from .ports import PortRegistry
from .scanner import scan
from .selection import Blacklist, score


def main(argv=None):
    parser = argparse.ArgumentParser(description='Scan VPNGate candidates without publishing them')
    parser.add_argument('--network', required=True, help='existing local Docker bridge network')
    parser.add_argument('--state-dir', required=True, type=Path)
    parser.add_argument('--max-countries', type=int, default=8)
    parser.add_argument('--first-port', type=int, default=20000)
    parser.add_argument('--last-port', type=int, default=60000)
    parser.add_argument('--cpus', type=float, default=.5)
    parser.add_argument('--memory-mb', type=int, default=128)
    args = parser.parse_args(argv)
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (args.state_dir / 'scan.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('another scan is already running') from exc
        blacklist = Blacklist(args.state_dir / 'blacklist.sqlite3')
        ports = PortRegistry(args.state_dir / 'ports.sqlite3', args.first_port, args.last_port, set())
        gateway = DockerGateway(args.network, cpus=args.cpus, memory_mb=args.memory_mb)
        selected = scan(fetch(), gateway, os.environ.get('IPAPI_IS_KEY'), blacklist.active(time.time()), args.max_countries)
        countries = {}
        for code, (candidate, measurement) in selected.items():
            vless, hy2 = ports.assign(code)
            countries[code] = {'server_ip': candidate.ip, 'exit_ip': measurement.exit_ip,
                               'score': score(measurement), 'ports': {'vless': vless, 'hysteria2': hy2}}
        result = {'status': 'candidates-only', 'created_at': int(time.time()), 'countries': countries}
        filename = None
        try:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=args.state_dir, prefix='.scan-', delete=False) as output:
                filename = output.name
                json.dump(result, output, sort_keys=True)
                output.write('\n')
                output.flush()
                os.fsync(output.fileno())
            os.replace(filename, args.state_dir / 'scan-results.json')
        finally:
            if filename and os.path.exists(filename):
                os.unlink(filename)
        print(f'{len(countries)} candidate country(s); no gateways published')


if __name__ == '__main__':
    main()
