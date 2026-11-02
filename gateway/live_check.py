"""Opt-in CI smoke test using live VPNGate relays and temporary containers."""
import ipaddress
import random
import subprocess
import tempfile
import time
from pathlib import Path

from vpngate_bridge.docker_gateway import DockerGateway
from vpngate_bridge.fetcher import fetch
from vpngate_bridge.pool import GatewayPool
from vpngate_bridge.ports import PortRegistry
from vpngate_bridge.probe import ProbeError


def curl(*args):
    return subprocess.run(['curl', '--disable', '-fsS', *args, '--max-time', '5', 'https://api.ipify.org/'], capture_output=True, text=True)


def main():
    direct_response = curl('--noproxy', '*')
    if direct_response.returncode:
        raise SystemExit('cannot determine runner IP')
    direct = ipaddress.ip_address(direct_response.stdout.strip())
    candidates = [candidate for group in fetch().values() for candidate in group]
    random.shuffle(candidates)
    gateways = DockerGateway('bridge')
    attempts = 0
    with tempfile.TemporaryDirectory() as directory:
        registry = PortRegistry(Path(directory) / 'ports.sqlite', 20000, 60000, set())
        published = []
        pool = GatewayPool(gateways, registry, None, 1, lambda routes: published.append(routes))
        for candidate in candidates:
            attempts += 1
            try:
                route = pool.replace(candidate, ())
                address = f'{route.socks_host}:{route.socks_port}'
                try:
                    result = curl('--noproxy', '', '--socks5-hostname', address)
                    if result.returncode:
                        raise ProbeError('SOCKS request failed')
                    exit_ip = ipaddress.ip_address(result.stdout.strip())
                    if not exit_ip.is_global or exit_ip == direct or str(exit_ip) != route.exit_ip:
                        raise RuntimeError('SOCKS exit changed or equals runner IP')
                    print(f'qualified country {route.country}; score probes and classification passed', flush=True)
                    names = subprocess.check_output(['docker', 'ps', '--filter', 'label=org.vpngate-bridge.probe', '--format', '{{.Names}}'], text=True).splitlines()
                    if len(names) != 1:
                        raise RuntimeError('unexpected number of probe containers')
                    subprocess.run(['docker', 'exec', names[0], 'pkill', '-9', 'openvpn'], check=True)
                    time.sleep(2)
                    if curl('--noproxy', '', '--socks5-hostname', address).returncode == 0:
                        raise RuntimeError('SOCKS remained reachable after OpenVPN stopped')
                    print(f'VPN tunnel changed exit and stopped SOCKS after VPN termination; attempts: {attempts}')
                    return
                finally:
                    pool.remove(candidate.country)
            except (ProbeError, ValueError) as exc:
                print(f'candidate rejected: {exc}', flush=True)
            if attempts >= 6:
                break
    raise SystemExit('No real relay connected')


if __name__ == '__main__':
    main()
