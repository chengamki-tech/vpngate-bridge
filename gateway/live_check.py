"""Opt-in CI smoke test using live VPNGate relays and temporary containers."""
import random
import subprocess
import tempfile
import time
from pathlib import Path

from vpngate_bridge.fetcher import fetch
from vpngate_bridge.openvpn import safe_config


def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, text=True, stdout=subprocess.PIPE, **kwargs).stdout.strip()


def main():
    candidates = [c for group in fetch().values() for c in group]
    random.shuffle(candidates)
    attempts = 0
    with tempfile.TemporaryDirectory() as directory:
        for candidate in candidates:
            try:
                safe_config(candidate.config, candidate.ip)
            except ValueError:
                continue
            attempts += 1
            path = Path(directory) / 'client.ovpn'
            path.write_text(candidate.config)
            container = docker('run', '-d', '--cap-add=NET_ADMIN', '--device=/dev/net/tun', '--cpus=0.5', '--memory=128m', '--network=bridge', '-e', f'VPN_SERVER_IP={candidate.ip}', '-v', f'{path}:/config/client.ovpn:ro', 'vpngate-gateway')
            try:
                address = docker('inspect', '-f', '{{.NetworkSettings.IPAddress}}', container)
                deadline = time.monotonic() + 16
                while time.monotonic() < deadline:
                    result = subprocess.run(['curl', '--disable', '-fsS', '--noproxy', '', '--socks5-hostname', address + ':1080', '--max-time', '5', 'https://api.ipify.org/'], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip():
                        print(f'VPNGate tunnel and SOCKS request succeeded after {attempts} attempt(s)')
                        return
                    if docker('inspect', '-f', '{{.State.Running}}', container) != 'true':
                        break
                    time.sleep(1)
                print('candidate failed:', docker('logs', '--tail', '8', container, stderr=subprocess.STDOUT))
            finally:
                docker('rm', '-f', container)
            if attempts >= 4:
                break
    raise SystemExit('No real relay connected; inspect failure logs')


if __name__ == '__main__':
    main()
