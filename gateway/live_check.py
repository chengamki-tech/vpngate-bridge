"""Opt-in CI smoke test using live VPNGate relays and temporary containers."""
import ipaddress
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
    direct = subprocess.run(['curl', '--disable', '-fsS', '--noproxy', '*', '--max-time', '10', 'https://api.ipify.org/'], check=True, capture_output=True, text=True).stdout.strip()
    direct = ipaddress.ip_address(direct)
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
                    if result.returncode == 0:
                        try:
                            exit_ip = ipaddress.ip_address(result.stdout.strip())
                        except ValueError:
                            continue
                        if not exit_ip.is_global or exit_ip == direct:
                            raise RuntimeError('SOCKS exit is invalid or equals runner IP')
                        docker('exec', container, 'pkill', '-9', 'openvpn')
                        time.sleep(2)
                        after = subprocess.run(['curl', '--disable', '-fsS', '--noproxy', '', '--socks5-hostname', address + ':1080', '--max-time', '5', 'https://api.ipify.org/'], capture_output=True, text=True)
                        if after.returncode == 0:
                            raise RuntimeError('SOCKS remained reachable after OpenVPN stopped')
                        print(f'VPN tunnel changed exit and stopped SOCKS after VPN termination; attempts: {attempts}')
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
