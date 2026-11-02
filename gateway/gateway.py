"""Run a private SOCKS gateway only while its OpenVPN tunnel is up."""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from vpngate_bridge.openvpn import safe_config


def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def install_firewall(server, port, protocol):
    # Default-deny first; never leave a permissive window if a later rule fails.
    for tool in ('iptables', 'ip6tables'):
        for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
            run(tool, '-P', chain, 'DROP')
    run('iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT')
    run('iptables', '-A', 'INPUT', '-i', 'tun0', '-j', 'ACCEPT')
    run('iptables', '-A', 'INPUT', '-i', 'eth0', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
    run('iptables', '-A', 'INPUT', '-i', 'eth0', '-p', 'tcp', '--dport', '1080', '-j', 'ACCEPT')
    run('iptables', '-A', 'OUTPUT', '-o', 'lo', '-d', '127.0.0.1', '-j', 'ACCEPT')
    run('iptables', '-A', 'OUTPUT', '-o', 'tun0', '-j', 'ACCEPT')
    run('iptables', '-A', 'OUTPUT', '-o', 'eth0', '-p', 'tcp', '--sport', '1080', '-m', 'conntrack', '--ctstate', 'ESTABLISHED', '-j', 'ACCEPT')
    run('iptables', '-A', 'OUTPUT', '-o', 'eth0', '-p', protocol, '-d', server, '--dport', port, '-j', 'ACCEPT')


def main():
    source = Path('/config/client.ovpn').read_text(encoding='utf-8')
    if len(source) > 256 * 1024:
        raise ValueError('configuration too large')
    config = safe_config(source, os.environ['VPN_SERVER_IP'])
    lines = config.splitlines()
    remote = next(line.split() for line in lines if line.startswith('remote '))
    protocol = next(line.split()[1] for line in lines if line.startswith('proto '))
    install_firewall(remote[1], remote[2], 'tcp' if protocol == 'tcp-client' else 'udp')
    # Avoid Docker's 127.0.0.11 DNS forwarding, which can bypass the tunnel.
    Path('/etc/resolv.conf').write_text('nameserver 1.1.1.1\n', encoding='ascii')
    fd = os.open('/tmp/client.ovpn', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(config)
    vpn = subprocess.Popen(['openvpn', '--config', '/tmp/client.ovpn'])
    socks = None
    def stop(*_):
        if socks and socks.poll() is None:
            socks.terminate()
        if vpn.poll() is None:
            vpn.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and vpn.poll() is None:
            route = subprocess.run(['ip', '-4', 'route', 'get', '1.1.1.1'], capture_output=True, text=True)
            if route.returncode == 0 and 'dev tun0' in route.stdout.split(' src ')[0]:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('VPN tunnel did not become ready within 10 seconds')
        socks = subprocess.Popen(['sockd', '-f', '/etc/sockd.conf'])
        while vpn.poll() is None and socks.poll() is None:
            time.sleep(.5)
        raise RuntimeError('VPN or SOCKS process exited')
    finally:
        stop()
        if socks:
            socks.wait(timeout=5)
        vpn.wait(timeout=5)


if __name__ == '__main__':
    try:
        main()
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('gateway failed:', exc, file=sys.stderr)
        sys.exit(1)
