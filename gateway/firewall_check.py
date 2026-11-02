"""Linux container smoke check: no direct IPv4/IPv6 or Docker DNS egress."""
import socket
import subprocess
from gateway import install_firewall

install_firewall('8.8.8.8', '1194', 'udp')
for tool in ('iptables', 'ip6tables'):
    for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
        rules = subprocess.check_output([tool, '-S', chain], text=True)
        assert rules.startswith(f'-P {chain} DROP\n'), rules
for host, port in [('1.1.1.1', 443), ('127.0.0.11', 53)]:
    with socket.socket() as sock:
        sock.settimeout(2)
        assert sock.connect_ex((host, port)) != 0, f'unexpected direct access to {host}'
print('firewall smoke check passed')
