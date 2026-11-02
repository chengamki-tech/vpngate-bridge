"""Reduce untrusted VPNGate configuration to a small OpenVPN allowlist."""
import base64
import binascii
import ipaddress
import re

_CIPHER = re.compile(r'[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)*\Z')


def safe_config(config: str, server_ip: str) -> str:
    ip = ipaddress.ip_address(server_ip)
    if not ip.is_global:
        raise ValueError('server IP must be public')
    options = {}
    blocks = {}
    active = None
    ignored = {'client', 'nobind', 'persist-key', 'persist-tun'}
    for raw in config.splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if active:
            if line == f'</{active}>':
                active = None
            else:
                blocks[active].append(line)
            continue
        if line in ('<ca>', '<cert>', '<key>'):
            active = line[1:-1]
            if active in blocks:
                raise ValueError('duplicate inline block')
            blocks[active] = []
            continue
        parts = line.split()
        key, args = parts[0], parts[1:]
        if key in ignored and not args:
            continue
        if key in options:
            raise ValueError('duplicate directive: ' + key)
        if key == 'dev' and args == ['tun']:
            continue
        if key == 'proto' and args in (['udp'], ['tcp'], ['tcp-client']):
            options[key] = 'tcp-client' if args[0] == 'tcp' else args[0]
        elif key == 'remote' and len(args) == 2 and args[1].isascii() and args[1].isdigit() and 1 <= int(args[1]) <= 65535:
            options[key] = str(int(args[1]))
        elif key in ('cipher', 'data-ciphers', 'auth') and len(args) == 1 and _CIPHER.fullmatch(args[0]):
            options[key] = args[0]
        elif key == 'resolv-retry' and args == ['infinite']:
            continue
        elif key == 'verb' and len(args) == 1 and args[0].isdigit() and int(args[0]) <= 9:
            continue
        else:
            raise ValueError('unsupported directive: ' + key)
    if active or 'ca' not in blocks or ('cert' in blocks) != ('key' in blocks) or 'remote' not in options or 'proto' not in options:
        raise ValueError('missing required VPN configuration')
    for name, lines in blocks.items():
        allowed = ('CERTIFICATE',) if name != 'key' else ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY')
        if len(lines) < 3 or not any(lines[0] == f'-----BEGIN {kind}-----' and lines[-1] == f'-----END {kind}-----' for kind in allowed):
            raise ValueError('invalid inline PEM')
        try:
            base64.b64decode(''.join(lines[1:-1]), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError('invalid inline PEM') from exc
    result = ['client', 'dev tun', 'nobind', 'persist-key', 'persist-tun', 'script-security 1',
              'remote-cert-tls server', 'route-nopull', 'redirect-gateway def1', 'proto ' + options['proto'],
              'remote ' + str(ip) + ' ' + options['remote']]
    result += [key + ' ' + options[key] for key in ('cipher', 'data-ciphers', 'auth') if key in options]
    for name, lines in blocks.items():
        result += [f'<{name}>'] + lines + [f'</{name}>']
    return '\n'.join(result + [''])
