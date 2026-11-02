"""Generate sing-box inbounds routed exclusively to private SOCKS gateways."""
import ipaddress
import re
import uuid
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class Client:
    name: str
    uuid: str
    password: str


@dataclass(frozen=True)
class Country:
    code: str
    socks_host: str
    socks_port: int
    vless_port: int
    hy2_port: int


def build_config(countries, clients, certificate_path, key_path, *, stats_port=10085):
    if not countries or not clients:
        raise ValueError('at least one country and authenticated client are required')
    if any(not isinstance(p, str) or not PurePosixPath(p).is_absolute() for p in (certificate_path, key_path)):
        raise ValueError('absolute TLS certificate and key paths required')
    names, ids, passwords = set(), set(), set()
    vless_users, hy2_users = [], []
    for user in clients:
        try:
            ident = str(uuid.UUID(user.uuid))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('invalid client UUID') from exc
        if (not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', user.name)
                or not isinstance(user.password, str) or len(user.password) < 16
                or user.name in names or ident in ids or user.password in passwords):
            raise ValueError('invalid or duplicate client credentials')
        names.add(user.name)
        ids.add(ident)
        passwords.add(user.password)
        vless_users.append({'name': user.name, 'uuid': ident})
        hy2_users.append({'name': user.name, 'password': user.password})
    if type(stats_port) is not int or not 1 <= stats_port <= 65535:
        raise ValueError('invalid stats port')
    codes, ports = set(), {stats_port}
    inbounds, outbounds, rules = [], [], []
    tls = {'enabled': True, 'certificate_path': certificate_path, 'key_path': key_path}
    for country in countries:
        try:
            address = ipaddress.ip_address(country.socks_host)
        except ValueError as exc:
            raise ValueError('SOCKS host must be a private IPv4 address') from exc
        if (not re.fullmatch(r'[A-Z]{2}', country.code) or country.code in codes
                or address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local):
            raise ValueError('invalid country or gateway address')
        for port in (country.socks_port, country.vless_port, country.hy2_port):
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('invalid port')
        if country.vless_port == country.hy2_port or ports.intersection((country.vless_port, country.hy2_port)):
            raise ValueError('duplicate public port')
        codes.add(country.code)
        ports.update((country.vless_port, country.hy2_port))
        code = country.code
        inbounds.extend([
            {'type': 'vless', 'tag': 'vless-' + code, 'listen': '0.0.0.0', 'listen_port': country.vless_port,
             'users': vless_users, 'tls': tls, 'transport': {'type': 'ws', 'path': '/ws'}},
            {'type': 'hysteria2', 'tag': 'hy2-' + code, 'listen': '0.0.0.0', 'listen_port': country.hy2_port,
             'users': hy2_users, 'tls': tls},
        ])
        outbounds.append({'type': 'socks', 'tag': 'socks-' + code, 'server': str(address),
                          'server_port': country.socks_port, 'version': '5', 'network': 'tcp'})
        rules.append({'inbound': ['vless-' + code, 'hy2-' + code], 'outbound': 'socks-' + code})
    rules.append({'action': 'reject'})
    return {'inbounds': inbounds, 'outbounds': outbounds, 'route': {'rules': rules},
            'experimental': {'v2ray_api': {'listen': f'127.0.0.1:{stats_port}',
                                            'stats': {'enabled': True, 'users': sorted(names)}}}}
