"""Generate client links from an already authorized sing-box configuration."""
import base64
import re
import uuid
from urllib.parse import quote, urlencode


def subscription(config, client_name, hostname):
    try:
        host = hostname.encode('idna').decode('ascii').lower()
    except (AttributeError, UnicodeError) as exc:
        raise ValueError('invalid subscription hostname') from exc
    labels = host.split('.')
    if (len(host) > 253 or len(labels) < 2 or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)):
        raise ValueError('invalid subscription hostname')
    links, protocols = [], {}
    for inbound in config['inbounds']:
        kind, tag = inbound.get('type'), inbound.get('tag', '')
        if kind not in ('vless', 'hysteria2'):
            continue
        prefix = 'vless-' if kind == 'vless' else 'hy2-'
        code = tag.removeprefix(prefix)
        if not tag.startswith(prefix) or not re.fullmatch(r'[A-Z]{2}', code):
            raise ValueError('invalid country inbound')
        users = [user for user in inbound.get('users', []) if user.get('name') == client_name]
        port = inbound.get('listen_port')
        if len(users) != 1 or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('client is not authorized for all inbounds')
        protocols.setdefault(code, set())
        if kind in protocols[code]:
            raise ValueError('duplicate inbound')
        protocols[code].add(kind)
        if kind == 'vless':
            try:
                credential = str(uuid.UUID(users[0]['uuid']))
            except (KeyError, ValueError, TypeError, AttributeError) as exc:
                raise ValueError('invalid client UUID') from exc
            query = urlencode({'encryption': 'none', 'security': 'tls', 'type': 'ws', 'host': host, 'sni': host, 'path': '/ws'})
            links.append(f'vless://{credential}@{host}:{port}?{query}#{code}-VLESS')
        else:
            password = users[0].get('password')
            if not isinstance(password, str) or not password:
                raise ValueError('invalid client password')
            query = urlencode({'sni': host})
            links.append(f'hysteria2://{quote(password, safe="")}@{host}:{port}/?{query}#{code}-Hysteria2')
    if not links or any(kinds != {'vless', 'hysteria2'} for kinds in protocols.values()):
        raise ValueError('subscription requires both protocols per country')
    return base64.b64encode(('\n'.join(links) + '\n').encode()).decode('ascii')
