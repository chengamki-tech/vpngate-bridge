"""Read 3x-ui client state; bridge traffic must be accounted separately."""
import http.cookiejar
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass


class PanelError(Exception):
    """The panel response cannot be trusted for authorization."""


@dataclass(frozen=True)
class PanelClient:
    email: str
    uuid: str
    sub_id: str
    enabled: bool
    expiry_ms: int
    total_bytes: int
    panel_bytes: int

    def authorized(self, *, now_ms, unreported_bridge_bytes):
        if (type(now_ms) is not int or now_ms < 0 or type(unreported_bridge_bytes) is not int
                or unreported_bridge_bytes < 0 or not self.enabled or self.expiry_ms < 0):
            return False
        if self.expiry_ms and now_ms >= self.expiry_ms:
            return False
        return not self.total_bytes or self.panel_bytes + unreported_bridge_bytes < self.total_bytes


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Panel:
    def __init__(self, base_url, username, password):
        if not isinstance(base_url, str) or any(ord(ch) <= 32 for ch in base_url):
            raise ValueError('invalid panel URL')
        try:
            parts = urllib.parse.urlsplit(base_url)
            host = parts.hostname
            _ = parts.port
        except ValueError as exc:
            raise ValueError('invalid panel URL') from exc
        if not host or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError('invalid panel URL')
        if parts.scheme == 'http':
            try:
                if not ipaddress.ip_address(host).is_loopback:
                    raise ValueError('HTTP panel access requires a loopback address')
            except ValueError as exc:
                raise ValueError('HTTP panel access requires a loopback address') from exc
        elif parts.scheme != 'https':
            raise ValueError('panel URL must use HTTPS')
        decoded = urllib.parse.unquote(parts.path)
        if any(segment in ('.', '..') for segment in decoded.split('/')) or '//' in decoded:
            raise ValueError('invalid panel base path')
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            raise ValueError('panel credentials required')
        self._base = base_url.rstrip('/') + '/'
        self._username, self._password = username, password
        self._cookies = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPCookieProcessor(self._cookies))
        self._logged_in = False

    def _request(self, path, body=None):
        data = None if body is None else json.dumps(body).encode('utf-8')
        request = urllib.request.Request(self._base + path, data=data, headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'vpngate-bridge/0.1'})
        try:
            with self._opener.open(request, timeout=10) as response:
                payload = response.read(16 * 1024 * 1024 + 1)
            if len(payload) > 16 * 1024 * 1024:
                raise ValueError('response too large')
            result = json.loads(payload)
            if not isinstance(result, dict) or result.get('success') is not True:
                raise ValueError('panel request unsuccessful')
            return result
        except (OSError, ValueError, TypeError) as exc:
            # HTTP errors and URLs may contain secrets; do not expose their details.
            raise PanelError('panel request failed') from None

    def login(self, *, two_factor_code=None):
        self._logged_in = False
        self._cookies.clear()
        body = {'username': self._username, 'password': self._password}
        if two_factor_code is not None:
            if not isinstance(two_factor_code, str) or not two_factor_code:
                raise ValueError('invalid two-factor code')
            body['twoFactorCode'] = two_factor_code
        self._request('login', body)
        if not self._cookies:
            raise PanelError('panel login did not provide a session cookie')
        self._logged_in = True

    def clients(self):
        if not self._logged_in:
            raise PanelError('panel login required')
        rows = self._request('panel/api/clients/list').get('obj')
        if not isinstance(rows, list):
            raise PanelError('invalid client list')
        result, emails, identifiers = [], set(), set()
        try:
            for row in rows:
                email, sub_id = row['email'], row['subId']
                identifier = str(uuid.UUID(row['uuid']))
                traffic = row['traffic']
                enabled = row['enable'] and traffic['enable']
                expiry, total, up, down = row['expiryTime'], row['totalGB'], traffic['up'], traffic['down']
                if (not isinstance(email, str) or not email or len(email) > 128 or any(ord(ch) < 33 for ch in email)
                        or not isinstance(sub_id, str) or len(sub_id) > 256
                        or type(row['enable']) is not bool or type(traffic['enable']) is not bool
                        or any(type(n) is not int for n in (expiry, total, up, down)) or min(total, up, down) < 0
                        or email in emails or identifier in identifiers or uuid.UUID(identifier).int == 0):
                    raise ValueError('invalid client record')
                emails.add(email)
                identifiers.add(identifier)
                result.append(PanelClient(email, identifier, sub_id, enabled, expiry, total, up + down))
        except (KeyError, ValueError, TypeError, AttributeError):
            raise PanelError('invalid client list') from None
        return result
