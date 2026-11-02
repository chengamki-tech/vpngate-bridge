"""Probe an already isolated SOCKS gateway; never open an unvalidated tunnel."""
import ipaddress
import json
import math
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from .selection import Measurement, score


class ProbeError(Exception):
    """A candidate could not be verified and must not be advertised."""


def _curl(proxy, url, output, format_string):
    command = ['curl', '--disable', '--silent', '--show-error', '--fail', '--noproxy', '',
               '--socks5-hostname', proxy, '--proto', '=https', '--connect-timeout', '10',
               '--max-time', '10', '--max-filesize', '1048576', '--output', output,
               '--write-out', format_string, url]
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=11)
        return result.stdout.decode('ascii').strip()
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise ProbeError('gateway request failed') from exc


def probe(candidate, proxy, api_key):
    if not re.fullmatch(r'[A-Za-z0-9.-]+:[0-9]{1,5}', proxy) or not 1 <= int(proxy.rsplit(':', 1)[1]) <= 65535:
        raise ValueError('invalid SOCKS address')
    ips, latencies = [], []
    for _ in range(3):
        try:
            # The first line is curl's body; the last is its end-to-end time.
            body = _curl(proxy, 'https://api.ipify.org/', '-', '\n%{time_total}')
            address, elapsed = body.splitlines()
            address = str(ipaddress.ip_address(address))
            seconds = float(elapsed)
            if not math.isfinite(seconds) or not 0 <= seconds <= 10:
                raise ValueError('invalid time')
            ips.append(address)
            latencies.append(seconds * 1000)
        except (ValueError, TypeError) as exc:
            raise ProbeError('invalid exit probe response') from exc
    if len(set(ips)) != 1:
        raise ProbeError('exit IP changed during probe')
    if api_key:
        query = urllib.parse.urlencode({'q': ips[0], 'key': api_key})
        url = 'https://api.ipapi.is/?' + query
    else:
        url = 'https://whatsmyip.now/api/v1/lookup/' + ips[0]
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'vpngate-bridge/0.1'})
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = response.read(65537)
        if len(payload) > 65536:
            raise ValueError('classification response too large')
        data = json.loads(payload)
        if api_key:
            country = data['location']['country_code']
            hosting = data['is_datacenter']
        else:
            if data.get('error'):
                raise ValueError('classification unavailable')
            country = data['country_code']
            hosting = data['is_hosting']
        if data['ip'] != ips[0] or type(hosting) is not bool or not isinstance(country, str):
            raise ValueError('incomplete classification')
    except urllib.error.HTTPError as exc:
        raise ProbeError(f'exit classification HTTP {exc.code}') from None
    except urllib.error.URLError:
        raise ProbeError('exit classification network error') from None
    except (OSError, ValueError, TypeError, KeyError):
        # Do not chain exceptions: URL errors can contain the API key.
        raise ProbeError('exit classification invalid response') from None
    preliminary = Measurement(candidate.country, country, ips[0], hosting, tuple(latencies), 0, candidate.uptime_ms)
    if score(preliminary) is None:
        raise ProbeError('exit did not meet country, hosting, latency or address requirements')
    try:
        speed = float(_curl(proxy, 'https://speed.cloudflare.com/__down?bytes=1000000', '/dev/null', '%{speed_download}')) * 8
        if not math.isfinite(speed) or speed <= 0:
            raise ValueError('invalid speed')
    except (ValueError, TypeError) as exc:
        raise ProbeError('speed test failed') from exc
    return Measurement(candidate.country, country, ips[0], hosting, tuple(latencies), speed, candidate.uptime_ms)
