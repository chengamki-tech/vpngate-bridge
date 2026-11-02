"""Read non-resetting sing-box counters through grpcurl on loopback."""
import ipaddress
import json
import subprocess
from pathlib import Path

from .meter import MeterError


def read_counters(endpoint, proto_path, users):
    try:
        host, port = endpoint.rsplit(':', 1)
        if not ipaddress.ip_address(host).is_loopback or not 1 <= int(port) <= 65535:
            raise ValueError('invalid endpoint')
    except (ValueError, AttributeError) as exc:
        raise ValueError('stats endpoint must be loopback IPv4') from exc
    path = Path(proto_path).resolve(strict=True)
    names = tuple(users)
    if len(names) != len(set(names)) or not names:
        raise ValueError('unique configured users required')
    result = {name: [0, 0] for name in names}
    command = ['grpcurl', '-plaintext', '-max-time', '5', '-import-path', str(path.parent), '-proto', path.name,
               '-d', '{"pattern":"user>>>","reset":false}', endpoint, 'experimental.v2rayapi.StatsService/QueryStats']
    try:
        response = subprocess.run(command, check=True, capture_output=True, text=True, timeout=6)
        payload = json.loads(response.stdout)
        if not isinstance(payload, dict) or set(payload) - {'stat'}:
            raise ValueError('invalid snapshot')
        rows = payload.get('stat', [])
        if not isinstance(rows, list):
            raise ValueError('invalid stats')
        seen = set()
        for row in rows:
            name = row['name']
            parts = name.split('>>>')
            if len(parts) != 4 or parts[0] != 'user' or parts[2] != 'traffic' or parts[3] not in ('uplink', 'downlink'):
                raise ValueError('unexpected counter')
            if parts[1] not in result or name in seen:
                raise ValueError('unknown or duplicate user counter')
            raw = row.get('value', '0')
            if isinstance(raw, bool) or not isinstance(raw, (int, str)) or not str(raw).isascii() or not str(raw).isdigit():
                raise ValueError('invalid counter value')
            value = int(raw)
            if value > 2**63 - 1:
                raise ValueError('counter overflow')
            result[parts[1]][0 if parts[3] == 'uplink' else 1] = value
            seen.add(name)
        return {name: tuple(values) for name, values in result.items()}
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError):
        raise MeterError('sing-box stats collection failed') from None


def collect(ledger, epoch, endpoint, proto_path, users, process_epoch, *, now=None):
    try:
        if process_epoch() != epoch:
            raise MeterError('sing-box process epoch changed')
        counters = read_counters(endpoint, proto_path, users)
        if process_epoch() != epoch:
            raise MeterError('sing-box process epoch changed during collection')
        ledger.record(epoch, counters, now=now)
    except BaseException:
        ledger.invalidate()
        raise
