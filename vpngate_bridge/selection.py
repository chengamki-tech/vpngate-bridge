"""Rank measured exits and retain failed IPv4 /24s between scans."""
import ipaddress
import math
import sqlite3
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class Measurement:
    expected_country: str
    country: str
    exit_ip: str
    hosting: Optional[bool]
    latencies_ms: Tuple[float, ...]
    speed_bps: float
    uptime_ms: int


def score(m: Measurement) -> Optional[float]:
    try:
        address = ipaddress.ip_address(m.exit_ip)
        valid_numbers = all(math.isfinite(x) for x in (*m.latencies_ms, m.speed_bps, m.uptime_ms))
    except (ValueError, TypeError, OverflowError):
        return None
    if (not address.is_global or m.country != m.expected_country or m.hosting is not False
            or len(m.latencies_ms) != 3 or not valid_numbers or m.speed_bps < 0 or m.uptime_ms < 0
            or any(x < 0 or x > 10_000 for x in m.latencies_ms)):
        return None
    latency = max(0.0, 1.0 - sum(m.latencies_ms) / 3 / 1000)
    speed = min(m.speed_bps / 100_000_000, 1.0)
    uptime = min(m.uptime_ms / 604_800_000, 1.0)
    # All three probes must pass; the stability component is consequently 1.
    return .30 * latency + .30 * speed + .25 + .15 * uptime


def choose(measurements, blocked):
    networks = tuple(ipaddress.ip_network(n) for n in blocked)
    ranked = []
    for m in measurements:
        value = score(m)
        if value is not None and not any(ipaddress.ip_address(m.exit_ip) in net for net in networks):
            ranked.append((value, m))
    ranked.sort(key=lambda item: (-item[0], item[1].expected_country, item[1].exit_ip))
    selected, exits = {}, set()
    for _, m in ranked:
        if m.expected_country not in selected and m.exit_ip not in exits:
            selected[m.expected_country] = m
            exits.add(m.exit_ip)
    return selected


class Blacklist:
    def __init__(self, path):
        self.path = path
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS blacklist (network TEXT PRIMARY KEY, reason TEXT NOT NULL, expires INTEGER NOT NULL)')

    def add(self, address, reason, now, ttl=86400):
        ip = ipaddress.ip_address(address)
        if not ip.is_global or not reason or ttl <= 0:
            raise ValueError('invalid blacklist entry')
        network = str(ipaddress.ip_network(f'{ip}/{24 if ip.version == 4 else 64}', strict=False))
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT OR REPLACE INTO blacklist VALUES (?, ?, ?)', (network, reason, int(now + ttl)))

    def active(self, now):
        with sqlite3.connect(self.path) as db:
            db.execute('DELETE FROM blacklist WHERE expires <= ?', (now,))
            return [row[0] for row in db.execute('SELECT network FROM blacklist ORDER BY network')]
