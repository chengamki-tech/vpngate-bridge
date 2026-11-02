"""Detect consecutive gateway failures and retry same-country replacement."""
import ipaddress
import logging
import sqlite3
import threading
import time

from .fetcher import fetch
from .probe import ProbeError, _curl
from .scanner import scan


def check_route(route):
    try:
        body = _curl(f'{route.socks_host}:{route.socks_port}', 'https://api.ipify.org/', '-', '\n%{time_total}')
        address, elapsed = body.splitlines()
        duration = float(elapsed)
        return str(ipaddress.ip_address(address)) == route.exit_ip and 0 <= duration <= 10
    except (ProbeError, ValueError, TypeError):
        return False


class Healer:
    def __init__(self, pool, blacklist, state_path, *, fetcher=fetch, check=check_route):
        self.pool, self.blacklist, self.state_path = pool, blacklist, state_path
        self.fetcher, self.check = fetcher, check
        self._lock = threading.Lock()
        with sqlite3.connect(self.state_path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS health (country TEXT PRIMARY KEY, server TEXT NOT NULL, exit_ip TEXT NOT NULL, failures INTEGER NOT NULL, pending INTEGER NOT NULL)')

    def _observe(self, route, healthy):
        with sqlite3.connect(self.state_path) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT server, exit_ip, failures, pending FROM health WHERE country = ?', (route.country,)).fetchone()
            if row is None or row[:2] != (route.server_ip, route.exit_ip):
                failures, pending = 0, 0
            else:
                failures, pending = row[2:]
            if not pending:
                failures = 0 if healthy else failures + 1
                pending = int(failures >= 2)
            db.execute('INSERT OR REPLACE INTO health VALUES (?, ?, ?, ?, ?)',
                       (route.country, route.server_ip, route.exit_ip, failures, pending))

    def _pending(self):
        with sqlite3.connect(self.state_path) as db:
            return db.execute('SELECT country, server, exit_ip FROM health WHERE pending = 1 ORDER BY country').fetchall()

    def _reset(self, route):
        with sqlite3.connect(self.state_path) as db:
            db.execute('INSERT OR REPLACE INTO health VALUES (?, ?, ?, 0, 0)', (route.country, route.server_ip, route.exit_ip))

    def tick(self, *, now=None):
        if now is None:
            now = time.time()
        with self._lock:
            for route in self.pool.routes().values():
                self._observe(route, self.check(route))
            candidates = None
            for country, server, exit_ip in self._pending():
                current = self.pool.routes().get(country)
                if current is not None:
                    if (current.server_ip, current.exit_ip) != (server, exit_ip):
                        continue
                    self.blacklist.add(server, 'gateway failed twice', now)
                    self.blacklist.add(exit_ip, 'gateway failed twice', now)
                    self.pool.remove(country, expected=current)
                if candidates is None:
                    candidates = self.fetcher()
                blocked = self.blacklist.active(now)
                other_exits = [route.exit_ip for route in self.pool.routes().values()]
                selected = scan({country: candidates.get(country, [])}, self.pool.gateways, self.pool.api_key,
                                blocked, 1, exclude_exits=other_exits)
                if country in selected:
                    candidate, _ = selected[country]
                    route = self.pool.replace(candidate, blocked, expected_absent=True)
                    self._reset(route)

    def run(self, stop_event):
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                self.tick()
            except Exception:
                logging.exception('gateway health cycle failed; it will be retried')
            stop_event.wait(max(0, 600 - (time.monotonic() - started)))
