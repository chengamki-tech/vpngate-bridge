"""Persist country listener ports so replacements retain subscription endpoints."""
import re
import sqlite3


class PortRegistry:
    def __init__(self, path, first, last, reserved):
        if type(first) is not int or type(last) is not int or not 1 <= first <= last <= 65535:
            raise ValueError('invalid port range')
        self.path, self.first, self.last, self.reserved = path, first, last, set(reserved)
        if any(type(p) is not int or not 1 <= p <= 65535 for p in self.reserved):
            raise ValueError('invalid reserved port')
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS ports (country TEXT PRIMARY KEY, vless INTEGER NOT NULL UNIQUE, hy2 INTEGER NOT NULL UNIQUE)')

    def assign(self, country):
        if not isinstance(country, str) or not re.fullmatch(r'[A-Z]{2}', country):
            raise ValueError('invalid country code')
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT vless, hy2 FROM ports WHERE country = ?', (country,)).fetchone()
            if existing:
                if any(p in self.reserved or not self.first <= p <= self.last for p in existing):
                    raise ValueError('existing country ports conflict with configured range or reservations')
                return existing
            used = set(self.reserved)
            for vless, hy2 in db.execute('SELECT vless, hy2 FROM ports'):
                used.update((vless, hy2))
            free = (p for p in range(self.first, self.last + 1) if p not in used)
            pair = (next(free, None), next(free, None))
            if None in pair:
                raise RuntimeError('not enough unreserved listener ports')
            db.execute('INSERT INTO ports VALUES (?, ?, ?)', (country, *pair))
            return pair
