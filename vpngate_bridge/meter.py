"""Persist cumulative per-user counters and fail closed on uncertain epochs."""
import re
import sqlite3
import time
import uuid


class MeterError(Exception):
    """Usage cannot safely be used for authorization."""


class CounterLedger:
    def __init__(self, path):
        self.path = path
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS meter_state (id INTEGER PRIMARY KEY CHECK(id=1), epoch TEXT NOT NULL, clean INTEGER NOT NULL, certain INTEGER NOT NULL, valid INTEGER NOT NULL, sampled INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS meter_users (name TEXT PRIMARY KEY, active INTEGER NOT NULL, raw_up INTEGER NOT NULL, raw_down INTEGER NOT NULL, total_up INTEGER NOT NULL, total_down INTEGER NOT NULL)')

    def begin(self, epoch, users):
        try:
            epoch = str(uuid.UUID(epoch))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('invalid meter epoch') from exc
        names = tuple(users)
        if (not names or any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', name) for name in names)
                or len(names) != len(set(names))):
            raise ValueError('invalid meter user list')
        error = None
        with sqlite3.connect(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            state = db.execute('SELECT epoch, clean, certain FROM meter_state WHERE id=1').fetchone()
            if state and not state[2]:
                error = 'meter requires reconciliation'
            elif state and state[0] == epoch and not state[1]:
                existing = {r[0] for r in db.execute('SELECT name FROM meter_users WHERE active=1')}
                if existing != set(names):
                    db.execute('UPDATE meter_state SET certain=0, valid=0 WHERE id=1')
                    error = 'meter user set changed during an epoch'
            elif state and state[0] == epoch:
                error = 'closed meter epoch cannot be reused'
            elif state and not state[1]:
                db.execute('UPDATE meter_state SET certain=0, valid=0 WHERE id=1')
                error = 'previous meter epoch ended unexpectedly'
            else:
                db.execute('UPDATE meter_users SET active=0')
                for name in names:
                    db.execute('INSERT OR IGNORE INTO meter_users VALUES (?, 0, 0, 0, 0, 0)', (name,))
                    db.execute('UPDATE meter_users SET active=1, raw_up=0, raw_down=0 WHERE name=?', (name,))
                db.execute('INSERT OR REPLACE INTO meter_state VALUES (1, ?, 0, 1, 0, 0)', (epoch,))
        if error:
            raise MeterError(error)

    def record(self, epoch, counters, *, now=None):
        if now is None:
            now = int(time.time())
        error, uncertain = None, False
        with sqlite3.connect(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            state = db.execute('SELECT epoch, clean, certain FROM meter_state WHERE id=1').fetchone()
            rows = db.execute('SELECT name, raw_up, raw_down, total_up, total_down FROM meter_users WHERE active=1').fetchall()
            if not state or state[1] or not state[2] or state[0] != epoch:
                error = 'invalid or uncertain meter epoch'
                uncertain = bool(state and not state[1] and state[0] != epoch)
            elif type(now) is not int or now < 0 or not isinstance(counters, dict) or set(counters) != {row[0] for row in rows}:
                error = 'incomplete meter snapshot'
            else:
                for name, raw_up, raw_down, total_up, total_down in rows:
                    values = counters[name]
                    if (not isinstance(values, (tuple, list)) or len(values) != 2
                            or any(type(value) is not int or value < 0 or value > 2**63-1 for value in values)):
                        error = 'invalid meter counter'
                        break
                    up, down = values
                    if up < raw_up or down < raw_down:
                        error, uncertain = 'meter counter decreased', True
                        break
                    if total_up + up - raw_up > 2**63-1 or total_down + down - raw_down > 2**63-1:
                        error, uncertain = 'meter counter overflow', True
                        break
            if error:
                if state:
                    db.execute('UPDATE meter_state SET valid=0, certain=CASE WHEN ? THEN 0 ELSE certain END WHERE id=1', (int(uncertain),))
            else:
                for name, raw_up, raw_down, _, _ in rows:
                    up, down = counters[name]
                    db.execute('UPDATE meter_users SET raw_up=?, raw_down=?, total_up=total_up+?, total_down=total_down+? WHERE name=?',
                               (up, down, up - raw_up, down - raw_down, name))
                db.execute('UPDATE meter_state SET valid=1, sampled=? WHERE id=1', (now,))
        if error:
            raise MeterError(error)

    def invalidate(self):
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE meter_state SET valid=0 WHERE id=1')

    def usage(self, name, *, now=None, max_age=30):
        if now is None:
            now = int(time.time())
        if type(now) is not int or type(max_age) is not int or max_age < 0:
            return None
        with sqlite3.connect(self.path) as db:
            db.execute('BEGIN')
            state = db.execute('SELECT clean, certain, valid, sampled FROM meter_state WHERE id=1').fetchone()
            if not state or state[:3] != (0, 1, 1) or not 0 <= now - state[3] <= max_age:
                return None
            row = db.execute('SELECT total_up, total_down FROM meter_users WHERE name=? AND active=1', (name,)).fetchone()
            return tuple(row) if row else None

    def close(self, epoch, counters, *, now=None, quiesced=False):
        if quiesced is not True:
            self.invalidate()
            raise MeterError('connections must be drained before closing an epoch')
        self.record(epoch, counters, now=now)
        with sqlite3.connect(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            cursor = db.execute('UPDATE meter_state SET clean=1, valid=0 WHERE id=1 AND epoch=? AND clean=0 AND certain=1 AND valid=1', (epoch,))
            if cursor.rowcount != 1:
                raise MeterError('meter epoch changed during close')
