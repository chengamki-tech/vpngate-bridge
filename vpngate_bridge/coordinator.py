"""Renew a fixed bridge configuration only after fresh metering and authorization."""
import threading
import time
from pathlib import Path

from .collector import collect
from .lease import renew
from .meter import MeterError
from .sync import sync_bridge_usage


class AccessRevoked(Exception):
    """The running configuration must stop before users can be reconciled."""


class LeaseCoordinator:
    def __init__(self, panel, ledger, source_guid, identities, meter_epoch, process_epoch,
                 endpoint, proto_path, lease_path, run_id):
        if not identities or any(not name or not isinstance(identity, tuple) or len(identity) != 2
                                 or not all(isinstance(value, str) and value for value in identity)
                                 for name, identity in identities.items()):
            raise ValueError('fixed runtime client identities required')
        self.panel, self.ledger, self.source_guid = panel, ledger, source_guid
        self.identities = dict(identities)
        self.meter_epoch, self.process_epoch = meter_epoch, process_epoch
        self.endpoint, self.proto_path = endpoint, proto_path
        self.lease_path, self.run_id = Path(lease_path), run_id
        self._lock = threading.Lock()

    def revoke(self):
        self.lease_path.unlink(missing_ok=True)
        self.ledger.invalidate()

    def tick(self, *, now=None):
        if now is None:
            now = int(time.time())
        with self._lock:
            try:
                collect(self.ledger, self.meter_epoch, self.endpoint, self.proto_path,
                        self.identities, self.process_epoch, now=now)
                eligible = sync_bridge_usage(self.panel, self.ledger, self.source_guid, self.identities, now=now)
                actual = {client.email: (client.uuid, client.sub_id) for client in eligible}
                if len(actual) != len(eligible) or actual != self.identities:
                    raise AccessRevoked('runtime client set or identity changed')
                if self.process_epoch() != self.meter_epoch:
                    raise MeterError('bridge process changed before lease renewal')
                renew(self.lease_path, self.run_id, duration=10)
                return eligible
            except BaseException:
                self.revoke()
                raise

    def run(self, stop_event):
        try:
            while not stop_event.is_set():
                started = time.monotonic()
                self.tick()
                stop_event.wait(max(0, 5 - (time.monotonic() - started)))
        finally:
            self.revoke()
