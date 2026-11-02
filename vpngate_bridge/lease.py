"""Fail-closed Linux process supervision using short monotonic-clock leases."""
import json
import math
import os
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

MAX_LEASE = 30


def renew(path, run_id, *, duration=10):
    run_id = str(uuid.UUID(run_id))
    if not isinstance(duration, (int, float)) or not math.isfinite(duration) or not 0 < duration <= MAX_LEASE:
        raise ValueError('lease duration must be between 0 and 30 seconds')
    path = Path(path)
    filename = None
    try:
        with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='.lease-', delete=False) as output:
            filename = output.name
            json.dump({'run_id': run_id, 'deadline': time.monotonic() + duration}, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(filename, path)
    finally:
        if filename and os.path.exists(filename): os.unlink(filename)


def valid(path, run_id):
    try:
        with open(path, 'rb') as source:
            data = source.read(4097)
        if len(data) > 4096:
            return False
        value = json.loads(data)
        remaining = value['deadline'] - time.monotonic()
        return (set(value) == {'run_id', 'deadline'} and value['run_id'] == str(uuid.UUID(run_id))
                and math.isfinite(remaining) and 0 < remaining <= MAX_LEASE)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False


def supervise(path, run_id, command):
    if not valid(path, run_id):
        raise RuntimeError('valid bridge lease required before process start')
    process = subprocess.Popen(command, start_new_session=True)
    try:
        while process.poll() is None:
            if not valid(path, run_id):
                return 1
            time.sleep(.1)
        return process.returncode
    finally:
        # Kill the process group so descendants cannot retain proxy listeners.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
