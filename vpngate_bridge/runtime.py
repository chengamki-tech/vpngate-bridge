"""Authorize a fixed client roster before starting its leased sing-box container."""
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .bridge import Client, build_config
from .coordinator import AccessRevoked, LeaseCoordinator
from .docker_gateway import _docker, _remove_owned
from .final_stats import read_final
from .lease import renew
from .meter import MeterError
from .process import docker_epoch
from .subscription_http import client_token
from .sync import sync_bridge_usage, sync_final_usage


@dataclass
class BridgeRuntime:
    container_id: str
    config: dict
    coordinator: LeaseCoordinator


def _write_json(path, value):
    filename = None
    try:
        with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='.recovery-', delete=False) as output:
            filename = output.name
            json.dump(value, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(filename, path)
    finally:
        if filename and os.path.exists(filename):
            os.unlink(filename)


def _recovery_manifest(state_dir, run_id, container, source_guid, identities, *, status, incarnation=None):
    value = {
        'version': 1,
        'run_id': run_id,
        'container': container,
        'source_guid': source_guid,
        'identities': {name: list(identity) for name, identity in identities.items()},
        'status': status,
    }
    if incarnation is not None:
        value['incarnation'] = incarnation
    return value


def _cleanup_run(run_dir, manifest):
    if run_dir.exists():
        shutil.rmtree(run_dir)
    manifest.unlink(missing_ok=True)


def _read_manifest(path, state_dir):
    try:
        payload = path.read_bytes()
        if len(payload) > 256 * 1024:
            raise ValueError('oversized recovery manifest')
        value = json.loads(payload)
        run_id = str(uuid.UUID(value['run_id']))
        container = value['container']
        source = str(uuid.UUID(value['source_guid']))
        identities = value['identities']
        status = value['status']
        incarnation = value.get('incarnation')
        if (value['version'] != 1 or run_id != value['run_id'] or source != value['source_guid']
                or status not in ('preflight', 'running')
                or not isinstance(container, str)
                or not re.fullmatch(r'vgb-bridge-[0-9a-f]{32}', container)
                or not isinstance(identities, dict) or not identities
                or any(not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', name)
                       or not isinstance(identity, list) or len(identity) != 2
                       or not all(isinstance(item, str) and item for item in identity)
                       for name, identity in identities.items())):
            raise ValueError('invalid recovery manifest')
        if status == 'running' and (not isinstance(incarnation, str)
                                    or str(uuid.UUID(incarnation)) != incarnation):
            raise ValueError('missing process incarnation')
        run_dir = state_dir / ('run-' + run_id)
        if run_dir.is_symlink() or not run_dir.is_dir():
            raise ValueError('missing recovery directory')
        return {
            'run_id': run_id, 'container': container, 'source_guid': source,
            'identities': {name: tuple(identity) for name, identity in identities.items()},
            'status': status, 'incarnation': incarnation, 'run_dir': run_dir,
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
        raise MeterError('bridge recovery manifest is missing or invalid') from None


def recover_bridges(panel, ledger, state_dir, proto_path):
    """Finish bridge generations that outlived a killed controller."""
    state_dir = Path(state_dir).resolve(strict=True)
    if state_dir.is_symlink() or state_dir.stat().st_mode & 0o077:
        raise MeterError('private recovery state directory required')
    Path(proto_path).resolve(strict=True)
    for manifest_path in sorted(state_dir.glob('recovery-*.json')):
        value = _read_manifest(manifest_path, state_dir)
        if value['status'] != 'running':
            raise MeterError('bridge started without a verified process incarnation')
        name, run_id, run_dir = value['container'], value['run_id'], value['run_dir']
        ids = _docker('ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}')
        if ids:
            matches = ids.splitlines()
            if len(matches) != 1:
                raise MeterError('ambiguous bridge recovery container')
            container = matches[0].strip()
            try:
                stopped = docker_epoch(container, stopped=True)
            except MeterError:
                (run_dir / 'lease.json').unlink(missing_ok=True)
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    try:
                        stopped = docker_epoch(container, stopped=True)
                        break
                    except MeterError:
                        time.sleep(.2)
                else:
                    _docker('stop', '--time', '5', name, timeout=10)
                    stopped = docker_epoch(container, stopped=True)
            if stopped != value['incarnation']:
                raise MeterError('bridge recovery incarnation changed')
        counters = read_final(run_dir / 'final' / 'counters.json', run_id, value['identities'])
        try:
            ledger.closed_totals(run_id)
        except MeterError:
            ledger.close(run_id, counters, quiesced=True)
        sync_final_usage(panel, ledger, value['source_guid'], run_id, value['identities'])
        _remove_owned(name, 'org.vpngate-bridge.bridge')
        _cleanup_run(run_dir, manifest_path)


@contextmanager
def open_bridge(panel, ledger, source_guid, countries, secret, certificate, key, state_dir,
                proto_path, *, image='vpngate-sing-box', listen='0.0.0.0', stats_port=10085, stop_event=None):
    """Public admission needs verified panel state; uncertain prior epochs never restart."""
    address = ipaddress.ip_address(listen)
    if address.version != 4 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@-]*', image):
        raise ValueError('IPv4 listen address and valid bridge image required')
    paths = [Path(path).resolve(strict=True) for path in (certificate, key, state_dir, proto_path)]
    if any(',' in str(path) for path in paths) or not paths[2].is_dir():
        raise ValueError('existing state directory and comma-free mount paths required')
    clients = [client for client in panel.clients()
               if client.authorized(now_ms=int(time.time() * 1000), unreported_bridge_bytes=0)]
    identities = {client.email: (client.uuid, client.sub_id) for client in clients}
    if not identities or len(identities) != len(clients):
        raise AccessRevoked('unique authorized panel clients required')
    credentials = [Client(client.email, client.uuid, hmac.new(
        secret, b'hysteria2\0' + client_token(secret, client).encode('ascii'), hashlib.sha256).hexdigest())
        for client in clients]
    config = build_config(countries, credentials, '/cert.pem', '/key.pem', stats_port=stats_port)
    for inbound in config['inbounds']:
        inbound['listen'] = str(address)
    name = 'vgb-bridge-' + uuid.uuid4().hex
    run_id = str(uuid.uuid4())
    attempted, container, incarnation = False, None, None
    root = paths[2] / ('run-' + run_id)
    root.mkdir(mode=0o700)
    manifest_path = paths[2] / ('recovery-' + run_id + '.json')
    manifest = _recovery_manifest(paths[2], run_id, name, source_guid, identities, status='preflight')
    try:
        _write_json(manifest_path, manifest)
        final_dir = root / 'final'
        final_dir.mkdir(mode=0o700)
        config_path, lease_path = root / 'config.json', root / 'lease.json'
        descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(config, output)
        mounts = ['--mount', f'type=bind,src={config_path},dst=/config.json,readonly',
                  '--mount', f'type=bind,src={paths[0]},dst=/cert.pem,readonly',
                  '--mount', f'type=bind,src={paths[1]},dst=/key.pem,readonly']
        isolation = ['--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL',
                     '--security-opt=no-new-privileges', '--read-only',
                     '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m']
        _docker('run', '--rm', *isolation, *mounts, image, 'check', '-c', '/config.json', timeout=30)
        if stop_event is not None and stop_event.is_set():
            raise InterruptedError('bridge startup canceled')
        # No bridge exists during this zero-raw-counter epoch, so it can be finalized safely.
        bootstrap = str(uuid.uuid4())
        zeros = {name: (0, 0) for name in identities}
        ledger.begin(bootstrap, identities)
        try:
            if stop_event is not None and stop_event.is_set():
                raise InterruptedError('bridge startup canceled')
            ledger.record(bootstrap, zeros)
            eligible = sync_bridge_usage(panel, ledger, source_guid, identities, now=int(time.time()))
            if {client.email: (client.uuid, client.sub_id) for client in eligible} != identities:
                raise AccessRevoked('panel client state changed before bridge startup')
        finally:
            ledger.close(bootstrap, zeros, quiesced=True)
        # Persist intent before Docker can expose listeners, including partial run failures.
        if stop_event is not None and stop_event.is_set():
            raise InterruptedError('bridge startup canceled')
        ledger.begin(run_id, identities)
        attempted = True
        renew(lease_path, run_id, duration=10)
        container = _docker('run', '-d', '--name', name, '--label', 'org.vpngate-bridge.bridge=' + name,
                            '--network', 'host', *isolation, '--cpus', '1', '--memory', '256m', '--pids-limit', '128',
                            '--mount', f'type=bind,src={root},dst=/run/vgb,readonly',
                            '--mount', f'type=bind,src={final_dir},dst=/run/vgb-final',
                            '-e', 'VGB_FINAL_STATS=/run/vgb-final/counters.json',
                            '-e', 'BRIDGE_RUN_ID=' + run_id, *mounts,
                            image, 'run', '-c', '/config.json', timeout=30)
        if stop_event is not None and stop_event.is_set():
            raise InterruptedError('bridge startup canceled')
        incarnation = docker_epoch(container)
        manifest = _recovery_manifest(paths[2], run_id, name, source_guid, identities,
                                      status='running', incarnation=incarnation)
        _write_json(manifest_path, manifest)

        def process_epoch():
            if docker_epoch(container) != incarnation:
                raise MeterError('bridge container restarted')
            return run_id

        controller = LeaseCoordinator(panel, ledger, source_guid, identities, run_id, process_epoch,
                                      f'127.0.0.1:{stats_port}', paths[3], lease_path, run_id)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', stats_port), timeout=.2):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise MeterError('bridge stats did not become ready')
        controller.tick()
        yield BridgeRuntime(container, config, controller)
    finally:
        lease_path = root / 'lease.json'
        lease_path.unlink(missing_ok=True)
        recoverable = not attempted
        if attempted:
            ledger.invalidate()
            finalized = False
            try:
                if container is not None and incarnation is not None:
                    _docker('stop', '--time', '5', container, timeout=10)
                    if docker_epoch(container, stopped=True) != incarnation:
                        raise MeterError('bridge incarnation changed during shutdown')
                    counters = read_final(final_dir / 'counters.json', run_id, identities)
                    ledger.close(run_id, counters, quiesced=True)
                    finalized = True
                    sync_final_usage(panel, ledger, source_guid, run_id, identities)
                    recoverable = True
            except Exception as exc:
                logging.warning('bridge shutdown accounting: %s; final counters %s',
                                type(exc).__name__, 'preserved' if finalized else 'unconfirmed')
            finally:
                _remove_owned(name, 'org.vpngate-bridge.bridge')
        if recoverable:
            _cleanup_run(root, manifest_path)
