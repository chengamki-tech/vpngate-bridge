"""Authorize a fixed client roster before starting its leased sing-box container."""
import hashlib
import hmac
import ipaddress
import json
import os
import re
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
from .lease import renew
from .meter import MeterError
from .process import docker_epoch
from .subscription_http import client_token
from .sync import sync_bridge_usage


@dataclass
class BridgeRuntime:
    container_id: str
    config: dict
    coordinator: LeaseCoordinator


@contextmanager
def open_bridge(panel, ledger, source_guid, countries, secret, certificate, key, state_dir,
                proto_path, *, image='vpngate-sing-box', listen='0.0.0.0', stats_port=10085):
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
    attempted, controller = False, None
    with tempfile.TemporaryDirectory(prefix='bridge-', dir=paths[2]) as directory:
        root = Path(directory)
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
        # No bridge exists during this zero-raw-counter epoch, so it can be finalized safely.
        bootstrap = str(uuid.uuid4())
        zeros = {name: (0, 0) for name in identities}
        ledger.begin(bootstrap, identities)
        try:
            ledger.record(bootstrap, zeros)
            eligible = sync_bridge_usage(panel, ledger, source_guid, identities, now=int(time.time()))
            if {client.email: (client.uuid, client.sub_id) for client in eligible} != identities:
                raise AccessRevoked('panel client state changed before bridge startup')
        finally:
            ledger.close(bootstrap, zeros, quiesced=True)
        try:
            # Persist intent before Docker can expose listeners, including partial run failures.
            ledger.begin(run_id, identities)
            attempted = True
            renew(lease_path, run_id, duration=10)
            container = _docker('run', '-d', '--name', name, '--label', 'org.vpngate-bridge.bridge=' + name,
                                '--network', 'host', *isolation, '--cpus', '1', '--memory', '256m', '--pids-limit', '128',
                                '--mount', f'type=bind,src={root},dst=/run/vgb,readonly',
                                '-e', 'BRIDGE_RUN_ID=' + run_id, *mounts,
                                image, 'run', '-c', '/config.json', timeout=30)
            incarnation = docker_epoch(container)

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
            lease_path.unlink(missing_ok=True)
            if attempted:
                ledger.invalidate()
                _remove_owned(name, 'org.vpngate-bridge.bridge')
