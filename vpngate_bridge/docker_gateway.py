"""Start disposable OpenVPN gateways on a Linux Docker bridge network."""
import ipaddress
import math
import os
import re
import socket
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .openvpn import safe_config
from .probe import ProbeError


class GatewayError(Exception):
    """Docker infrastructure failed; the scan must stop."""


def _docker(*args, timeout=20):
    try:
        result = subprocess.run(['docker', *args], check=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise GatewayError('Docker command failed: ' + args[0]) from exc


def _remove_owned(name, label='org.vpngate-bridge.probe'):
    try:
        owner = _docker('inspect', '--format', '{{index .Config.Labels "' + label + '"}}', name)
    except GatewayError as exc:
        cause = exc.__cause__
        if isinstance(cause, subprocess.CalledProcessError) and ('No such object' in cause.stderr or 'No such container' in cause.stderr):
            return
        raise
    if owner != name:
        raise GatewayError('refusing to remove container without matching ownership label')
    _docker('rm', '-f', name, timeout=20)


class DockerGateway:
    def __init__(self, network, image='vpngate-gateway', cpus=0.5, memory_mb=128):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', network):
            raise ValueError('invalid Docker network')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@-]*', image):
            raise ValueError('invalid Docker image')
        if not isinstance(cpus, (int, float)) or not math.isfinite(cpus) or not 0 < cpus <= 64:
            raise ValueError('invalid CPU limit')
        if type(memory_mb) is not int or not 64 <= memory_mb <= 65536:
            raise ValueError('invalid memory limit')
        if _docker('network', 'inspect', '--format', '{{.Driver}}', network) != 'bridge':
            raise GatewayError('a Docker bridge network is required')
        self.network, self.image, self.cpus, self.memory_mb = network, image, cpus, memory_mb

    @contextmanager
    def open(self, candidate):
        try:
            safe_config(candidate.config, candidate.ip)
        except ValueError as exc:
            raise ProbeError('invalid OpenVPN candidate') from exc
        name = 'vgb-probe-' + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix='vgb-') as directory:
            path = Path(directory) / 'client.ovpn'
            path.write_text(candidate.config, encoding='utf-8')
            os.chmod(path, 0o600)
            attempted = False
            try:
                attempted = True
                _docker('run', '-d', '--name', name, '--label', 'org.vpngate-bridge.probe=' + name,
                        '--network', self.network, '--cap-add=NET_ADMIN', '--device=/dev/net/tun',
                        '--cpus', str(self.cpus), '--memory', f'{self.memory_mb}m', '--pids-limit', '128',
                        '--mount', f'type=bind,src={path},dst=/config/client.ovpn,readonly',
                        '-e', 'VPN_SERVER_IP=' + candidate.ip, self.image, timeout=30)
                template = '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
                try:
                    ip = ipaddress.ip_address(_docker('inspect', '--format', template, name))
                except ValueError as exc:
                    raise GatewayError('gateway did not receive an IP address') from exc
                if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise GatewayError('gateway address is not a private IPv4 address')
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection((str(ip), 1080), timeout=.3):
                            break
                    except OSError:
                        time.sleep(.2)
                else:
                    raise ProbeError('gateway did not become ready within 10 seconds')
                yield f'{ip}:1080'
            finally:
                if attempted:
                    _remove_owned(name)
