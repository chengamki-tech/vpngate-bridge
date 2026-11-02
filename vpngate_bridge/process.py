"""Identify a running Docker container incarnation for meter coordination."""
import json
import re
import subprocess
import uuid

from .meter import MeterError


def docker_epoch(container_id):
    if not isinstance(container_id, str) or not re.fullmatch(r'[0-9a-f]{64}', container_id):
        raise ValueError('full Docker container ID required')
    try:
        result = subprocess.run(['docker', 'inspect', '--format', '{{json .State}}', container_id],
                                check=True, capture_output=True, text=True, timeout=5)
        state = json.loads(result.stdout)
        started = state['StartedAt']
        if (state.get('Running') is not True or state.get('Paused') is not False
                or state.get('Restarting') is not False or type(state.get('Pid')) is not int or state['Pid'] <= 0
                or not isinstance(started, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z', started)):
            raise ValueError('container is not verifiably running')
        return str(uuid.uuid5(uuid.NAMESPACE_URL, 'docker:' + container_id + ':' + started))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise MeterError('cannot verify sing-box container incarnation') from None
