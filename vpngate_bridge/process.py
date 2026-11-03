"""Identify a running Docker container incarnation for meter coordination."""
import json
import re
import subprocess
import uuid

from .meter import MeterError


def docker_epoch(container_id, *, stopped=False):
    if not isinstance(container_id, str) or not re.fullmatch(r'[0-9a-f]{64}', container_id):
        raise ValueError('full Docker container ID required')
    try:
        result = subprocess.run(['docker', 'inspect', '--format', '{{json .State}}', container_id],
                                check=True, capture_output=True, text=True, timeout=5)
        state = json.loads(result.stdout)
        started = state['StartedAt']
        if (state.get('Running') is not (not stopped) or state.get('Paused') is not False
                or state.get('Restarting') is not False or type(state.get('Pid')) is not int
                or (state['Pid'] != 0 if stopped else state['Pid'] <= 0)
                or not isinstance(started, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z', started)):
            raise ValueError('container is not in the expected process state')
        if stopped and (state.get('OOMKilled') is not False or state.get('Dead') is not False
                        or type(state.get('ExitCode')) is not int or state['ExitCode'] not in (0, 1, 143)):
            raise ValueError('container did not stop through its supervisor')
        return str(uuid.uuid5(uuid.NAMESPACE_URL, 'docker:' + container_id + ':' + started))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise MeterError('cannot verify sing-box container incarnation') from None
