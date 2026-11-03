"""Validate the bounded final snapshot emitted after the bridge freezes counted I/O."""
import json
import re
import uuid

from .meter import MeterError


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate snapshot key')
        result[key] = value
    return result


def read_final(path, run_id, users):
    names = tuple(users)
    try:
        if (str(uuid.UUID(run_id)) != run_id or not names or len(set(names)) != len(names)
                or any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', name) for name in names)):
            raise ValueError('invalid expected snapshot identity')
        limit = 1024 + 256 * len(names)
        with open(path, 'rb') as source:
            payload = source.read(limit + 1)
        if len(payload) > limit:
            raise ValueError('oversized final snapshot')
        data = json.loads(payload, object_pairs_hook=_unique_object)
        if (not isinstance(data, dict) or set(data) != {'version', 'run_id', 'counters'}
                or type(data['version']) is not int or data['version'] != 1 or data['run_id'] != run_id
                or not isinstance(data['counters'], dict) or set(data['counters']) != set(names)):
            raise ValueError('final snapshot identity or roster mismatch')
        for values in data['counters'].values():
            if (not isinstance(values, list) or len(values) != 2
                    or any(type(value) is not int or not 0 <= value <= 2**63 - 1 for value in values)):
                raise ValueError('invalid final counter')
        return {name: tuple(values) for name, values in data['counters'].items()}
    except (OSError, ValueError, TypeError, AttributeError):
        raise MeterError('final bridge counter snapshot is missing or invalid') from None
