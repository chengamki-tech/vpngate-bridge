"""Synchronize bridge-only usage through 3x-ui's absolute global overlay."""
from .meter import MeterError
from .panel import PanelError


def sync_bridge_usage(panel, ledger, source_guid, emails, *, now):
    names = tuple(emails)
    if not names or len(set(names)) != len(names) or type(now) is not int:
        raise ValueError('unique managed clients and integer timestamp required')
    try:
        inbounds = panel._request('panel/api/inbounds/list').get('obj')
        if not isinstance(inbounds, list) or any(not isinstance(row, dict) or row.get('enable') is not False for row in inbounds):
            raise PanelError('bridge-only accounting requires all panel inbounds disabled')
        before = {client.email: client for client in panel.clients()}
        totals = {}
        for name in names:
            if name not in before:
                raise PanelError('managed panel client is missing')
            usage = ledger.usage(name, now=now)
            if usage is None:
                raise MeterError('fresh certain bridge usage required')
            totals[name] = usage
        panel.push_global_totals(source_guid, totals)
        after = {client.email: client for client in panel.clients()}
        authorized = []
        for name in names:
            client = after.get(name)
            if (client is None or client.uuid != before[name].uuid or client.sub_id != before[name].sub_id
                    or client.panel_bytes != sum(totals[name])):
                raise PanelError('panel client or traffic changed during synchronization')
            if client.authorized(now_ms=now * 1000, unreported_bridge_bytes=0):
                authorized.append(client)
        return authorized
    except BaseException:
        ledger.invalidate()
        raise
