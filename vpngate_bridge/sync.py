"""Synchronize bridge-only usage through 3x-ui's absolute global overlay."""
from .meter import MeterError
from .panel import PanelError


def _panel_clients(panel):
    inbounds = panel._request('panel/api/inbounds/list').get('obj')
    if not isinstance(inbounds, list) or any(not isinstance(row, dict) or row.get('enable') is not False for row in inbounds):
        raise PanelError('bridge-only accounting requires all panel inbounds disabled')
    return {client.email: client for client in panel.clients()}


def _push_verified(panel, source_guid, before, totals, identities):
    for name, usage in totals.items():
        existing = before.get(name)
        if existing is None:
            raise PanelError('managed panel client is missing')
        if identities is not None and (existing.uuid, existing.sub_id) != identities[name]:
            raise PanelError('managed panel identity changed before traffic push')
        if existing.panel_bytes > sum(usage) or existing.panel_up > usage[0] or existing.panel_down > usage[1]:
            raise MeterError('panel usage exceeds local ledger; reconciliation required')
    panel.push_global_totals(source_guid, totals)
    after = {client.email: client for client in panel.clients()}
    for name, usage in totals.items():
        client = after.get(name)
        if (client is None or client.uuid != before[name].uuid or client.sub_id != before[name].sub_id
                or client.panel_bytes != sum(usage)):
            raise PanelError('panel client or traffic changed during synchronization')
    return [after[name] for name in totals]


def sync_bridge_usage(panel, ledger, source_guid, emails, *, now):
    names = tuple(emails)
    if not names or len(set(names)) != len(names) or type(now) is not int:
        raise ValueError('unique managed clients and integer timestamp required')
    identities = emails if isinstance(emails, dict) else None
    try:
        before = _panel_clients(panel)
        totals = {}
        for name in names:
            usage = ledger.usage(name, now=now)
            if usage is None:
                raise MeterError('fresh certain bridge usage required')
            totals[name] = usage
        clients = _push_verified(panel, source_guid, before, totals, identities)
        return [client for client in clients if client.authorized(now_ms=now * 1000, unreported_bridge_bytes=0)]
    except BaseException:
        ledger.invalidate()
        raise


def sync_final_usage(panel, ledger, source_guid, epoch, identities):
    totals = ledger.closed_totals(epoch)
    if set(totals) != set(identities):
        raise MeterError('final meter roster changed')
    _push_verified(panel, source_guid, _panel_clients(panel), totals, identities)
