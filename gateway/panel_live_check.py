"""Test the read adapter against a disposable 3x-ui instance in CI."""
import os
import time
from vpngate_bridge.panel import Panel, PanelError


def main():
    panel = Panel(os.environ['PANEL_URL'], 'vgb-ci', 'vgb-ci-password')
    for attempt in range(30):
        try:
            panel.login()
            break
        except PanelError as exc:
            if attempt == 29:
                print(f'login failure: {exc}', flush=True)
            if attempt == 29:
                raise
            time.sleep(1)
    inbound = panel._request('panel/api/inbounds/add', {
        'enable': False, 'remark': 'ci-management', 'listen': '', 'port': 23456, 'protocol': 'vless',
        'expiryTime': 0, 'total': 0, 'settings': {'clients': [], 'decryption': 'none', 'fallbacks': []},
        'streamSettings': {'network': 'tcp', 'security': 'none'}, 'sniffing': {'enabled': False, 'destOverride': []},
    })['obj']
    panel._request('panel/api/clients/add', {'client': {
        'id': 'bf000d23-0752-40b4-affe-68f7707a9661', 'email': 'ci@example.com', 'subId': 'ci-sub',
        'totalGB': 1024, 'expiryTime': 0, 'enable': True,
    }, 'inboundIds': [inbound['id']]})
    clients = panel.clients()
    assert len(clients) == 1 and clients[0].email == 'ci@example.com'
    assert clients[0].authorized(now_ms=int(time.time() * 1000), unreported_bridge_bytes=0)
    assert not clients[0].authorized(now_ms=int(time.time() * 1000), unreported_bridge_bytes=None)
    print('real 3x-ui login, client list, and fail-closed usage check passed')


if __name__ == '__main__':
    main()
