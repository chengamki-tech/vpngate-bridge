import threading
import unittest
import urllib.request
import urllib.error
from unittest.mock import Mock, patch
from vpngate_bridge.panel import PanelClient
from vpngate_bridge.subscription_http import client_token, subscription_server


class SubscriptionHttpTests(unittest.TestCase):
    def test_access_is_rechecked_and_failures_do_not_expose_credentials(self):
        client = PanelClient('alice', 'uuid', 'sub', True, 0, 1000, 100)
        secret = b'x' * 32
        authorize = Mock(return_value=[client])
        render = Mock(return_value='encoded-subscription')
        server = subscription_server(0, secret, authorize, render)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}/sub/' + client_token(secret, client)
        try:
            with urllib.request.urlopen(url) as response:
                self.assertEqual(response.read(), b'encoded-subscription')
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
            authorize.return_value = []
            with self.assertRaises(urllib.error.HTTPError) as denied: urllib.request.urlopen(url)
            self.assertEqual(denied.exception.code, 404)
            authorize.side_effect = RuntimeError('meter unavailable')
            with self.assertRaises(urllib.error.HTTPError) as unavailable: urllib.request.urlopen(url)
            self.assertEqual(unavailable.exception.code, 503)
            self.assertEqual(render.call_count, 1)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
    def test_token_is_stable_for_identity_and_changes_when_subscription_rotates(self):
        a = PanelClient('alice', 'uuid', 'sub1', True, 0, 0, 0)
        b = PanelClient('alice', 'uuid', 'sub2', True, 0, 0, 0)
        self.assertEqual(client_token(b'x'*32, a), client_token(b'x'*32, a))
        self.assertNotEqual(client_token(b'x'*32, a), client_token(b'x'*32, b))
        with self.assertRaises(ValueError): subscription_server(0, b'short', lambda: [], lambda _: '')

    def test_expiry_during_render_does_not_return_credentials(self):
        client = PanelClient('alice', 'uuid', 'sub', True, 1000, 1000, 100)
        secret = b'x' * 32
        def render(_):
            client_clock[0] = 2
            return 'sensitive-credentials'
        client_clock = [.5]
        server = subscription_server(0, secret, lambda: [client], render)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch('vpngate_bridge.subscription_http.time.time', side_effect=lambda: client_clock[0]):
                url = f'http://127.0.0.1:{server.server_port}/sub/' + client_token(secret, client)
                with self.assertRaises(urllib.error.HTTPError) as denied: urllib.request.urlopen(url)
                self.assertEqual(denied.exception.code, 404)
                self.assertNotIn(b'sensitive-credentials', denied.exception.read())
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
