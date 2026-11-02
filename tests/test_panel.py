import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from vpngate_bridge.panel import Panel, PanelError


class Handler(BaseHTTPRequestHandler):
    calls = []
    clients = [{'id': 1, 'email': 'alice@example.com', 'uuid': 'bf000d23-0752-40b4-affe-68f7707a9661', 'subId': 'sub1', 'totalGB': 1000, 'expiryTime': 200000, 'enable': True, 'traffic': {'up': 100, 'down': 200, 'enable': True}}]
    def log_message(self, *args): pass
    def reply(self, body, status=200, headers=()):
        data = json.dumps(body).encode()
        self.send_response(status)
        for key, value in headers: self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        Handler.calls.append((self.path, json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
        self.reply({'success': True}, headers=[('Set-Cookie', 'session=abc; Path=/prefix/')])
    def do_GET(self):
        Handler.calls.append((self.path, self.headers.get('Cookie')))
        if self.path != '/prefix/panel/api/clients/list' or self.headers.get('Cookie') != 'session=abc':
            self.reply({'success': False}, 403)
        else: self.reply({'success': True, 'obj': Handler.clients})


class PanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()
    def setUp(self):
        Handler.calls = []
        Handler.clients = [{'id': 1, 'email': 'alice@example.com', 'uuid': 'bf000d23-0752-40b4-affe-68f7707a9661', 'subId': 'sub1', 'totalGB': 1000, 'expiryTime': 200000, 'enable': True, 'traffic': {'up': 100, 'down': 200, 'enable': True}}]
    def panel(self): return Panel(f'http://127.0.0.1:{self.server.server_port}/prefix/', 'admin', 'secret')
    def test_login_and_read_clients_using_session_cookie(self):
        panel = self.panel()
        panel.login(two_factor_code='123456')
        clients = panel.clients()
        self.assertEqual(Handler.calls[0][0], '/prefix/login')
        self.assertEqual(Handler.calls[0][1]['twoFactorCode'], '123456')
        self.assertEqual(Handler.calls[1][1], 'session=abc')
        self.assertTrue(clients[0].authorized(now_ms=100000, unreported_bridge_bytes=0))
        self.assertFalse(clients[0].authorized(now_ms=200000, unreported_bridge_bytes=0))
        self.assertFalse(clients[0].authorized(now_ms=100000, unreported_bridge_bytes=700))
        self.assertFalse(clients[0].authorized(now_ms=100000, unreported_bridge_bytes=None))
    def test_reject_missing_traffic_or_duplicate_identity(self):
        panel = self.panel()
        panel.login()
        del Handler.clients[0]['traffic']
        with self.assertRaises(PanelError): panel.clients()
        Handler.clients[0]['traffic'] = {'up': 0, 'down': 0, 'enable': True}
        Handler.clients.append(dict(Handler.clients[0]))
        with self.assertRaises(PanelError): panel.clients()
    def test_reject_insecure_remote_url_and_unauthenticated_requests(self):
        with self.assertRaises(ValueError): Panel('http://example.com', 'u', 'p')
        with self.assertRaises(PanelError): self.panel().clients()
