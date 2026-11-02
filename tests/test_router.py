import json
import asyncio
import os
import socket
import socketserver
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from vpngate_bridge.pool import ActiveRoute
from vpngate_bridge.router import GatewayRouter


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(self.server.prefix + data)


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'routes.json'
        self.backends = []
        self.router = GatewayRouter(os.environ.get('VGB_ROUTER_TEST_HOST', '127.0.0.1'), self.path)

    def tearDown(self):
        self.router.close()
        for backend in self.backends:
            backend.shutdown()
            backend.server_close()
        self.directory.cleanup()

    def backend(self, prefix):
        backend = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
        backend.daemon_threads = True
        backend.prefix = prefix
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        self.backends.append(backend)
        return backend.server_address[1]

    def test_replacement_retains_endpoint_and_closes_old_streams_without_restarting_clients(self):
        first = ActiveRoute('JP', '8.8.8.8', '8.8.4.4', '127.0.0.1', self.backend(b'a'), 20000, 20001)
        second = replace(first, server_ip='1.1.1.1', socks_port=self.backend(b'b'))
        country = self.router.publish({'JP': first})[0]
        endpoint = (country.socks_host, country.socks_port)
        with socket.create_connection(endpoint, timeout=2) as existing:
            existing.sendall(b'first')
            self.assertEqual(existing.recv(100), b'afirst')
            self.assertEqual(self.router.publish({'JP': second}), [country])
            self.assertEqual(existing.recv(100), b'')
        with socket.create_connection(endpoint, timeout=2) as connection:
            connection.sendall(b'next')
            self.assertEqual(connection.recv(100), b'bnext')
        self.assertEqual(json.loads(self.path.read_text())['countries']['JP']['server_ip'], '1.1.1.1')
        self.router.publish({})
        with socket.create_connection(endpoint, timeout=2) as connection:
            self.assertEqual(connection.recv(100), b'')
        self.assertEqual(self.router.publish({'JP': first}), [country])

    def test_manifest_failure_and_invalid_update_keep_the_old_backend(self):
        first = ActiveRoute('JP', '8.8.8.8', '8.8.4.4', '127.0.0.1', self.backend(b'a'), 20000, 20001)
        country = self.router.publish({'JP': first})[0]
        before = self.path.read_bytes()
        with patch.object(self.router, '_write_manifest', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.router.publish({'JP': replace(first, socks_port=self.backend(b'b'))})
        for bad in (replace(first, vless_port=30000), replace(first, socks_host='8.8.8.8'),
                    replace(first, socks_host=country.socks_host, socks_port=country.socks_port)):
            with self.assertRaises(ValueError):
                self.router.publish({'JP': bad})
        self.assertEqual(self.path.read_bytes(), before)
        with socket.create_connection((country.socks_host, country.socks_port), timeout=2) as connection:
            connection.sendall(b'still-live')
            self.assertEqual(connection.recv(100), b'astill-live')

    def test_private_endpoint_rejects_nonlocal_sources_and_close_is_terminal(self):
        first = ActiveRoute('JP', '8.8.8.8', '8.8.4.4', '127.0.0.1', self.backend(b'a'), 20000, 20001)
        country = self.router.publish({'JP': first})[0]
        writer = Mock()
        writer.get_extra_info.return_value = ('127.0.0.2', 12345)
        asyncio.run(self.router._relay('JP', Mock(), writer))
        writer.close.assert_called_once()
        self.router.close()
        self.assertEqual(json.loads(self.path.read_text()), {'countries': {}})
        with self.assertRaises(RuntimeError):
            self.router.publish({'JP': first})

    def test_connection_cap_and_manifest_failure_do_not_prevent_shutdown(self):
        self.router.limit = 1
        first = ActiveRoute('JP', '8.8.8.8', '8.8.4.4', '127.0.0.1', self.backend(b'a'), 20000, 20001)
        country = self.router.publish({'JP': first})[0]
        endpoint = (country.socks_host, country.socks_port)
        with socket.create_connection(endpoint, timeout=2) as existing:
            existing.sendall(b'open')
            self.assertEqual(existing.recv(100), b'aopen')
            with socket.create_connection(endpoint, timeout=2) as extra:
                self.assertEqual(extra.recv(100), b'')
            with patch.object(self.router, '_write_manifest', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    self.router.close()
            self.assertEqual(existing.recv(100), b'')
        with self.assertRaises(OSError):
            socket.create_connection(endpoint, timeout=2)

    def test_linux_nat_accepts_only_exact_addresses_assigned_to_the_host(self):
        interfaces = [{'addr_info': [{'family': 'inet', 'local': address} for address in
                                     ('127.0.0.1', '172.17.0.1', '10.1.0.209')]}]
        with patch('vpngate_bridge.router.subprocess.check_output', return_value=json.dumps(interfaces)):
            router = GatewayRouter('172.17.0.1', self.path)
        try:
            router._routes['JP'] = ActiveRoute('JP', '8.8.8.8', '8.8.4.4', '172.17.0.2', 1080, 20000, 20001)
            writer = Mock()
            writer.get_extra_info.return_value = ('10.1.0.209', 12345)
            with patch('vpngate_bridge.router.asyncio.open_connection', new_callable=AsyncMock,
                       side_effect=OSError('backend unavailable')) as connect:
                asyncio.run(router._relay('JP', Mock(), writer))
                connect.assert_awaited_once_with('172.17.0.2', 1080)
                connect.reset_mock()
                writer.get_extra_info.return_value = ('10.1.0.210', 12345)
                asyncio.run(router._relay('JP', Mock(), writer))
                connect.assert_not_awaited()
        finally:
            router.close()
