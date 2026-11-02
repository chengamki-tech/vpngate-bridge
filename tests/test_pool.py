import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from vpngate_bridge.fetcher import Candidate
from vpngate_bridge.pool import GatewayPool
from vpngate_bridge.ports import PortRegistry
from vpngate_bridge.selection import Measurement


class Gateways:
    def __init__(self): self.closed = []
    @contextmanager
    def open(self, candidate):
        try: yield ('172.18.0.2' if candidate.ip == '8.8.8.8' else '172.18.0.3') + ':1080'
        finally: self.closed.append(candidate.ip)


class PoolTests(unittest.TestCase):
    def test_replacement_preserves_ports_and_closes_old_only_after_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            gateways = Gateways()
            ports = PortRegistry(Path(directory) / 'ports.sqlite', 20000, 20010, set())
            published = []
            def publish(routes):
                published.append((dict(routes), list(gateways.closed)))
            pool = GatewayPool(gateways, ports, None, 1, publish)
            first = Candidate('8.8.8.8', 'JP', 1, 1, 'x')
            second = Candidate('1.1.1.1', 'JP', 1, 1, 'x')
            result1 = Measurement('JP', 'JP', '8.8.4.4', False, (100,)*3, 1, 1)
            result2 = Measurement('JP', 'JP', '1.0.0.1', False, (100,)*3, 1, 1)
            with patch('vpngate_bridge.pool.probe', side_effect=[result1, result2]):
                pool.replace(first, ())
                pool.replace(second, ())
            self.assertEqual(published[0][0]['JP'].vless_port, published[1][0]['JP'].vless_port)
            self.assertEqual(published[0][0]['JP'].hy2_port, published[1][0]['JP'].hy2_port)
            self.assertEqual(published[1][1], [])
            self.assertEqual(gateways.closed, ['8.8.8.8'])
            pool.remove('JP')
            self.assertEqual(published[-1][0], {})
            self.assertEqual(gateways.closed, ['8.8.8.8', '1.1.1.1'])

    def test_failed_replacement_keeps_old_gateway_and_cleans_staged(self):
        with tempfile.TemporaryDirectory() as directory:
            gateways = Gateways()
            ports = PortRegistry(Path(directory) / 'ports.sqlite', 20000, 20010, set())
            def publish(routes):
                if routes['JP'].server_ip == '1.1.1.1': raise RuntimeError('publish failed')
            pool = GatewayPool(gateways, ports, None, 1, publish)
            a = Candidate('8.8.8.8', 'JP', 1, 1, 'x')
            b = Candidate('1.1.1.1', 'JP', 1, 1, 'x')
            m = Measurement('JP', 'JP', '8.8.4.4', False, (100,)*3, 1, 1)
            with patch('vpngate_bridge.pool.probe', return_value=m):
                pool.replace(a, ())
                with self.assertRaisesRegex(RuntimeError, 'publish failed'): pool.replace(b, ())
            self.assertEqual(pool.routes()['JP'].server_ip, '8.8.8.8')
            self.assertEqual(gateways.closed, ['1.1.1.1'])

    def test_rejects_duplicate_exit_blacklist_and_country_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            gateways = Gateways()
            ports = PortRegistry(Path(directory) / 'ports.sqlite', 20000, 20010, set())
            pool = GatewayPool(gateways, ports, None, 2, lambda _: None)
            jp = Candidate('8.8.8.8', 'JP', 1, 1, 'x')
            us = Candidate('1.1.1.1', 'US', 1, 1, 'x')
            measurement = Measurement('JP', 'JP', '8.8.4.4', False, (100,)*3, 1, 1)
            with patch('vpngate_bridge.pool.probe', side_effect=[measurement, Measurement('US', 'US', '8.8.4.4', False, (100,)*3, 1, 1)]):
                pool.replace(jp, ())
                with self.assertRaises(ValueError): pool.replace(us, ())
            self.assertEqual(set(pool.routes()), {'JP'})
            with self.assertRaises(ValueError): pool.replace(us, ('1.1.1.0/24',))
            with patch('vpngate_bridge.pool.probe', return_value=Measurement('US', 'US', '9.9.9.9', False, (100,)*3, 1, 1)):
                pool.replace(us, ())
                with self.assertRaises(ValueError): pool.replace(Candidate('4.2.2.2', 'GB', 1, 1, 'x'), ())

    def test_close_withdraws_before_cleanup_and_rejects_reactivation(self):
        from unittest.mock import Mock
        first, second = Mock(), Mock()
        first.__exit__ = Mock(side_effect=OSError('cleanup failed'))
        second.__exit__ = Mock()
        published = Mock()
        pool = GatewayPool(None, None, None, 2, published)
        pool._active = {'JP': (None, first), 'US': (None, second)}
        with self.assertRaisesRegex(OSError, 'cleanup failed'):
            pool.close()
        published.assert_called_once_with({})
        second.__exit__.assert_called_once_with(None, None, None)
        self.assertEqual(pool.routes(), {})
        with self.assertRaisesRegex(OSError, "cleanup failed"):
            pool.close()
        published.assert_called_once()
        with self.assertRaisesRegex(RuntimeError, 'closed'):
            pool.replace(None, ())

    def test_failed_withdrawal_keeps_gateways_for_retry(self):
        from unittest.mock import Mock
        context = Mock()
        context.__exit__ = Mock()
        published = Mock(side_effect=[RuntimeError('publisher unavailable'), None])
        pool = GatewayPool(None, None, None, 1, published)
        pool._active = {'JP': (None, context)}
        with self.assertRaisesRegex(RuntimeError, 'publisher unavailable'):
            pool.close()
        context.__exit__.assert_not_called()
        self.assertIn('JP', pool.routes())
        pool.close()
        context.__exit__.assert_called_once()
