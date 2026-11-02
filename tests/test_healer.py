import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from vpngate_bridge.fetcher import Candidate
from vpngate_bridge.healer import Healer
from vpngate_bridge.pool import ActiveRoute
from vpngate_bridge.selection import Blacklist, Measurement
from vpngate_bridge.probe import ClassificationError, ProbeError


class FakePool:
    def __init__(self, route):
        self.live = {route.country: route}
        self.gateways = object()
        self.api_key = None
        self.events = []
    def routes(self): return dict(self.live)
    def remove(self, country, *, expected=None):
        assert self.live[country] == expected
        self.events.append(('remove', country))
        del self.live[country]
    def replace(self, candidate, blocked, *, expected_absent=False):
        assert expected_absent and candidate.country not in self.live
        self.events.append(('replace', candidate.country))
        route = ActiveRoute(candidate.country, candidate.ip, '1.0.0.1', '172.18.0.3', 1080, 20000, 20001)
        self.live[candidate.country] = route
        return route


class HealerTests(unittest.TestCase):
    def test_failed_replacement_stays_pending_and_only_bad_relays_are_blacklisted(self):
        for failure, blocked in ((ProbeError('tunnel failed'), True), (ClassificationError('metadata unavailable'), False)):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                pool = FakePool(ActiveRoute('JP', '8.8.8.8', '8.8.4.4', '172.18.0.2', 1080, 20000, 20001))
                blacklist = Blacklist(Path(directory) / 'blacklist.sqlite')
                candidate = Candidate('1.1.1.1', 'JP', 1, 1, 'x')
                measurement = Measurement('JP', 'JP', '1.0.0.1', False, (100,)*3, 100, 1)
                healer = Healer(pool, blacklist, Path(directory) / 'health.sqlite',
                                fetcher=lambda: {'JP': [candidate]}, check=lambda _: False)
                with patch('vpngate_bridge.healer.scan', return_value={'JP': (candidate, measurement)}), \
                        patch.object(pool, 'replace', side_effect=failure):
                    healer.tick(now=100)
                    healer.tick(now=700)
                self.assertEqual(pool.routes(), {})
                self.assertEqual(len(healer._pending()), 1)
                self.assertEqual('1.1.1.0/24' in blacklist.active(700), blocked)

    def test_two_failures_rescan_same_country_and_preserve_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = FakePool(ActiveRoute('JP', '8.8.8.8', '8.8.4.4', '172.18.0.2', 1080, 20000, 20001))
            blacklist = Blacklist(Path(directory) / 'blacklist.sqlite')
            candidate = Candidate('1.1.1.1', 'JP', 1, 1, 'x')
            result = Measurement('JP', 'JP', '1.0.0.1', False, (100,)*3, 1, 1)
            healer = Healer(pool, blacklist, Path(directory) / 'health.sqlite', fetcher=lambda: {'JP': [candidate]}, check=lambda _: False)
            with patch('vpngate_bridge.healer.scan', return_value={'JP': (candidate, result)}) as scanner:
                healer.tick(now=100)
                self.assertEqual(pool.events, [])
                healer.tick(now=700)
            self.assertEqual(pool.events, [('remove', 'JP'), ('replace', 'JP')])
            self.assertEqual((pool.live['JP'].vless_port, pool.live['JP'].hy2_port), (20000, 20001))
            self.assertEqual(set(blacklist.active(700)), {'8.8.4.0/24', '8.8.8.0/24'})
            self.assertEqual(set(scanner.call_args.args[0]), {'JP'})

    def test_success_resets_failures_and_pending_country_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = FakePool(ActiveRoute('JP', '8.8.8.8', '8.8.4.4', '172.18.0.2', 1080, 20000, 20001))
            blacklist = Blacklist(Path(directory) / 'blacklist.sqlite')
            outcomes = iter([False, True, False, False])
            candidate = Candidate('1.1.1.1', 'JP', 1, 1, 'x')
            result = Measurement('JP', 'JP', '1.0.0.1', False, (100,)*3, 1, 1)
            healer = Healer(pool, blacklist, Path(directory) / 'health.sqlite', fetcher=lambda: {'JP': [candidate]}, check=lambda _: next(outcomes))
            with patch('vpngate_bridge.healer.scan', side_effect=[{}, {'JP': (candidate, result)}]):
                for now in (100, 700, 1300): healer.tick(now=now)
                self.assertEqual(pool.events, [])
                healer.tick(now=1900)
                self.assertEqual(pool.events, [('remove', 'JP')])
                healer.tick(now=2500)
            self.assertEqual(pool.events, [('remove', 'JP'), ('replace', 'JP')])

    def test_real_pool_and_healer_switch_route_after_two_failures(self):
        from contextlib import contextmanager
        from vpngate_bridge.pool import GatewayPool
        from vpngate_bridge.ports import PortRegistry
        class Gateways:
            def __init__(self): self.closed = []
            @contextmanager
            def open(self, candidate):
                try: yield ('172.18.0.2' if candidate.ip == '8.8.8.8' else '172.18.0.3') + ':1080'
                finally: self.closed.append(candidate.ip)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            gates = Gateways()
            published = []
            pool = GatewayPool(gates, PortRegistry(path / 'ports.sqlite', 20000, 20010, set()), None, 1, lambda routes: published.append(dict(routes)))
            old = Candidate('8.8.8.8', 'JP', 1, 1, 'x')
            new = Candidate('1.1.1.1', 'JP', 1, 1, 'x')
            old_result = Measurement('JP', 'JP', '8.8.4.4', False, (100,)*3, 1, 1)
            new_result = Measurement('JP', 'JP', '1.0.0.1', False, (100,)*3, 1, 1)
            healer = Healer(pool, Blacklist(path / 'blacklist.sqlite'), path / 'health.sqlite', fetcher=lambda: {'JP': [new]}, check=lambda _: False)
            with patch('vpngate_bridge.pool.probe', side_effect=[old_result, new_result]), patch('vpngate_bridge.healer.scan', return_value={'JP': (new, new_result)}):
                first = pool.replace(old, ())
                healer.tick(now=100)
                healer.tick(now=700)
            self.assertEqual([set(item) for item in published], [{'JP'}, set(), {'JP'}])
            self.assertEqual((pool.routes()['JP'].vless_port, pool.routes()['JP'].hy2_port), (first.vless_port, first.hy2_port))
            self.assertEqual(gates.closed, ['8.8.8.8'])
            self.assertEqual(healer._pending(), [])
            pool.remove('JP')
