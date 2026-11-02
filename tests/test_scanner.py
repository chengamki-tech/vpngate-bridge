import unittest
import tempfile
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from vpngate_bridge.fetcher import Candidate
from vpngate_bridge.probe import ClassificationError, ProbeError
from vpngate_bridge.scanner import scan
from vpngate_bridge.selection import Blacklist, Measurement


class Gateway:
    def __init__(self): self.closed = []
    @contextmanager
    def open(self, candidate):
        try: yield candidate.ip + ':1080'
        finally: self.closed.append(candidate.ip)


class ScannerTests(unittest.TestCase):
    def test_probes_candidates_selects_best_unique_exits_and_limits_countries(self):
        gateway = Gateway()
        candidates = [Candidate('8.8.8.8', 'JP', 100, 1, 'x'), Candidate('1.1.1.1', 'JP', 100, 1, 'x'), Candidate('9.9.9.9', 'US', 100, 1, 'x')]
        results = [Measurement('JP', 'JP', '8.8.4.4', False, (100,)*3, 100_000_000, 100), Measurement('JP', 'JP', '1.0.0.1', False, (900,)*3, 1, 100), Measurement('US', 'US', '8.8.4.4', False, (200,)*3, 100_000_000, 100)]
        with patch('vpngate_bridge.scanner.probe', side_effect=results):
            selected = scan({'JP': candidates[:2], 'US': candidates[2:]}, gateway, 'key', (), 2)
        self.assertEqual(selected['JP'][0], candidates[0])
        self.assertNotIn('US', selected)
        self.assertEqual(len(gateway.closed), 3)

    def test_failure_is_not_advertised_and_gateway_is_closed(self):
        gateway = Gateway()
        candidate = Candidate('8.8.8.8', 'JP', 1, 1, 'x')
        with patch('vpngate_bridge.scanner.probe', side_effect=ProbeError('failed')):
            self.assertEqual(scan({'JP': [candidate]}, gateway, 'key', (), 1), {})
        self.assertEqual(gateway.closed, ['8.8.8.8'])
        with self.assertRaises(ValueError): scan({}, gateway, 'key', (), 0)

    def test_failed_subnet_skips_other_ports_and_survives_next_scan_until_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            blacklist = Blacklist(Path(directory) / 'blacklist.sqlite')
            candidates = [Candidate('8.8.8.8', 'JP', 1, 1, 'port-one'),
                          Candidate('8.8.8.9', 'JP', 1, 1, 'port-two')]
            with patch('vpngate_bridge.scanner.probe', side_effect=ProbeError('unreachable')) as probe:
                scan({'JP': candidates}, Gateway(), None, (), 1, blacklist=blacklist, now=100)
                self.assertEqual(probe.call_count, 1)
                scan({'JP': candidates}, Gateway(), None, (), 1, blacklist=blacklist, now=101)
                self.assertEqual(probe.call_count, 1)
                scan({'JP': candidates}, Gateway(), None, (), 1, blacklist=blacklist, now=86501)
                self.assertEqual(probe.call_count, 2)
            self.assertEqual(blacklist.active(86501), ['8.8.8.0/24'])

    def test_bad_later_measurement_removes_an_earlier_winner_from_same_subnet(self):
        candidates = [Candidate('8.8.8.8', 'JP', 1, 1, 'x'), Candidate('8.8.8.9', 'JP', 1, 1, 'y')]
        result = Measurement('JP', 'JP', '1.1.1.1', False, (100,)*3, 100, 1)
        with patch('vpngate_bridge.scanner.probe', side_effect=[result, replace(result, hosting=True)]):
            self.assertEqual(scan({'JP': candidates}, Gateway(), None, (), 1), {})

    def test_metadata_outage_and_docker_failure_do_not_blacklist_a_relay(self):
        from vpngate_bridge.docker_gateway import GatewayError
        with tempfile.TemporaryDirectory() as directory:
            blacklist = Blacklist(Path(directory) / 'blacklist.sqlite')
            candidate = Candidate('8.8.8.8', 'JP', 1, 1, 'x')
            with patch('vpngate_bridge.scanner.probe', side_effect=ClassificationError('rate limited')):
                self.assertEqual(scan({'JP': [candidate]}, Gateway(), None, (), 1, blacklist=blacklist, now=100), {})
            with patch('vpngate_bridge.scanner.probe', side_effect=GatewayError('docker failed')):
                with self.assertRaises(GatewayError):
                    scan({'JP': [candidate]}, Gateway(), None, (), 1, blacklist=blacklist, now=100)
            self.assertEqual(blacklist.active(100), [])
