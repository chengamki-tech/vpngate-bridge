import unittest
from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import patch
from vpngate_bridge.fetcher import Candidate
from vpngate_bridge.probe import ProbeError
from vpngate_bridge.scanner import scan
from vpngate_bridge.selection import Measurement


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
