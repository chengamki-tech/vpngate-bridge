import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from vpngate_bridge.__main__ import main
from vpngate_bridge.fetcher import Candidate
from vpngate_bridge.selection import Measurement


class CliTests(unittest.TestCase):
    def test_scan_writes_candidate_manifest_without_vpn_config(self):
        candidate = Candidate('8.8.8.8', 'JP', 1, 1, 'secret-inline-vpn-config')
        measurement = Measurement('JP', 'JP', '8.8.4.4', False, (100,)*3, 1000, 1)
        with tempfile.TemporaryDirectory() as directory, patch('vpngate_bridge.__main__.fetch', return_value={'JP': [candidate]}), patch('vpngate_bridge.__main__.DockerGateway'), patch('vpngate_bridge.__main__.scan', return_value={'JP': (candidate, measurement)}):
            main(['--network', 'private', '--state-dir', directory, '--max-countries', '1'])
            path = Path(directory) / 'scan-results.json'
            result = json.loads(path.read_text())
            self.assertEqual(result['status'], 'candidates-only')
            self.assertEqual(result['countries']['JP']['ports'], {'vless': 20000, 'hysteria2': 20001})
            self.assertNotIn('secret-inline-vpn-config', path.read_text())
