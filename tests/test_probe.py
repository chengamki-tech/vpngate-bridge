import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from vpngate_bridge.probe import ProbeError, probe


class Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit): return self.payload[:limit]


class ProbeTests(unittest.TestCase):
    def test_measures_socks_and_classifies_exit(self):
        responses = [b'8.8.8.8\n0.200', b'8.8.8.8\n0.300', b'8.8.8.8\n0.400', b'1000000']
        meta = {'ip': '8.8.8.8', 'is_datacenter': False, 'location': {'country_code': 'JP'}}
        with patch('vpngate_bridge.probe.subprocess.run', side_effect=[SimpleNamespace(stdout=x) for x in responses]) as run, patch('vpngate_bridge.probe.urllib.request.urlopen', return_value=Response(meta)):
            result = probe(SimpleNamespace(country='JP', uptime_ms=1000), 'gateway-jp:1080', 'private-key')
        self.assertEqual(result.exit_ip, '8.8.8.8')
        self.assertEqual(result.latencies_ms, (200, 300, 400))
        self.assertEqual(result.speed_bps, 8000000)
        self.assertEqual(run.call_count, 4)
        self.assertIn('--socks5-hostname', run.call_args_list[0].args[0])
        self.assertNotIn('private-key', str(run.call_args_list))

    def test_free_provider_requires_complete_matching_response(self):
        candidate = SimpleNamespace(country='JP', uptime_ms=1)
        meta = {'ip': '8.8.8.8', 'country_code': 'JP', 'is_hosting': False}
        outputs = [SimpleNamespace(stdout=x) for x in [b'8.8.8.8\n0.1'] * 3 + [b'1000']]
        with patch('vpngate_bridge.probe.subprocess.run', side_effect=outputs), patch('vpngate_bridge.probe.urllib.request.urlopen', return_value=Response(meta)) as request:
            self.assertEqual(probe(candidate, 'gateway:1080', None).exit_ip, '8.8.8.8')
            self.assertIn('whatsmyip.now', request.call_args.args[0].full_url)
            self.assertEqual(request.call_args.args[0].get_header('User-agent'), 'vpngate-bridge/0.1')
        meta.pop('is_hosting')
        with patch('vpngate_bridge.probe.subprocess.run', side_effect=[SimpleNamespace(stdout=b'8.8.8.8\n0.1') for _ in range(3)]), patch('vpngate_bridge.probe.urllib.request.urlopen', return_value=Response(meta)):
            with self.assertRaises(ProbeError): probe(candidate, 'gateway:1080', None)

    def test_rejects_inconsistent_exit_missing_classification_and_timeout(self):
        candidate = SimpleNamespace(country='JP', uptime_ms=1)
        for outputs, metadata in [([b'8.8.8.8\n0.1', b'1.1.1.1\n0.1', b'8.8.8.8\n0.1'], None), ([b'8.8.8.8\n0.1'] * 3, {'ip': '8.8.8.8', 'location': {'country_code': 'JP'}})]:
            with self.subTest(outputs=outputs), patch('vpngate_bridge.probe.subprocess.run', side_effect=[SimpleNamespace(stdout=x) for x in outputs]), patch('vpngate_bridge.probe.urllib.request.urlopen', return_value=Response(metadata or {})):
                with self.assertRaises(ProbeError): probe(candidate, 'gateway:1080', 'secret')
        with patch('vpngate_bridge.probe.subprocess.run', side_effect=subprocess.TimeoutExpired('curl', 10)):
            with self.assertRaises(ProbeError): probe(candidate, 'gateway:1080', 'secret')
