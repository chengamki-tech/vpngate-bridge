import unittest
from vpngate_bridge.openvpn import safe_config


CA = '<ca>\n-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n</ca>\n'


class OpenVPNTests(unittest.TestCase):
    def test_rebuilds_safe_config_and_pins_remote_ip(self):
        result = safe_config('proto udp\nremote vpn.example 1194\ncipher AES-128-CBC\nauth SHA1\n' + CA, '8.8.8.8')
        self.assertIn('remote 8.8.8.8 1194\n', result)
        self.assertNotIn('vpn.example', result)
        cert = '<cert>\n-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n</cert>\n'
        key = '<key>\n-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n</key>\n'
        self.assertIn('<key>', safe_config('proto udp\nremote x 1194\n' + CA + cert + key, '8.8.8.8'))
        self.assertIn('script-security 1', result)
        self.assertIn('route-nopull', result)
        self.assertIn('redirect-gateway def1', result)

    def test_rejects_injection_and_malformed_config(self):
        good = 'proto udp\nremote vpn.example 1194\n' + CA
        for bad in [good + 'up /tmp/evil\n', good + 'remote other 443\n', good.replace('1194', '0'), good.replace('</ca>', '</cert>'), good + 'plugin x\n']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                safe_config(bad, '8.8.8.8')
        with self.assertRaises(ValueError):
            safe_config(good, '127.0.0.1')
