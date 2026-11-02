import base64
import unittest
from vpngate_bridge.bridge import Client, Country, build_config
from vpngate_bridge.subscription import subscription


class SubscriptionTests(unittest.TestCase):
    def test_generates_authenticated_country_links(self):
        user = Client('alice', 'bf000d23-0752-40b4-affe-68f7707a9661', 'special-password-+/')
        config = build_config([Country('JP', '172.18.0.3', 1080, 20000, 20001)], [user], '/cert', '/key')
        links = base64.b64decode(subscription(config, 'alice', 'vpn.example.com')).decode().splitlines()
        self.assertEqual(len(links), 2)
        self.assertIn('vless://bf000d23-0752-40b4-affe-68f7707a9661@vpn.example.com:20000', links[0])
        self.assertIn('path=%2Fws', links[0])
        self.assertIn('hysteria2://special-password-%2B%2F@vpn.example.com:20001', links[1])

    def test_rejects_unknown_client_and_invalid_host(self):
        user = Client('alice', 'bf000d23-0752-40b4-affe-68f7707a9661', 'long-random-password')
        config = build_config([Country('JP', '172.18.0.3', 1080, 20000, 20001)], [user], '/cert', '/key')
        for name, host in [('bob', 'vpn.example.com'), ('alice', 'vpn.example.com@evil.example'), ('alice', 'bad/path')]:
            with self.subTest(name=name, host=host), self.assertRaises(ValueError): subscription(config, name, host)
