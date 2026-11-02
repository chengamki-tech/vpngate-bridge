import unittest
from dataclasses import replace
from vpngate_bridge.bridge import Client, Country, build_config


class BridgeTests(unittest.TestCase):
    def test_routes_each_protocol_to_its_gateway(self):
        user = Client('alice', 'bf000d23-0752-40b4-affe-68f7707a9661', 'long-random-password')
        countries = [Country('JP', '172.18.0.3', 1080, 20000, 20001), Country('US', '172.18.0.4', 1080, 20002, 20003)]
        config = build_config(countries, [user], '/cert.pem', '/key.pem')
        self.assertEqual(len(config['inbounds']), 4)
        self.assertEqual(config['experimental']['v2ray_api']['listen'], '127.0.0.1:10085')
        self.assertEqual(config['experimental']['v2ray_api']['stats']['users'], ['alice'])
        self.assertEqual(config['route']['rules'][0], {'inbound': ['vless-JP', 'hy2-JP'], 'outbound': 'socks-JP'})
        self.assertEqual(config['route']['rules'][-1], {'action': 'reject'})
        self.assertEqual(config['outbounds'][0]['server'], '172.18.0.3')
        self.assertEqual(config['inbounds'][0]['users'][0]['uuid'], user.uuid)
        self.assertTrue(config['inbounds'][1]['tls']['enabled'])

    def test_rejects_unauthenticated_or_conflicting_configuration(self):
        country = Country('JP', '172.18.0.3', 1080, 20000, 20001)
        user = Client('alice', 'bf000d23-0752-40b4-affe-68f7707a9661', 'long-random-password')
        for countries, users in [([country], []), ([country, country], [user]), ([replace(country, hy2_port=20000)], [user]), ([replace(country, code='../')], [user]), ([country], [replace(user, uuid='bad')]), ([country], [replace(user, password='')])]:
            with self.subTest(countries=countries, users=users), self.assertRaises(ValueError):
                build_config(countries, users, '/cert.pem', '/key.pem')

    def test_rejects_stats_listener_collision(self):
        user = Client('alice', 'bf000d23-0752-40b4-affe-68f7707a9661', 'long-random-password')
        with self.assertRaises(ValueError):
            build_config([Country('JP', '172.18.0.3', 1080, 10085, 20001)], [user], '/cert', '/key')
