import base64
import unittest

from gateway.stack_live_check import outbound_from_link
from vpngate_bridge.bridge import Client, Country, build_config
from vpngate_bridge.subscription import subscription


class StackLinkTests(unittest.TestCase):
    def test_real_generated_links_import_both_tls_protocols_without_disabling_verification(self):
        client = Client('alice', 'bf000d23-0752-40b4-affe-68f7707a9661', 'long:@#/?&password')
        config = build_config([Country('JP', '172.18.0.2', 1080, 20000, 20001)], [client], '/cert', '/key')
        links = base64.b64decode(subscription(config, 'alice', 'bridge.test')).decode().splitlines()
        vless, hy2 = [outbound_from_link(link) for link in links]
        self.assertEqual(vless['uuid'], client.uuid)
        self.assertEqual(vless['transport'], {'type': 'ws', 'path': '/ws'})
        self.assertEqual(hy2['password'], client.password)
        self.assertEqual([vless['server_port'], hy2['server_port']], [20000, 20001])
        for outbound in (vless, hy2):
            self.assertEqual(outbound['tls'], {'enabled': True, 'server_name': 'bridge.test', 'certificate_path': '/work/cert.pem'})
        self.assertEqual(outbound_from_link(links[0], certificate_path='/tmp/host-cert.pem')['tls']['certificate_path'],
                         '/tmp/host-cert.pem')

    def test_acceptance_importer_rejects_wrong_destination_and_missing_transport(self):
        for link in ('vless://uuid@evil.test:443?sni=bridge.test',
                     'vless://uuid@bridge.test:443?sni=bridge.test',
                     'trojan://secret@bridge.test:443?sni=bridge.test'):
            with self.subTest(link=link), self.assertRaises(ValueError):
                outbound_from_link(link)
