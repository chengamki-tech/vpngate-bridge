import base64
import fcntl
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from vpngate_bridge.bridge import Client, Country, build_config
from vpngate_bridge.fetcher import Candidate
from vpngate_bridge.meter import MeterError
from vpngate_bridge.panel import PanelClient
from vpngate_bridge.selection import Measurement
from vpngate_bridge.service import parser, serve


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.state = self.root / 'state'
        for name in ('cert.pem', 'key.pem'):
            (self.root / name).write_text('fixture')
        self.args = parser().parse_args(['--state-dir', str(self.state), '--network', 'vgb-private',
                                        '--hostname', 'bridge.test', '--certificate', str(self.root / 'cert.pem'),
                                        '--key', str(self.root / 'key.pem'), '--subscription-port', '0'])
        self.client = PanelClient('alice', 'bf000d23-0752-40b4-affe-68f7707a9661', 'sub', True, 0, 1000000, 0)
        self.candidate = Candidate('8.8.8.8', 'JP', 100, 100, 'fixture')
        self.measurement = Measurement('JP', 'JP', '8.8.4.4', False, (100,)*3, 100, 100)
        self.stack = ExitStack()
        self.stack.enter_context(patch('vpngate_bridge.service.sys.platform', 'linux'))
        self.stack.enter_context(patch.dict(os.environ, {'PANEL_URL': 'http://127.0.0.1:2053/',
                                                       'PANEL_USERNAME': 'fixture', 'PANEL_PASSWORD': 'secret',
                                                       'DOCKER_HOST': 'unix:///var/run/docker.sock'}))
        self.stack.enter_context(patch('vpngate_bridge.service._docker', side_effect=lambda operation, *args:
                                      'unix:///var/run/docker.sock' if operation == 'context' else '172.18.0.1'))
        self.stack.enter_context(patch('vpngate_bridge.service.Panel'))
        self.gateway = self.stack.enter_context(patch('vpngate_bridge.service.DockerGateway')).return_value
        self.gateway.open.side_effect = self.gateway_context
        self.router = self.stack.enter_context(patch('vpngate_bridge.service.GatewayRouter')).return_value
        self.router.countries.return_value = [Country('JP', '172.18.0.1', 31080, 20000, 20001)]
        self.stack.enter_context(patch('vpngate_bridge.service.fetch', return_value={'JP': [self.candidate]}))
        self.scan = self.stack.enter_context(patch('vpngate_bridge.service.scan', return_value={'JP': (self.candidate, self.measurement)}))
        self.stack.enter_context(patch('vpngate_bridge.pool.probe', return_value=self.measurement))
        self.runtime = self.stack.enter_context(patch('vpngate_bridge.service.open_bridge', side_effect=self.bridge_context))
        self.healer = self.stack.enter_context(patch('vpngate_bridge.service.Healer')).return_value
        self.healer.run.side_effect = lambda stop: stop.wait()
        self.controller = Mock()
        self.controller.tick.return_value = [self.client]
        self.active, self.stopped, self.sources = False, False, []

    def tearDown(self):
        self.stack.close()
        self.directory.cleanup()

    @contextmanager
    def gateway_context(self, candidate):
        yield '172.18.0.2:1080'

    @contextmanager
    def bridge_context(self, panel, ledger, source, countries, secret, *args, **kwargs):
        self.sources.append((source, secret))
        self.active = True
        config = build_config(countries, [Client(self.client.email, self.client.uuid, 'long-private-password')],
                              '/cert.pem', '/key.pem')
        try:
            yield SimpleNamespace(config=config, coordinator=self.controller)
        finally:
            self.active, self.stopped = False, True

    def test_serves_authenticated_subscription_and_cleans_workers_and_resources_on_stop(self):
        owner = threading.current_thread()
        for _ in range(2):
            stop = threading.Event()
            content = []
            def tick():
                access = self.state / 'access.json'
                if threading.current_thread() is owner and access.exists():
                    state = json.loads(access.read_text())
                    url = 'http://' + state['listen'] + state['subscriptions']['alice']
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open(url, timeout=3) as response:
                        content.append(base64.b64decode(response.read()).decode())
                    stop.set()
                return [self.client]
            self.controller.tick.side_effect = tick
            serve(self.args, stop)
            self.assertIn('vless://', content[0])
            self.assertIn('hysteria2://', content[0])
            self.assertTrue(self.stopped)
            self.assertFalse((self.state / 'access.json').exists())
        self.assertEqual(self.sources[0], self.sources[1], 'source identity and signing key must survive restarts')
        self.assertEqual((self.state / 'subscription.key').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.router.publish.assert_any_call({})
        self.assertEqual(self.router.close.call_count, 2)

    def test_no_qualified_country_and_accounting_failure_never_leave_ready_access(self):
        self.scan.return_value = {}
        with self.assertRaisesRegex(RuntimeError, 'no qualified'):
            serve(self.args, threading.Event())
        self.runtime.assert_not_called()
        self.scan.return_value = {'JP': (self.candidate, self.measurement)}
        self.controller.tick.side_effect = MeterError('uncertain ledger')
        with self.assertRaises(MeterError):
            serve(self.args, threading.Event())
        self.assertFalse((self.state / 'access.json').exists())
        self.assertTrue(self.stopped)
        self.controller.revoke.assert_called()
        self.router.publish.assert_any_call({})
        self.router.close.assert_called_once()

    def test_state_lock_prevents_concurrent_service_and_canceled_activation_never_launches(self):
        self.state.mkdir(mode=0o700)
        with (self.state / 'scan.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'another scan or service'):
                serve(self.args, threading.Event())
        self.assertFalse((self.state / 'subscription.key').exists())
        stop = threading.Event()
        def probe(*args):
            stop.set()
            return self.measurement
        with patch('vpngate_bridge.pool.probe', side_effect=probe):
            serve(self.args, stop)
        self.runtime.assert_not_called()
        self.router.publish.assert_any_call({})
        self.router.close.assert_called_once()
