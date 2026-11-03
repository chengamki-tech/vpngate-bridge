import tempfile
import os
import unittest
import uuid
import threading
import json
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from vpngate_bridge.bridge import Country
from vpngate_bridge.coordinator import AccessRevoked
from vpngate_bridge.docker_gateway import GatewayError
from vpngate_bridge.meter import CounterLedger, MeterError
from vpngate_bridge.panel import PanelClient
from vpngate_bridge.runtime import open_bridge


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        for name in ('cert.pem', 'key.pem', 'stats.proto'):
            (self.root / name).write_text('fixture')
        self.ledger = CounterLedger(self.root / 'meter.sqlite')
        self.client = PanelClient('alice', 'bf000d23-0752-40b4-affe-68f7707a9661', 'sub', True, 0, 1000000, 0)
        self.panel = Mock()
        self.panel.clients.return_value = [self.client]
        self.events = []
        self.commands = []
        self.stack = ExitStack()
        self.stack.enter_context(patch('vpngate_bridge.runtime._docker', side_effect=self.docker))
        self.cleanup = self.stack.enter_context(patch('vpngate_bridge.runtime._remove_owned'))
        self.epoch = self.stack.enter_context(patch('vpngate_bridge.runtime.docker_epoch', return_value='incarnation'))
        self.preflight = self.stack.enter_context(patch('vpngate_bridge.runtime.sync_bridge_usage', side_effect=self.authorize))
        self.stack.enter_context(patch('vpngate_bridge.coordinator.sync_bridge_usage', return_value=[self.client]))
        self.stack.enter_context(patch('vpngate_bridge.coordinator.collect', side_effect=self.collect))
        self.stack.enter_context(patch('vpngate_bridge.runtime.socket.create_connection', return_value=MagicMock()))

    def tearDown(self):
        self.stack.close()
        self.directory.cleanup()

    def docker(self, *args, **kwargs):
        self.commands.append(args)
        self.events.append('launch' if '-d' in args else 'check')
        return 'a' * 64

    def authorize(self, *args, **kwargs):
        self.events.append('authorize')
        return [self.client]

    def collect(self, ledger, epoch, endpoint, proto, users, process_epoch, *, now):
        if process_epoch() != epoch:
            raise MeterError('wrong process')
        ledger.record(epoch, {name: (12, 34) for name in users}, now=now)

    def runtime(self, **kwargs):
        return open_bridge(self.panel, self.ledger, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                           [Country('JP', '172.18.0.1', 31080, 20000, 20001)], b'x' * 32,
                           self.root / 'cert.pem', self.root / 'key.pem', self.root, self.root / 'stats.proto', **kwargs)

    def test_authorizes_before_exposure_and_never_claims_a_running_epoch_was_drained(self):
        with self.runtime() as runtime:
            self.assertEqual(self.events, ['check', 'authorize', 'launch'])
            self.assertEqual(runtime.container_id, 'a' * 64)
            self.assertEqual(self.ledger.usage('alice'), (12, 34))
            self.assertTrue(runtime.coordinator.lease_path.exists())
            self.assertEqual(runtime.config['inbounds'][0]['users'][0]['uuid'], self.client.uuid)
            self.assertGreaterEqual(len(runtime.config['inbounds'][1]['users'][0]['password']), 32)
            launch = next(command for command in self.commands if '-d' in command)
            self.assertIn('--cap-drop=ALL', launch)
            self.assertIn('--read-only', launch)
            self.assertEqual(launch[launch.index('--user') + 1], f'{os.getuid()}:{os.getgid()}')
        self.cleanup.assert_called_once()
        self.assertEqual(self.cleanup.call_args.args[1], 'org.vpngate-bridge.bridge')
        self.assertIsNone(self.ledger.usage('alice'))
        with self.assertRaises(MeterError):
            self.ledger.begin(str(uuid.uuid4()), ['alice'])

    def test_revoked_or_changed_clients_never_get_public_listeners(self):
        self.panel.clients.return_value = [replace(self.client, enabled=False)]
        with self.assertRaises(AccessRevoked):
            with self.runtime():
                self.fail('disabled user launched')
        self.assertEqual(self.events, [])
        self.panel.clients.return_value = [self.client]
        self.preflight.side_effect = None
        self.preflight.return_value = [replace(self.client, sub_id='rotated')]
        with self.assertRaises(AccessRevoked):
            with self.runtime():
                self.fail('changed user launched')
        self.assertNotIn('launch', self.events)
        self.cleanup.assert_not_called()
        self.preflight.return_value = [self.client]
        stop = threading.Event()
        with patch('vpngate_bridge.runtime._docker', side_effect=lambda *args, **kwargs: stop.set()):
            with self.assertRaises(InterruptedError):
                with self.runtime(stop_event=stop):
                    self.fail('canceled startup launched')
        self.ledger.begin(str(uuid.uuid4()), ['alice'])  # Preflight had no traffic and can close cleanly.

    def test_partial_docker_run_failure_preserves_uncertain_intent_and_cleans_owned_container(self):
        def docker(*args, **kwargs):
            if '-d' in args:
                raise GatewayError('Docker response lost')
            return ''
        with patch('vpngate_bridge.runtime._docker', side_effect=docker):
            with self.assertRaises(GatewayError):
                with self.runtime():
                    self.fail('failed run entered runtime')
        self.cleanup.assert_called_once()
        with self.assertRaises(MeterError):
            self.ledger.begin(str(uuid.uuid4()), ['alice'])

    def test_previous_unclean_epoch_cannot_be_restarted_as_a_zero_usage_client(self):
        self.ledger.begin(str(uuid.uuid4()), ['alice'])
        with self.assertRaises(MeterError):
            with self.runtime():
                self.fail('uncertain usage launched')
        self.assertNotIn('launch', self.events)

    def test_container_restart_before_initial_collection_rejects_admission_and_cleans_up(self):
        self.epoch.side_effect = ['first-incarnation', 'second-incarnation']
        with self.assertRaises(MeterError):
            with self.runtime():
                self.fail('changed process entered runtime')
        self.cleanup.assert_called_once()
        self.assertIsNone(self.ledger.usage('alice'))

    def test_verified_final_snapshot_allows_restart_without_resetting_cumulative_usage(self):
        with patch('vpngate_bridge.runtime.sync_final_usage') as publish:
            for _ in range(2):
                with self.runtime() as runtime:
                    final = runtime.coordinator.lease_path.parent / 'final' / 'counters.json'
                    epoch = runtime.coordinator.meter_epoch
                    final.write_text(json.dumps({'version': 1, 'run_id': epoch, 'counters': {'alice': [15, 40]}}))
            self.assertEqual(publish.call_count, 2)
            self.assertEqual(self.ledger.closed_totals(epoch), {'alice': (30, 80)})
        self.assertIsNone(self.ledger.usage('alice'))
