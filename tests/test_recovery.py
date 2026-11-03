import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock, patch

from vpngate_bridge.meter import CounterLedger, MeterError
from vpngate_bridge.runtime import recover_bridges


RUN = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
SOURCE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
INCIDENT = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
CONTAINER = 'vgb-bridge-' + 'd' * 32


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.proto = self.root / 'stats.proto'
        self.proto.write_text('fixture')
        self.run_dir = self.root / ('run-' + RUN)
        self.run_dir.mkdir(mode=0o700)
        (self.run_dir / 'final').mkdir(mode=0o700)
        (self.run_dir / 'lease.json').write_text('expired')
        self.manifest = self.root / ('recovery-' + RUN + '.json')
        self.write_final()
        self.manifest.write_text(json.dumps({
            'version': 1, 'run_id': RUN, 'container': CONTAINER, 'source_guid': SOURCE,
            'identities': {'alice': ['bf000d23-0752-40b4-affe-68f7707a9661', 'sub']},
            'status': 'running', 'incarnation': INCIDENT,
        }))
        self.ledger = CounterLedger(self.root / 'meter.sqlite')
        self.ledger.begin(RUN, ['alice'])
        self.ledger.record(RUN, {'alice': (10, 20)}, now=100)
        self.panel = Mock()

    def tearDown(self):
        self.directory.cleanup()

    def write_final(self):
        (self.run_dir / 'final' / 'counters.json').write_text(json.dumps({
            'version': 1, 'run_id': RUN,
            'counters': {'alice': [15, 40]},
        }))

    def test_finalizes_an_absent_auto_removed_bridge_from_private_snapshot(self):
        with patch('vpngate_bridge.runtime._docker', return_value=''), \
                patch('vpngate_bridge.runtime._remove_owned') as remove, \
                patch('vpngate_bridge.runtime.sync_final_usage') as sync:
            recover_bridges(self.panel, self.ledger, self.root, self.proto)
        self.assertEqual(self.ledger.closed_totals(RUN), {'alice': (15, 40)})
        sync.assert_called_once_with(self.panel, self.ledger, SOURCE, RUN,
                                     {'alice': ('bf000d23-0752-40b4-affe-68f7707a9661', 'sub')})
        remove.assert_called_once_with(CONTAINER, 'org.vpngate-bridge.bridge')
        self.assertFalse(self.run_dir.exists())
        self.assertFalse(self.manifest.exists())

    def test_expired_live_bridge_removes_lease_and_verifies_same_incarnation(self):
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[0] == 'ps':
                return 'e' * 12
            if args[0] == 'inspect':
                return 'e' * 64
            return ''
        with patch('vpngate_bridge.runtime._docker', side_effect=docker), \
                patch('vpngate_bridge.runtime.docker_epoch',
                      side_effect=[MeterError('running'), INCIDENT]) as epoch, \
                patch('vpngate_bridge.runtime._remove_owned'), \
                patch('vpngate_bridge.runtime.sync_final_usage'):
            recover_bridges(self.panel, self.ledger, self.root, self.proto)
        self.assertFalse((self.run_dir / 'lease.json').exists())
        self.assertEqual(calls[0][0], 'ps')
        self.assertEqual(calls[1], ('inspect', '--format', '{{.Id}}', 'e' * 12))
        self.assertEqual(epoch.call_args_list[0].args[0], 'e' * 64)
        self.assertFalse(self.manifest.exists())

    def test_preflight_manifest_without_incarnation_never_claims_a_final_count(self):
        value = json.loads(self.manifest.read_text())
        value['status'] = 'preflight'
        value.pop('incarnation')
        self.manifest.write_text(json.dumps(value))
        with patch('vpngate_bridge.runtime._docker') as docker:
            with self.assertRaisesRegex(MeterError, 'verified process incarnation'):
                recover_bridges(self.panel, self.ledger, self.root, self.proto)
            docker.assert_not_called()
        self.assertTrue(self.run_dir.exists())
        self.assertTrue(self.manifest.exists())
        with self.assertRaises(MeterError):
            self.ledger.begin(str(uuid.uuid4()), ['alice'])
