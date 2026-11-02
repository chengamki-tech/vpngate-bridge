import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from vpngate_bridge.coordinator import LeaseCoordinator, AccessRevoked
from vpngate_bridge.lease import valid
from vpngate_bridge.panel import PanelClient


class CoordinatorTests(unittest.TestCase):
    def test_renews_only_exact_runtime_users_and_revokes_on_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            ledger = Mock()
            client = PanelClient('alice', 'uuid', 'sub', True, 0, 1000, 0)
            run_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
            controller = LeaseCoordinator(Mock(), ledger, 'source', {'alice': ('uuid', 'sub')}, 'epoch', lambda: 'epoch', '127.0.0.1:1', 'stats.proto', path, run_id)
            with patch('vpngate_bridge.coordinator.collect'), patch('vpngate_bridge.coordinator.sync_bridge_usage', return_value=[client]) as sync:
                self.assertEqual(controller.tick(now=100), [client])
                self.assertTrue(valid(path, run_id))
                sync.return_value = []
                with self.assertRaises(AccessRevoked): controller.tick(now=101)
                self.assertFalse(path.exists())
                ledger.invalidate.assert_called_once()
    def test_collection_failure_removes_existing_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            path.write_text('stale')
            ledger = Mock()
            controller = LeaseCoordinator(Mock(), ledger, 'source', {'alice': ('uuid', 'sub')}, 'epoch', lambda: 'epoch', '127.0.0.1:1', 'stats.proto', path, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
            with patch('vpngate_bridge.coordinator.collect', side_effect=RuntimeError('unavailable')), patch('vpngate_bridge.coordinator.sync_bridge_usage') as sync:
                with self.assertRaises(RuntimeError): controller.tick(now=100)
                sync.assert_not_called()
            self.assertFalse(path.exists())
            ledger.invalidate.assert_called_once()
