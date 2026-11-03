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
            panel = Mock()
            panel.clients.return_value = [client]
            run_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
            controller = LeaseCoordinator(panel, ledger, 'source', {'alice': ('uuid', 'sub')}, 'epoch', lambda: 'epoch', '127.0.0.1:1', 'stats.proto', path, run_id)
            with patch('vpngate_bridge.coordinator.collect'), patch('vpngate_bridge.coordinator.sync_bridge_usage', return_value=[client]) as sync:
                self.assertEqual(controller.tick(now=100), [client])
                self.assertTrue(valid(path, run_id))
                sync.return_value = []
                with self.assertRaises(AccessRevoked): controller.tick(now=101)
                self.assertFalse(path.exists())
                ledger.invalidate.assert_called_once()
    def test_detects_newly_authorized_panel_client_even_when_fixed_users_still_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            client = PanelClient('alice', 'uuid', 'sub', True, 0, 1000, 0)
            added = PanelClient('bob', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'bob-sub', True, 0, 1000, 0)
            panel = Mock()
            panel.clients.return_value = [client, added]
            ledger = Mock()
            controller = LeaseCoordinator(panel, ledger, 'source', {'alice': ('uuid', 'sub')}, 'epoch',
                                          lambda: 'epoch', '127.0.0.1:1', 'stats.proto', path,
                                          'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
            with patch('vpngate_bridge.coordinator.collect'), \
                    patch('vpngate_bridge.coordinator.sync_bridge_usage', return_value=[client]):
                with self.assertRaises(AccessRevoked):
                    controller.tick(now=100)
            self.assertFalse(path.exists())
            ledger.invalidate.assert_called_once()
    def test_expired_user_triggers_rotation_before_collecting_the_old_roster(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            client = PanelClient('alice', 'uuid', 'sub', True, 50, 1000, 0)
            panel = Mock()
            panel.clients.return_value = [client]
            ledger = Mock()
            controller = LeaseCoordinator(panel, ledger, 'source', {'alice': ('uuid', 'sub')}, 'epoch',
                                          lambda: 'epoch', '127.0.0.1:1', 'stats.proto', path,
                                          'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
            with patch('vpngate_bridge.coordinator.collect') as collect:
                with self.assertRaises(AccessRevoked):
                    controller.tick(now=100)
                collect.assert_not_called()
            ledger.invalidate.assert_called_once()
    def test_collection_failure_removes_existing_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            path.write_text('stale')
            ledger = Mock()
            panel = Mock()
            panel.clients.return_value = [PanelClient('alice', 'uuid', 'sub', True, 0, 1000, 0)]
            controller = LeaseCoordinator(panel, ledger, 'source', {'alice': ('uuid', 'sub')}, 'epoch',
                                          lambda: 'epoch', '127.0.0.1:1', 'stats.proto', path,
                                          'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
            with patch('vpngate_bridge.coordinator.collect', side_effect=RuntimeError('unavailable')), patch('vpngate_bridge.coordinator.sync_bridge_usage') as sync:
                with self.assertRaises(RuntimeError): controller.tick(now=100)
                sync.assert_not_called()
            self.assertFalse(path.exists())
            ledger.invalidate.assert_called_once()
