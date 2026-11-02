import unittest
from unittest.mock import Mock
from vpngate_bridge.panel import PanelClient, PanelError
from vpngate_bridge.meter import MeterError
from vpngate_bridge.sync import sync_bridge_usage


class SyncTests(unittest.TestCase):
    def test_syncs_verified_totals_and_returns_eligible_clients(self):
        client = PanelClient('alice', 'id', 'sub', True, 0, 1000, 300)
        panel, ledger = Mock(), Mock()
        panel._request.return_value = {'obj': [{'enable': False}]}
        panel.clients.return_value = [client]
        ledger.usage.return_value = (100, 200)
        self.assertEqual(sync_bridge_usage(panel, ledger, 'source', ['alice'], now=100), [client])
        panel.push_global_totals.assert_called_once_with('source', {'alice': (100, 200)})
        ledger.invalidate.assert_not_called()
    def test_unknown_usage_or_active_xray_inbound_fails_closed(self):
        panel, ledger = Mock(), Mock()
        panel._request.return_value = {'obj': [{'enable': True}]}
        with self.assertRaises(PanelError): sync_bridge_usage(panel, ledger, 'source', ['alice'], now=100)
        panel.push_global_totals.assert_not_called()
        ledger.invalidate.assert_called_once()
        panel._request.return_value = {'obj': [{'enable': False}]}
        panel.clients.return_value = [PanelClient('alice', 'id', 'sub', True, 0, 1000, 0)]
        ledger.usage.return_value = None
        with self.assertRaises(MeterError): sync_bridge_usage(panel, ledger, 'source', ['alice'], now=100)

    def test_never_overwrites_higher_existing_panel_usage(self):
        panel, ledger = Mock(), Mock()
        panel._request.return_value = {'obj': [{'enable': False}]}
        panel.clients.return_value = [PanelClient('alice', 'id', 'sub', True, 0, 1000, 300, 200, 100)]
        ledger.usage.return_value = (100, 200)
        with self.assertRaises(MeterError): sync_bridge_usage(panel, ledger, 'source', ['alice'], now=100)
        panel.push_global_totals.assert_not_called()
        ledger.invalidate.assert_called_once()
