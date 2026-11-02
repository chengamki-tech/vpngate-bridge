import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock
from vpngate_bridge.collector import read_counters, collect
from vpngate_bridge.meter import MeterError


class CollectorTests(unittest.TestCase):
    def test_reads_cumulative_counters_and_rejects_bad_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            proto = Path(directory) / 'stats.proto'
            proto.touch()
            rows = [{'name': 'user>>>alice>>>traffic>>>uplink', 'value': '123'}]
            with patch('vpngate_bridge.collector.subprocess.run', return_value=SimpleNamespace(stdout=json.dumps({'stat': rows}))) as run:
                self.assertEqual(read_counters('127.0.0.1:10085', proto, ['alice']), {'alice': (123, 0)})
                self.assertIn('"reset":false', str(run.call_args))
            for invalid in [rows + rows, [{'name': rows[0]['name'], 'value': '-1'}], [{'name': 'user>>>bob>>>traffic>>>uplink', 'value': '1'}]]:
                with patch('vpngate_bridge.collector.subprocess.run', return_value=SimpleNamespace(stdout=json.dumps({'stat': invalid}))):
                    with self.assertRaises(MeterError): read_counters('127.0.0.1:10085', proto, ['alice'])
    def test_process_change_invalidates_ledger(self):
        ledger = Mock()
        with patch('vpngate_bridge.collector.read_counters', return_value={'alice': (1, 2)}):
            with self.assertRaises(MeterError): collect(ledger, 'epoch', '127.0.0.1:1', 'stats.proto', ['alice'], Mock(side_effect=['epoch', 'changed']))
        ledger.invalidate.assert_called_once()
        ledger.record.assert_not_called()
