import json
import tempfile
import unittest
from pathlib import Path

from vpngate_bridge.final_stats import read_final
from vpngate_bridge.meter import CounterLedger, MeterError


RUN = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
NEXT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'


class FinalStatsTests(unittest.TestCase):
    def test_final_snapshot_closes_only_the_matching_epoch_and_preserves_cumulative_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'final.json'
            path.write_text(json.dumps({'version': 1, 'run_id': RUN, 'counters': {'alice': [15, 40]}}))
            ledger = CounterLedger(root / 'meter.sqlite')
            ledger.begin(RUN, ['alice'])
            ledger.record(RUN, {'alice': (12, 34)}, now=100)
            with self.assertRaises(MeterError):
                ledger.closed_totals(RUN)
            ledger.close(RUN, read_final(path, RUN, ['alice']), now=101, quiesced=True)
            self.assertIsNone(ledger.usage('alice', now=101), 'final counters must never authorize closed traffic')
            self.assertEqual(ledger.closed_totals(RUN), {'alice': (15, 40)})
            with self.assertRaises(MeterError):
                ledger.closed_totals(NEXT)
            ledger.begin(NEXT, ['alice'])
            ledger.record(NEXT, {'alice': (2, 3)}, now=102)
            self.assertEqual(ledger.usage('alice', now=102), (17, 43))

    def test_invalid_generation_roster_or_counter_never_becomes_a_final_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'final.json'
            cases = [
                {'version': 1, 'run_id': NEXT, 'counters': {'alice': [1, 2]}},
                {'version': True, 'run_id': RUN, 'counters': {'alice': [1, 2]}},
                {'version': 1, 'run_id': RUN, 'counters': {'unknown': [1, 2]}},
                {'version': 1, 'run_id': RUN, 'counters': {'alice': [-1, 2]}},
                {'version': 1, 'run_id': RUN, 'counters': {'alice': [True, 2]}},
                {'version': 1, 'run_id': RUN, 'counters': {'alice': [2**63, 2]}},
            ]
            for data in cases:
                with self.subTest(data=data):
                    path.write_text(json.dumps(data))
                    with self.assertRaises(MeterError):
                        read_final(path, RUN, ['alice'])
            for data in ('{', 'x' * 2048,
                         '{"version":1,"run_id":"' + RUN + '","counters":{"alice":[1,2],"alice":[0,0]}}'):
                path.write_text(data)
                with self.assertRaises(MeterError):
                    read_final(path, RUN, ['alice'])
            path.unlink()
            with self.assertRaises(MeterError):
                read_final(path, RUN, ['alice'])

    def test_regressing_final_snapshot_keeps_the_ledger_uncertain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'final.json'
            path.write_text(json.dumps({'version': 1, 'run_id': RUN, 'counters': {'alice': [1, 2]}}))
            ledger = CounterLedger(root / 'meter.sqlite')
            ledger.begin(RUN, ['alice'])
            ledger.record(RUN, {'alice': (10, 20)}, now=100)
            with self.assertRaises(MeterError):
                ledger.close(RUN, read_final(path, RUN, ['alice']), now=101, quiesced=True)
            with self.assertRaises(MeterError):
                ledger.begin(NEXT, ['alice'])
