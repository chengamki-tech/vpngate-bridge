import tempfile
import unittest
from pathlib import Path
from vpngate_bridge.meter import CounterLedger, MeterError


class MeterTests(unittest.TestCase):
    def test_cumulative_samples_are_idempotent_and_crashes_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'meter.sqlite'
            ledger = CounterLedger(path)
            ledger.begin('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', ['alice'])
            self.assertIsNone(ledger.usage('alice', now=100))
            ledger.record('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', {'alice': (100, 200)}, now=100)
            ledger.record('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', {'alice': (100, 200)}, now=101)
            self.assertEqual(ledger.usage('alice', now=101), (100, 200))
            self.assertIsNone(ledger.usage('alice', now=132))
            ledger.close('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', {'alice': (150, 250)}, now=102, quiesced=True)
            self.assertIsNone(ledger.usage('alice', now=102))
            ledger.begin('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', ['alice'])
            ledger.record('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', {'alice': (10, 20)}, now=103)
            self.assertEqual(ledger.usage('alice', now=103), (160, 270))
            with self.assertRaises(MeterError):
                CounterLedger(path).begin('cccccccc-cccc-4ccc-8ccc-cccccccccccc', ['alice'])
            self.assertIsNone(CounterLedger(path).usage('alice', now=103))

    def test_missing_or_decreasing_counters_disable_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = CounterLedger(Path(directory) / 'meter.sqlite')
            epoch = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
            ledger.begin(epoch, ['alice'])
            ledger.record(epoch, {'alice': (100, 200)}, now=100)
            with self.assertRaises(MeterError): ledger.record(epoch, {}, now=101)
            self.assertIsNone(ledger.usage('alice', now=101))
            ledger.record(epoch, {'alice': (110, 210)}, now=102)
            self.assertEqual(ledger.usage('alice', now=102), (110, 210))
            with self.assertRaises(MeterError): ledger.record(epoch, {'alice': (1, 2)}, now=103)
            self.assertIsNone(ledger.usage('alice', now=103))
            with self.assertRaises(MeterError): ledger.record(epoch, {'alice': (120, 220)}, now=104)
