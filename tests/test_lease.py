import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from vpngate_bridge.lease import renew, valid, supervise


class LeaseTests(unittest.TestCase):
    def test_expiry_terminates_real_process_and_invalid_lease_cannot_start(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            identity = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
            renew(path, identity, duration=.4)
            self.assertTrue(valid(path, identity))
            pidfile = Path(directory) / 'pid'
            code = 'import os,time,pathlib; pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid())); time.sleep(30)'
            started = time.monotonic()
            self.assertEqual(supervise(path, identity, [sys.executable, '-c', code]), 1)
            self.assertLess(time.monotonic() - started, 4)
            pid = int(pidfile.read_text())
            with self.assertRaises(ProcessLookupError): os.kill(pid, 0)
            with patch('vpngate_bridge.lease.subprocess.Popen') as launch:
                with self.assertRaises(RuntimeError): supervise(path, identity, ['unused'])
                launch.assert_not_called()
    def test_wrong_generation_and_invalid_duration_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            renew(path, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
            self.assertFalse(valid(path, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'))
            with self.assertRaises(ValueError): renew(path, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', duration=31)
