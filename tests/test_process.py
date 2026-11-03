import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from vpngate_bridge.process import docker_epoch
from vpngate_bridge.meter import MeterError


class ProcessTests(unittest.TestCase):
    def test_restarts_change_epoch_and_inactive_states_are_rejected(self):
        state = {'Running': True, 'Paused': False, 'Restarting': False, 'Pid': 123, 'StartedAt': '2026-11-02T01:00:00.123Z'}
        def response(): return SimpleNamespace(stdout=json.dumps(state))
        with patch('vpngate_bridge.process.subprocess.run', side_effect=lambda *a, **k: response()):
            first = docker_epoch('a' * 64)
            self.assertEqual(docker_epoch('a' * 64), first)
            state['StartedAt'] = '2026-11-02T02:00:00.123Z'
            self.assertNotEqual(docker_epoch('a' * 64), first)
            state['Running'] = False
            with self.assertRaises(MeterError): docker_epoch('a' * 64)
            state.update(Pid=0, OOMKilled=False, Dead=False, ExitCode=143)
            stopped = docker_epoch('a' * 64, stopped=True)
            state['ExitCode'] = 137
            with self.assertRaises(MeterError): docker_epoch('a' * 64, stopped=True)
            state.update(ExitCode=1, OOMKilled=True)
            with self.assertRaises(MeterError): docker_epoch('a' * 64, stopped=True)
            state['OOMKilled'] = False
            self.assertEqual(docker_epoch('a' * 64, stopped=True), stopped)
        with self.assertRaises(ValueError): docker_epoch('mutable-name')
