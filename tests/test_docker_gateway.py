import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from vpngate_bridge.docker_gateway import DockerGateway


class DockerGatewayTests(unittest.TestCase):
    def test_lifecycle_cleans_up_on_downstream_error(self):
        fake_connection = MagicMock()
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[0] == 'network': return 'bridge'
            if args[0] == 'inspect' and 'IPAddress' in args[2]: return '172.18.0.2'
            if args[0] == 'inspect': return args[-1]
            return ''
        with patch('vpngate_bridge.docker_gateway._docker', side_effect=docker), patch('vpngate_bridge.docker_gateway.safe_config'), patch('vpngate_bridge.docker_gateway.socket.create_connection', return_value=fake_connection):
            gateway = DockerGateway('private-net')
            with self.assertRaisesRegex(OSError, 'probe broke'):
                with gateway.open(SimpleNamespace(ip='8.8.8.8', config='client')) as address:
                    self.assertEqual(address, '172.18.0.2:1080')
                    raise OSError('probe broke')
        self.assertEqual(sum(call[0] == 'rm' for call in calls), 1)
        args = next(call for call in calls if call[0] == 'run')
        self.assertNotIn('-p', args)
        self.assertIn('--pids-limit', args)

    def test_unsafe_candidate_is_rejected_without_starting_container(self):
        from vpngate_bridge.probe import ProbeError
        with patch('vpngate_bridge.docker_gateway._docker', return_value='bridge') as docker, patch('vpngate_bridge.docker_gateway.safe_config', side_effect=ValueError('bad configuration')):
            gateway = DockerGateway('private-net')
            with self.assertRaises(ProbeError):
                with gateway.open(SimpleNamespace(ip='8.8.8.8', config='invalid')):
                    pass
        self.assertEqual(docker.call_count, 1)
