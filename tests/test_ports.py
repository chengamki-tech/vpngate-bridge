import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from vpngate_bridge.ports import PortRegistry


class PortRegistryTests(unittest.TestCase):
    def test_persists_assignments_and_avoids_reserved_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.sqlite'
            registry = PortRegistry(path, 20000, 20010, {20000})
            self.assertEqual(registry.assign('JP'), (20001, 20002))
            self.assertEqual(PortRegistry(path, 20000, 20010, {20000}).assign('JP'), (20001, 20002))
            self.assertEqual(registry.assign('US'), (20003, 20004))
            with self.assertRaises(ValueError): registry.assign('../')
            with self.assertRaises(ValueError): PortRegistry(path, 20000, 20010, {20001}).assign('JP')

    def test_concurrent_assignments_do_not_collide_and_exhaustion_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.sqlite'
            registry = PortRegistry(path, 21000, 21003, set())
            with ThreadPoolExecutor(max_workers=2) as pool:
                ports = list(pool.map(registry.assign, ['JP', 'US']))
            self.assertEqual(len(set(ports[0] + ports[1])), 4)
            with self.assertRaises(RuntimeError): registry.assign('GB')
