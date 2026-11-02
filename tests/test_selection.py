import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from vpngate_bridge.selection import Blacklist, Measurement, choose, score


class SelectionTests(unittest.TestCase):
    def test_scoring_and_hard_rejections(self):
        good = Measurement('JP', 'JP', '8.8.8.8', False, (100, 200, 300), 50_000_000, 604_800_000)
        self.assertAlmostEqual(score(good), 0.30 * .8 + .30 * .5 + .25 + .15)
        for bad in (replace(good, country='US'), replace(good, hosting=True), replace(good, hosting=None), replace(good, latencies_ms=(100, 200, 10001)), replace(good, latencies_ms=(100, 200)), replace(good, exit_ip='127.0.0.1')):
            with self.subTest(bad=bad):
                self.assertIsNone(score(bad))

    def test_highest_per_country_and_unique_exit(self):
        a = Measurement('JP', 'JP', '8.8.8.8', False, (100, 100, 100), 100_000_000, 604_800_000)
        b = replace(a, expected_country='US', country='US', latencies_ms=(200, 200, 200))
        c = replace(b, exit_ip='1.1.1.1', latencies_ms=(300, 300, 300))
        self.assertEqual(choose([c, b, a], ()), {'JP': a, 'US': c})
        self.assertEqual(choose([a, c], ('8.8.8.0/24',)), {'US': c})

    def test_blacklist_survives_restart_and_expires(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'blacklist.sqlite'
            Blacklist(path).add('8.8.8.8', 'failed', 100, ttl=60)
            self.assertEqual(Blacklist(path).active(159), ['8.8.8.0/24'])
            self.assertEqual(Blacklist(path).active(160), [])
