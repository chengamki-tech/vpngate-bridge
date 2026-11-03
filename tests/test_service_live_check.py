import unittest

from gateway.service_live_check import ordered_batches
from vpngate_bridge.fetcher import Candidate


def candidate(ip, country, speed, uptime):
    return Candidate(ip, country, uptime, speed, 'fixture')


class OrderedBatchTests(unittest.TestCase):
    def test_orders_by_speed_then_uptime_then_ip_and_batches(self):
        grouped = {
            'JP': [
                candidate('10.0.0.3', 'JP', 100, 10),
                candidate('10.0.0.1', 'JP', 300, 5),
                candidate('10.0.0.2', 'JP', 300, 9),
            ],
            'KR': [candidate('10.0.1.1', 'KR', 999, 99)],
        }
        batches = ordered_batches(grouped, batch_size=2, max_batches=6, max_batches_per_country=3)
        # JP is larger, so it comes first even though KR has a faster candidate.
        self.assertEqual([country for country, _ in batches], ['JP', 'JP', 'KR'])
        self.assertEqual([c.ip for _, batch in batches for c in batch],
                         ['10.0.0.2', '10.0.0.1', '10.0.0.3', '10.0.1.1'])

    def test_caps_batches_per_country_then_total(self):
        grouped = {
            'JP': [candidate(f'10.0.0.{i}', 'JP', 100, 1) for i in range(1, 40)],
            'US': [candidate(f'10.0.1.{i}', 'US', 100, 1) for i in range(1, 40)],
        }
        batches = ordered_batches(grouped, batch_size=8, max_batches=6, max_batches_per_country=3)
        self.assertEqual(len(batches), 6)
        self.assertEqual([country for country, _ in batches],
                         ['JP', 'JP', 'JP', 'US', 'US', 'US'])
        self.assertTrue(all(len(batch) == 8 for _, batch in batches))

    def test_empty_grouping_and_invalid_limits(self):
        self.assertEqual(ordered_batches({}), [])
        with self.assertRaises(ValueError):
            ordered_batches({}, batch_size=0)


if __name__ == '__main__':
    unittest.main()
