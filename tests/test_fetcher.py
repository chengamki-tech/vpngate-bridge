import base64
import csv
import io
import unittest
from vpngate_bridge.fetcher import parse_csv


class FetcherTests(unittest.TestCase):
    def test_dynamic_grouping_and_invalid_rows(self):
        output = io.StringIO()
        output.write('*vpn_servers\n')
        writer = csv.writer(output, lineterminator='\n')
        writer.writerow(['#HostName', 'IP', 'CountryShort', 'Uptime', 'Speed', 'OpenVPN_ConfigData_Base64'])
        encoded = base64.b64encode(b'client\nremote 1.2.3.4 443\n').decode()
        writer.writerow(['a', '1.2.3.4', 'JP', '100', '200', encoded])
        writer.writerow(['b', '2.3.4.5', 'ZZ', '1', '2', encoded])
        writer.writerow(['c', 'bad', 'JP', '1', '2', encoded])
        writer.writerow(['d', '3.4.5.6', '../', '1', '2', encoded])
        writer.writerow(['e', '3.4.5.6', 'US', '1', '2', '%%%'])
        output.write('*\n')
        grouped = parse_csv(output.getvalue())
        self.assertEqual(set(grouped), {'JP', 'ZZ'})
        self.assertEqual(grouped['JP'][0].ip, '1.2.3.4')
        self.assertEqual(grouped['JP'][0].uptime_ms, 100)

    def test_rejects_missing_header_and_unusable_configuration(self):
        with self.assertRaises(ValueError):
            parse_csv('not csv')
        encoded = base64.b64encode(b'client\n').decode()
        data = '#HostName,IP,CountryShort,Uptime,Speed,OpenVPN_ConfigData_Base64\nx,1.2.3.4,US,1,2,' + encoded
        self.assertEqual(parse_csv(data), {})


if __name__ == '__main__':
    unittest.main()
