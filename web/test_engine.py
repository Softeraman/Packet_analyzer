"""End-to-end native engine checks, also run during the container build."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from server import ENGINE, ROOT, validate_pcap

class EngineTests(unittest.TestCase):
    def analyze(self, ip='', app='', domain=''):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'report.json'
            subprocess.run([ENGINE, str(ROOT/'test_dpi.pcap'), str(out), ip, app, domain],
                           check=True, timeout=20, stdout=subprocess.DEVNULL)
            return json.loads(out.read_text())

    def test_sample_and_packet_accounting(self):
        validate_pcap((ROOT/'test_dpi.pcap').read_bytes())
        report = self.analyze()
        self.assertGreater(report['totalPackets'], 20)
        self.assertEqual(report['totalPackets'], report['analyzedPackets'] + report['skippedPackets'])
        self.assertEqual(report['allowedPackets'], report['analyzedPackets'])
        self.assertEqual(report['blockedPackets'], 0)
        self.assertTrue(any(f['application']=='YouTube' and f['hostname'] for f in report['flows']))

    def test_application_domain_and_address_rules(self):
        for kwargs in ({'app':'YouTube'}, {'domain':'youtube'}, {'ip':'192.168.1.50'}):
            with self.subTest(kwargs=kwargs):
                report = self.analyze(**kwargs)
                self.assertGreater(report['blockedPackets'], 0)
                self.assertEqual(report['analyzedPackets'], report['allowedPackets']+report['blockedPackets'])
                self.assertTrue(any(f['blocked'] for f in report['flows']))

    def test_invalid_and_truncated_capture(self):
        for data in (b'not a capture', (ROOT/'test_dpi.pcap').read_bytes()[:-3]):
            with self.assertRaises(ValueError): validate_pcap(data)

if __name__=='__main__': unittest.main()
