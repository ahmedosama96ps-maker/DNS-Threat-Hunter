import json
import tempfile
import unittest
from pathlib import Path

from dns_hunter import detect, parse_logs


class DetectionTests(unittest.TestCase):
    def test_nxdomain_burst(self):
        events = [
            {"ts": "100.0", "id.orig_h": "192.0.2.1", "query": f"fake{i}.invalid", "rcode_name": "NXDOMAIN"}
            for i in range(12)
        ]
        self.assertTrue(any(a["type"] == "nxdomain_burst" for a in detect(events)))

    def test_no_burst_for_repeated_query(self):
        events = [
            {"ts": "100.0", "id.orig_h": "192.0.2.1", "query": "same.invalid", "rcode_name": "NXDOMAIN"}
            for _ in range(25)
        ]
        self.assertFalse(any(a["type"] == "nxdomain_burst" for a in detect(events)))

    def test_long_label(self):
        events = [{"ts": 100, "id.orig_h": "192.0.2.1", "query": "a" * 50 + ".test.invalid"}]
        self.assertTrue(any(a["type"] == "long_dns_label" for a in detect(events)))

    def test_multi_a_and_low_ttl(self):
        events = [{"ts": 100, "query": "flux.invalid", "answers": ["192.0.2.1", "192.0.2.2", "192.0.2.3"], "TTLs": [30, 30, 30]}]
        self.assertTrue(any(a["type"] == "multi_a_low_ttl" for a in detect(events)))

    def test_json_line_input(self):
        record = {"ts": "100", "query": "test.invalid", "rcode_name": "NXDOMAIN"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dns.log"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertEqual(list(parse_logs(path))[0]["query"], "test.invalid")

    def test_zeek_tsv_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dns.log"
            path.write_text("#separator \\x09\n#fields\tts\tid.orig_h\tquery\trcode_name\n100\t192.0.2.1\tfoo.invalid\tNXDOMAIN\n", encoding="utf-8")
            self.assertEqual(list(parse_logs(path))[0]["query"], "foo.invalid")


if __name__ == "__main__":
    unittest.main()
