"""Unit tests for Simple Port Scanner."""

import json
import os
import tempfile
import unittest

import portscan


class TestPortParser(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(portscan.parse_ports("80"), [80])

    def test_comma_separated_ports(self):
        self.assertEqual(portscan.parse_ports("22, 80, 443"), [22, 80, 443])

    def test_port_range(self):
        self.assertEqual(portscan.parse_ports("8080-8083"), [8080, 8081, 8082, 8083])

    def test_combined_syntax(self):
        self.assertEqual(portscan.parse_ports("22, 80-82, 443"), [22, 80, 81, 82, 443])

    def test_deduplication_and_sorting(self):
        self.assertEqual(portscan.parse_ports("443, 80, 80, 22"), [22, 80, 443])

    def test_invalid_range_inverted(self):
        with self.assertRaises(ValueError):
            portscan.parse_ports("100-50")

    def test_invalid_port_number(self):
        with self.assertRaises(ValueError):
            portscan.parse_ports("0")
        with self.assertRaises(ValueError):
            portscan.parse_ports("70000")


class TestTargetExpansion(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(portscan.expand_target("192.168.1.1"), ["192.168.1.1"])

    def test_hostname(self):
        self.assertEqual(portscan.expand_target("example.com"), ["example.com"])

    def test_cidr_expansion(self):
        # /30 yields 2 usable host addresses (.1 and .2)
        hosts = portscan.expand_target("192.168.1.0/30")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_ip_range_expansion(self):
        hosts = portscan.expand_target("10.0.0.1-10.0.0.3")
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_ip_range_suffix(self):
        hosts = portscan.expand_target("10.0.0.1-3")
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_load_targets_file(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
            tmp.write("# Comment line\n")
            tmp.write("192.168.1.10\n\n")
            tmp.write("example.com\n")
            tmp_path = tmp.name

        try:
            loaded = portscan.load_targets([], targets_file=tmp_path)
            self.assertEqual(loaded, ["192.168.1.10", "example.com"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestExport(unittest.TestCase):
    def setUp(self):
        portscan.Colors.disable()
        self.sample_results = [
            portscan.ScanResult(
                host="127.0.0.1",
                ip="127.0.0.1",
                port=80,
                is_open=True,
                elapsed_ms=1.2,
                reason="connected",
                service="http",
                banner="Apache/2.4.52",
            ),
            portscan.ScanResult(
                host="127.0.0.1",
                ip="127.0.0.1",
                port=443,
                is_open=False,
                elapsed_ms=0.5,
                reason="refused",
                service="https",
            ),
        ]

    def test_json_export(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
            tmp_path = tmp.name

        try:
            portscan.export_results(self.sample_results, tmp_path, fmt="json", show_banner=True)
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(len(data), 2)
            self.assertEqual(data[0]["port"], 80)
            self.assertEqual(data[0]["state"], "open")
            self.assertEqual(data[0]["banner"], "Apache/2.4.52")
            self.assertEqual(data[1]["state"], "closed")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_csv_export(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".csv") as tmp:
            tmp_path = tmp.name

        try:
            portscan.export_results(self.sample_results, tmp_path, fmt="csv", show_banner=True)
            with open(tmp_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertIn("host,ip,port,state,service,elapsed_ms,reason,banner\n", lines[0])
            self.assertIn("127.0.0.1,127.0.0.1,80,open,http", lines[1])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
