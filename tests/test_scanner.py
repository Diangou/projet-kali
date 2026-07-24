# tests/test_scanner.py
import unittest

from vuln_scanner.scanner import VulnerabilityScanner
from vuln_scanner.trivy_tool import TrivyTool


class TestVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = VulnerabilityScanner()

    def test_scan(self):
        results = self.scanner.scan('http://example.com')
        self.assertEqual(len(results), 0)

    def test_add_tool(self):
        self.scanner.add_tool(TrivyTool())
        self.assertEqual(len(self.scanner.tools), 1)


if __name__ == '__main__':
    unittest.main()
