# tests/test_nuclei_tool.py
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from vuln_scanner.nuclei_tool import NucleiTool, _normalize_localhost


class TestNucleiTool(unittest.TestCase):
    def setUp(self):
        self.tool = NucleiTool()

    @patch('vuln_scanner.nuclei_tool.subprocess.run')
    def test_scan_parses_jsonl(self, mock_run):
        stdout = (
            '{"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info"}, "host": "http://x"}\n'
            '{"template-id": "exposed-panel", "info": {"name": "Panel", "severity": "high"}, "host": "http://x"}\n'
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr='')

        result = self.tool.scan('http://x')

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['template-id'], 'tech-detect')
        mock_run.assert_called_once_with(
            ['nuclei', '-u', 'http://x', '-jsonl', '-silent', '-no-color'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=self.tool.timeout,
        )
        self.assertEqual(
            self.tool.last_command,
            ['nuclei', '-u', 'http://x', '-jsonl', '-silent', '-no-color'],
        )

    @patch('vuln_scanner.nuclei_tool.subprocess.run')
    def test_scan_with_severity_filter(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        tool = NucleiTool(severity='critical,high')

        tool.scan('http://x')

        mock_run.assert_called_once_with(
            ['nuclei', '-u', 'http://x', '-jsonl', '-silent', '-no-color', '-severity', 'critical,high'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=tool.timeout,
        )

    @patch('vuln_scanner.nuclei_tool.subprocess.run')
    def test_scan_ignores_malformed_lines(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout='not-json\n{"template-id": "a", "info": {}}\n', stderr=''
        )

        result = self.tool.scan('http://x')

        self.assertEqual(len(result), 1)

    @patch('vuln_scanner.nuclei_tool.subprocess.run')
    def test_scan_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        result = self.tool.scan('http://x')

        self.assertIn('error', result)
        self.assertIn('not installed', result['error'])

    @patch('vuln_scanner.nuclei_tool.subprocess.run')
    def test_scan_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='nuclei', timeout=300)

        result = self.tool.scan('http://x')

        self.assertIn('error', result)
        self.assertIn('timed out', result['error'])

    @patch('vuln_scanner.nuclei_tool.subprocess.run')
    def test_scan_nonzero_exit_without_output_is_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout='', stderr='connection refused')

        result = self.tool.scan('http://x')

        self.assertIn('error', result)
        self.assertIn('connection refused', result['error'])

    def test_is_available_reflects_path(self):
        self.assertIsInstance(self.tool.is_available(), bool)

    @patch('vuln_scanner.nuclei_tool.subprocess.run')
    def test_scan_rewrites_localhost_to_loopback_ip(self, mock_run):
        # nuclei's Go resolver can fail on the literal host "localhost" on
        # Windows even though the OS resolves it fine — see _normalize_localhost.
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')

        self.tool.scan('http://localhost:3000')

        args = mock_run.call_args[0][0]
        self.assertIn('http://127.0.0.1:3000', args)
        self.assertNotIn('http://localhost:3000', args)


class TestNormalizeLocalhost(unittest.TestCase):
    def test_rewrites_bare_localhost(self):
        self.assertEqual(_normalize_localhost('http://localhost'), 'http://127.0.0.1')

    def test_preserves_port(self):
        self.assertEqual(_normalize_localhost('http://localhost:3000'), 'http://127.0.0.1:3000')

    def test_preserves_path_and_scheme(self):
        self.assertEqual(
            _normalize_localhost('https://localhost:8443/admin?x=1'),
            'https://127.0.0.1:8443/admin?x=1',
        )

    def test_leaves_other_hosts_untouched(self):
        self.assertEqual(_normalize_localhost('http://example.com'), 'http://example.com')
        self.assertEqual(_normalize_localhost('http://127.0.0.1:3000'), 'http://127.0.0.1:3000')
        self.assertEqual(_normalize_localhost('http://sub.localhost.dev'), 'http://sub.localhost.dev')


if __name__ == '__main__':
    unittest.main()
