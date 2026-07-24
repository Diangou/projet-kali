# tests/test_semgrep_tool.py
import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from vuln_scanner.semgrep_tool import SemgrepTool


class TestSemgrepTool(unittest.TestCase):
    def setUp(self):
        self.tool = SemgrepTool()

    @patch('vuln_scanner.semgrep_tool.subprocess.run')
    def test_scan_success(self, mock_run):
        payload = {'results': [], 'errors': []}
        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(payload), stderr='')

        result = self.tool.scan('/tmp/project')

        self.assertEqual(result, payload)
        mock_run.assert_called_once_with(
            ['semgrep', '--config', 'p/ci', '--json', '--quiet', '/tmp/project'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=self.tool.timeout,
        )
        self.assertEqual(
            self.tool.last_command,
            ['semgrep', '--config', 'p/ci', '--json', '--quiet', '/tmp/project'],
        )

    @patch('vuln_scanner.semgrep_tool.subprocess.run')
    def test_scan_findings_return_code_1_is_not_an_error(self, mock_run):
        payload = {'results': [{'check_id': 'x'}]}
        mock_run.return_value = MagicMock(returncode=1, stdout=json.dumps(payload), stderr='')

        result = self.tool.scan('/tmp/project')

        self.assertEqual(result, payload)

    @patch('vuln_scanner.semgrep_tool.subprocess.run')
    def test_scan_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        result = self.tool.scan('/tmp/project')

        self.assertIn('error', result)
        self.assertIn('not installed', result['error'])

    @patch('vuln_scanner.semgrep_tool.subprocess.run')
    def test_scan_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='semgrep', timeout=180)

        result = self.tool.scan('/tmp/project')

        self.assertIn('error', result)
        self.assertIn('timed out', result['error'])

    @patch('vuln_scanner.semgrep_tool.subprocess.run')
    def test_scan_real_error_exit_code(self, mock_run):
        mock_run.return_value = MagicMock(returncode=2, stdout='', stderr='invalid config')

        result = self.tool.scan('/tmp/project')

        self.assertIn('error', result)
        self.assertIn('invalid config', result['error'])


if __name__ == '__main__':
    unittest.main()
