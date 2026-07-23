# tests/test_trivy.py
import json
import subprocess
import unittest
from unittest.mock import patch, MagicMock

from vuln_scanner.trivy_tool import TrivyTool


class TestTrivyTool(unittest.TestCase):
    def setUp(self):
        self.tool = TrivyTool()

    @patch('vuln_scanner.trivy_tool.subprocess.run')
    def test_scan_success(self, mock_run):
        payload = {'Results': []}
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(payload), stderr=''
        )

        result = self.tool.scan('alpine:latest')

        self.assertEqual(result, payload)
        mock_run.assert_called_once_with(
            ['trivy', 'image', '--format', 'json', '--quiet', 'alpine:latest'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=self.tool.timeout,
        )

    @patch('vuln_scanner.trivy_tool.subprocess.run')
    def test_scan_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        result = self.tool.scan('alpine:latest')

        self.assertIn('error', result)
        self.assertIn('not installed', result['error'])

    @patch('vuln_scanner.trivy_tool.subprocess.run')
    def test_scan_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='trivy', timeout=120)

        result = self.tool.scan('alpine:latest')

        self.assertIn('error', result)
        self.assertIn('timed out', result['error'])

    @patch('vuln_scanner.trivy_tool.subprocess.run')
    def test_scan_nonzero_exit(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stdout='', stderr='unknown image'
        )

        result = self.tool.scan('bad:target')

        self.assertIn('error', result)
        self.assertIn('unknown image', result['error'])

    @patch('vuln_scanner.trivy_tool.subprocess.run')
    def test_scan_invalid_json(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout='not-json', stderr=''
        )

        result = self.tool.scan('alpine:latest')

        self.assertIn('error', result)
        self.assertIn('parse', result['error'])

    @patch.object(TrivyTool, 'scan')
    def test_get_summary_counts_by_severity(self, mock_scan):
        mock_scan.return_value = {
            'Results': [
                {
                    'Vulnerabilities': [
                        {'Severity': 'CRITICAL'},
                        {'Severity': 'HIGH'},
                        {'Severity': 'HIGH'},
                        {'Severity': 'MEDIUM'},
                        {'Severity': 'LOW'},
                        {'Severity': 'UNKNOWN'},
                    ]
                },
                {},
            ]
        }

        summary = self.tool.get_summary('alpine:latest')

        self.assertEqual(summary, {
            'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 1,
        })

    @patch.object(TrivyTool, 'scan')
    def test_get_summary_no_vulnerabilities(self, mock_scan):
        mock_scan.return_value = {'Results': []}

        summary = self.tool.get_summary('alpine:latest')

        self.assertEqual(summary, {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0,
        })

    @patch.object(TrivyTool, 'scan')
    def test_get_summary_propagates_error(self, mock_scan):
        mock_scan.return_value = {'error': 'trivy is not installed or not found on PATH'}

        summary = self.tool.get_summary('alpine:latest')

        self.assertEqual(summary['error'], 'trivy is not installed or not found on PATH')
        self.assertEqual(summary['CRITICAL'], 0)


if __name__ == '__main__':
    unittest.main()
