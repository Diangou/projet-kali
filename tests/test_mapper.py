# tests/test_mapper.py
import unittest

from vuln_scanner.nmap_tool import NmapHost, NmapPort, NmapScanResult, NmapService
from vuln_scanner.utils.mapper import (
    nmap_to_vulnerabilities,
    nuclei_to_vulnerabilities,
    semgrep_to_vulnerabilities,
    trivy_to_vulnerabilities,
)
from vuln_scanner.utils.models import Vulnerability


class TestTrivyMapper(unittest.TestCase):
    def test_maps_vulnerabilities(self):
        raw = {
            'Results': [
                {
                    'Target': 'alpine:latest',
                    'Vulnerabilities': [
                        {
                            'VulnerabilityID': 'CVE-2021-1',
                            'Title': 'openssl issue',
                            'Severity': 'HIGH',
                            'PkgName': 'openssl',
                            'FixedVersion': '1.2.3',
                            'References': ['https://example.com/cve'],
                            'CVSS': {'nvd': {'V3Score': 7.5}},
                        }
                    ],
                }
            ]
        }

        result = trivy_to_vulnerabilities(raw)

        self.assertEqual(len(result), 1)
        vuln = result[0]
        self.assertIsInstance(vuln, Vulnerability)
        self.assertEqual(vuln.tool, 'trivy')
        self.assertEqual(vuln.severity, 'high')
        self.assertEqual(vuln.cve, 'CVE-2021-1')
        self.assertEqual(vuln.target, 'alpine:latest')
        self.assertEqual(vuln.location, 'openssl')
        self.assertEqual(vuln.cvss, 7.5)
        self.assertEqual(vuln.recommendation, 'Upgrade to 1.2.3')

    def test_missing_results_key_returns_empty(self):
        self.assertEqual(trivy_to_vulnerabilities({'error': 'boom'}), [])
        self.assertEqual(trivy_to_vulnerabilities({}), [])


class TestNmapMapper(unittest.TestCase):
    def test_maps_open_ports_only(self):
        host = NmapHost(
            address='10.0.0.1',
            address_type='ipv4',
            status='up',
            ports=[
                NmapPort(
                    port=22, protocol='tcp', state='open', reason='syn-ack',
                    service=NmapService(name='ssh', product='OpenSSH', version='8.2'),
                ),
                NmapPort(
                    port=81, protocol='tcp', state='closed', reason='reset',
                    service=NmapService(),
                ),
            ],
        )
        scan_result = NmapScanResult(tool='nmap', target='10.0.0.1', success=True, hosts=[host])

        result = nmap_to_vulnerabilities(scan_result)

        self.assertEqual(len(result), 1)
        vuln = result[0]
        self.assertEqual(vuln.tool, 'nmap')
        self.assertEqual(vuln.severity, 'info')
        self.assertEqual(vuln.location, '10.0.0.1:22')
        self.assertIn('22/tcp open', vuln.title)


class TestSemgrepMapper(unittest.TestCase):
    def test_maps_results(self):
        raw = {
            'results': [
                {
                    'check_id': 'python.lang.security.audit.foo',
                    'path': 'app.py',
                    'start': {'line': 10},
                    'extra': {
                        'message': 'insecure use of eval',
                        'severity': 'ERROR',
                        'metadata': {
                            'description': 'do not use eval',
                            'references': ['https://example.com'],
                        },
                        'fix': 'use ast.literal_eval',
                    },
                }
            ]
        }

        result = semgrep_to_vulnerabilities(raw)

        self.assertEqual(len(result), 1)
        vuln = result[0]
        self.assertEqual(vuln.severity, 'high')
        self.assertEqual(vuln.location, 'app.py:10')
        self.assertEqual(vuln.recommendation, 'use ast.literal_eval')


class TestNucleiMapper(unittest.TestCase):
    def test_maps_findings(self):
        findings = [
            {
                'template-id': 'exposed-git-config',
                'info': {
                    'name': 'Exposed .git',
                    'severity': 'high',
                    'description': 'git config exposed',
                    'reference': ['https://example.com'],
                    'classification': {'cve-id': ['CVE-2020-1']},
                },
                'host': 'https://target.test',
                'matched-at': 'https://target.test/.git/config',
            }
        ]

        result = nuclei_to_vulnerabilities(findings)

        self.assertEqual(len(result), 1)
        vuln = result[0]
        self.assertEqual(vuln.severity, 'high')
        self.assertEqual(vuln.cve, 'CVE-2020-1')
        self.assertEqual(vuln.location, 'https://target.test/.git/config')


if __name__ == '__main__':
    unittest.main()
