# vuln_scanner/trivy_tool.py
import json
import subprocess

from .tool import Tool


class TrivyTool(Tool):
    def __init__(self, timeout=120):
        super().__init__('trivy')
        self.timeout = timeout

    def scan(self, target):
        try:
            process = subprocess.run(
                ['trivy', 'image', '--format', 'json', '--quiet', target],
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=self.timeout,
            )
        except FileNotFoundError:
            return {'error': 'trivy is not installed or not found on PATH'}
        except subprocess.TimeoutExpired:
            return {'error': 'trivy scan timed out after {}s'.format(self.timeout)}

        if process.returncode != 0:
            return {'error': 'trivy exited with code {}: {}'.format(
                process.returncode, process.stderr.strip()
            )}

        try:
            return json.loads(process.stdout)
        except ValueError:
            return {'error': 'failed to parse trivy JSON output'}

    def get_summary(self, target):
        results = self.scan(target)
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        if not isinstance(results, dict) or 'error' in results:
            summary['error'] = results.get('error', 'unknown error')
            return summary

        for item in results.get('Results') or []:
            for vuln in item.get('Vulnerabilities') or []:
                severity = vuln.get('Severity')
                if severity in summary:
                    summary[severity] += 1

        return summary
