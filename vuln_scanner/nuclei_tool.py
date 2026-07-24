# vuln_scanner/nuclei_tool.py
import json
import shutil
import subprocess
from urllib.parse import urlsplit, urlunsplit

from .tool import Tool


def _normalize_localhost(target):
    """nuclei's Go resolver sometimes fails to resolve the literal host
    'localhost' on Windows ("no address found for host") even though the
    OS itself resolves it fine — every request in the scan then errors out
    silently, reporting a false "0 findings". 127.0.0.1 sidesteps it.
    """
    parts = urlsplit(target)

    if parts.hostname != 'localhost':
        return target

    netloc = '127.0.0.1'

    if parts.port:
        netloc += ':{}'.format(parts.port)

    if '@' in parts.netloc:
        netloc = '{}@{}'.format(parts.netloc.split('@', 1)[0], netloc)

    return urlunsplit(parts._replace(netloc=netloc))


class NucleiTool(Tool):
    executable = 'nuclei'

    def __init__(self, timeout=300, severity=None):
        super().__init__('nuclei')
        self.timeout = timeout
        self.severity = severity
        self.last_command = None

    def is_available(self):
        return shutil.which(self.executable) is not None

    def scan(self, target):
        command = [
            self.executable,
            '-u', _normalize_localhost(target),
            '-jsonl',
            '-silent',
            '-no-color',
        ]

        if self.severity:
            command.extend(['-severity', self.severity])

        self.last_command = command

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=self.timeout,
            )
        except FileNotFoundError:
            return {'error': 'nuclei is not installed or not found on PATH'}
        except subprocess.TimeoutExpired:
            return {'error': 'nuclei scan timed out after {}s'.format(self.timeout)}

        if process.returncode != 0 and not process.stdout.strip():
            return {'error': 'nuclei exited with code {}: {}'.format(
                process.returncode, process.stderr.strip()
            )}

        findings = []

        for line in process.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                findings.append(json.loads(line))
            except ValueError:
                continue

        return findings
