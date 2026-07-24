# vuln_scanner/semgrep_tool.py
import json
import shutil
import subprocess

from .tool import Tool


class SemgrepTool(Tool):
    """Runs semgrep against a local source path and returns parsed JSON.

    Semgrep performs static analysis on source code, not on a live URL —
    it needs a checked-out path. Kept separate from the legacy
    `run_semgrep()` helper in semgrep.py, which existing tests pin to a
    plain (non-JSON) invocation.
    """

    executable = 'semgrep'

    def __init__(self, timeout=180, config='p/ci'):
        super().__init__('semgrep')
        self.timeout = timeout
        self.config = config
        self.last_command = None

    def is_available(self):
        return shutil.which(self.executable) is not None

    def scan(self, path):
        command = [self.executable, '--config', self.config, '--json', '--quiet', path]
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
            return {'error': 'semgrep is not installed or not found on PATH'}
        except subprocess.TimeoutExpired:
            return {'error': 'semgrep scan timed out after {}s'.format(self.timeout)}

        if process.returncode not in (0, 1):
            return {'error': 'semgrep exited with code {}: {}'.format(
                process.returncode, process.stderr.strip()
            )}

        try:
            return json.loads(process.stdout)
        except ValueError:
            return {'error': 'failed to parse semgrep JSON output'}
