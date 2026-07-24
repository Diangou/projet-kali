# vuln_scanner/scan_manager.py
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from .nmap_tool import NmapTool
from .nuclei_tool import NucleiTool
from .semgrep_tool import SemgrepTool
from .trivy_tool import TrivyTool
from .utils.mapper import MAPPERS

ENGINES = {
    'trivy': {
        'label': 'Trivy',
        'description': 'Container image & dependency vulnerability scan.',
        'executable': 'trivy',
        'expects': 'a container image reference, e.g. ghcr.io/org/app:tag',
    },
    'nmap': {
        'label': 'Nmap',
        'description': 'Network discovery and open service enumeration.',
        'executable': 'nmap',
        'expects': 'the target host — extracted automatically from the URL',
    },
    'nuclei': {
        'label': 'Nuclei',
        'description': 'Template-based detection for known CVEs & misconfigurations.',
        'executable': 'nuclei',
        'expects': 'the full target URL',
    },
    'semgrep': {
        'label': 'Semgrep',
        'description': 'Static analysis of source code, when available.',
        'executable': 'semgrep',
        'expects': 'a local source path or a git repository URL (optional — skipped without one)',
    },
}

TERMINAL_STATUSES = {'done', 'error'}


def engine_available(name):
    return shutil.which(ENGINES[name]['executable']) is not None


def engines_status():
    return {
        name: {**meta, 'available': engine_available(name)}
        for name, meta in ENGINES.items()
    }


def _now():
    return datetime.now(timezone.utc).isoformat()


def _extract_host(target):
    if '://' in target:
        return urlparse(target).hostname or target
    return urlparse('//' + target).hostname or target


GIT_URL_RE = re.compile(r'^(https?://|git@|git://|ssh://)', re.IGNORECASE)


def _is_git_url(value):
    return bool(GIT_URL_RE.match(value or ''))


class ScanManager:
    """In-memory scan orchestrator: one background thread per engine.

    A v1 datastore by design — see docs/ARCHITECTURE.md for the Postgres +
    Celery version this is meant to grow into. The per-engine execution
    method (`_run_engine`) is a plain, synchronous, mockable call so it can
    be unit tested without spinning up real threads.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._scans = {}

    def create_scan(self, target, engines, source_path=None, image_ref=None, authorized=False):
        target = (target or '').strip()
        image_ref = (image_ref or '').strip() or None
        source_path = (source_path or '').strip() or None

        if not target and not image_ref and not source_path:
            raise ValueError('a target URL, image reference, or source path is required')

        # Different engines look at different resources (Trivy: image_ref,
        # Semgrep: source_path, everything else: target) — whichever one
        # was actually provided doubles as the scan's display label.
        target = target or image_ref or source_path

        if not authorized:
            raise PermissionError(
                'this target has not been confirmed as authorized for testing'
            )

        engines = list(dict.fromkeys(engines or []))
        unknown = [e for e in engines if e not in ENGINES]

        if unknown:
            raise ValueError('unknown engine(s): {}'.format(', '.join(unknown)))

        if not engines:
            raise ValueError('at least one engine is required')

        scan_id = uuid.uuid4().hex[:12]

        with self._lock:
            self._scans[scan_id] = {
                'id': scan_id,
                'target': target,
                'source_path': source_path,
                'image_ref': image_ref,
                'engines': {
                    name: {
                        'status': 'queued',
                        'progress': 0,
                        'started_at': None,
                        'finished_at': None,
                        'error': None,
                        'findings_count': 0,
                        'command': None,
                    }
                    for name in engines
                },
                'vulnerabilities': [],
                'status': 'queued',
                'created_at': _now(),
                'started_at': None,
                'finished_at': None,
            }

        for name in engines:
            threading.Thread(
                target=self._run_engine,
                args=(scan_id, name),
                daemon=True,
            ).start()

        return scan_id

    def _execute(self, name, target, source_path, image_ref=None):
        """Returns (raw_result, commands) — commands is the list of argv
        lists actually run, so the UI can show what was executed."""
        if name == 'trivy':
            if not image_ref:
                return {'error': 'no container image reference provided for trivy'}, []
            tool = TrivyTool()
            return tool.scan(image_ref), [tool.last_command]

        if name == 'nmap':
            # 'quick' caps at the top 100 ports instead of nmap's default
            # ~1000 — -sV service detection on the full range is what made
            # this take 1-2 minutes even against localhost.
            result = NmapTool().scan(
                _extract_host(target),
                profile='quick',
                skip_discovery=True,
                timeout=90,
            )
            command = result.metadata.get('command') if result.metadata else None
            commands = [command] if command else []

            if not result.success and result.errors:
                return {'error': '; '.join(result.errors)}, commands

            return result, commands

        if name == 'nuclei':
            tool = NucleiTool()
            return tool.scan(target), [tool.last_command]

        if name == 'semgrep':
            if not source_path:
                return {'error': 'no local source path or git URL provided for semgrep'}, []

            if _is_git_url(source_path):
                return self._scan_git_source(source_path)

            tool = SemgrepTool()
            return tool.scan(source_path), [tool.last_command]

        raise ValueError('unknown engine {}'.format(name))

    @staticmethod
    def _scan_git_source(repo_url):
        if shutil.which('git') is None:
            return {'error': 'git is not installed or not found on PATH — required to clone a repository URL for semgrep'}, []

        with tempfile.TemporaryDirectory(prefix='semgrep-src-') as clone_dir:
            clone_command = ['git', 'clone', '--depth', '1', repo_url, clone_dir]

            try:
                clone = subprocess.run(
                    clone_command,
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
            except subprocess.TimeoutExpired:
                return {'error': 'git clone timed out after 180s'}, [clone_command]

            if clone.returncode != 0:
                return {'error': 'failed to clone repository: {}'.format(clone.stderr.strip())}, [clone_command]

            tool = SemgrepTool()
            return tool.scan(clone_dir), [clone_command, tool.last_command]

    @staticmethod
    def _format_commands(commands):
        rendered = [shlex.join(c) for c in commands if c]
        return '\n'.join(rendered) if rendered else None

    def _run_engine(self, scan_id, name):
        with self._lock:
            scan = self._scans[scan_id]
            scan['status'] = 'running'
            scan['started_at'] = scan['started_at'] or _now()
            engine = scan['engines'][name]
            engine['status'] = 'running'
            engine['progress'] = 50
            engine['started_at'] = _now()
            target = scan['target']
            source_path = scan['source_path']
            image_ref = scan['image_ref']

        try:
            if not engine_available(name):
                raise RuntimeError(
                    '{} is not installed or not found on PATH'.format(
                        ENGINES[name]['label']
                    )
                )

            raw_result, commands = self._execute(name, target, source_path, image_ref=image_ref)

            with self._lock:
                engine['command'] = self._format_commands(commands)

            if isinstance(raw_result, dict) and 'error' in raw_result:
                raise RuntimeError(raw_result['error'])

            mapper_target = image_ref if name == 'trivy' else target
            vulnerabilities = MAPPERS[name](raw_result, target=mapper_target)

            with self._lock:
                engine['status'] = 'done'
                engine['progress'] = 100
                engine['finished_at'] = _now()
                engine['findings_count'] = len(vulnerabilities)
                scan['vulnerabilities'].extend(v.to_dict() for v in vulnerabilities)
                self._maybe_finalize(scan)
        except Exception as exc:  # noqa: BLE001 - surfaced as EngineRun.error
            with self._lock:
                engine['status'] = 'error'
                engine['progress'] = 100
                engine['finished_at'] = _now()
                engine['error'] = str(exc)
                self._maybe_finalize(scan)

    @staticmethod
    def _maybe_finalize(scan):
        statuses = [e['status'] for e in scan['engines'].values()]

        if not all(s in TERMINAL_STATUSES for s in statuses):
            return

        scan['finished_at'] = _now()

        if all(s == 'error' for s in statuses):
            scan['status'] = 'failed'
        elif any(s == 'error' for s in statuses):
            scan['status'] = 'partial'
        else:
            scan['status'] = 'completed'

    # ---------------------------------------------------------------- reads
    def get_scan(self, scan_id):
        with self._lock:
            scan = self._scans.get(scan_id)
            return None if scan is None else _clone(scan)

    def list_scans(self):
        with self._lock:
            scans = [_clone(s) for s in self._scans.values()]
        return sorted(scans, key=lambda s: s['created_at'], reverse=True)

    def get_vulnerabilities(self, scan_id, severity=None):
        scan = self.get_scan(scan_id)

        if scan is None:
            return None

        vulns = scan['vulnerabilities']

        if severity and severity != 'all':
            vulns = [v for v in vulns if v['severity'] == severity]

        return vulns

    def dashboard_summary(self):
        scans = self.list_scans()
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for scan in scans:
            for vuln in scan['vulnerabilities']:
                if vuln['severity'] in severity_counts:
                    severity_counts[vuln['severity']] += 1

        return {
            'total_scans': len(scans),
            'total_vulnerabilities': sum(severity_counts.values()),
            'severity_counts': severity_counts,
            'scans_running': sum(1 for s in scans if s['status'] in ('queued', 'running')),
            'engines': engines_status(),
            'recent_scans': scans[:5],
        }


def _clone(scan):
    return {
        **scan,
        'engines': {k: dict(v) for k, v in scan['engines'].items()},
        'vulnerabilities': list(scan['vulnerabilities']),
    }
