# tests/test_scan_manager.py
import unittest
from unittest.mock import MagicMock, patch

from vuln_scanner.scan_manager import ScanManager, _is_git_url

FORMAT_COMMANDS_CASES = [
    ([], None),
    ([None], None),
    ([['trivy', 'image', 'alpine:latest']], 'trivy image alpine:latest'),
    (
        [['git', 'clone', 'https://x'], ['semgrep', '--config', 'p/ci']],
        'git clone https://x\nsemgrep --config p/ci',
    ),
]


class TestScanManagerValidation(unittest.TestCase):
    def setUp(self):
        self.manager = ScanManager()

    def test_requires_authorization(self):
        with self.assertRaises(PermissionError):
            self.manager.create_scan('http://x', ['trivy'], authorized=False)

    def test_rejects_unknown_engine(self):
        with self.assertRaises(ValueError):
            self.manager.create_scan('http://x', ['not-a-tool'], authorized=True)

    def test_requires_target(self):
        with self.assertRaises(ValueError):
            self.manager.create_scan('', ['trivy'], authorized=True)

    def test_requires_at_least_one_engine(self):
        with self.assertRaises(ValueError):
            self.manager.create_scan('http://x', [], authorized=True)

    def test_image_ref_satisfies_target_requirement(self):
        # Trivy-only scans don't need a throwaway URL — the image ref is a
        # distinct resource and can stand in as the scan's target label.
        scan_id = self.manager.create_scan(
            '', ['trivy'], image_ref='alpine:latest', authorized=True,
        )
        scan = self.manager.get_scan(scan_id)
        self.assertEqual(scan['target'], 'alpine:latest')
        self.assertEqual(scan['image_ref'], 'alpine:latest')

    def test_source_path_satisfies_target_requirement(self):
        # Semgrep-only scans (single-tool page) shouldn't need a throwaway
        # URL either — the source path stands in as the target label.
        scan_id = self.manager.create_scan(
            '', ['semgrep'], source_path='vuln_scanner', authorized=True,
        )
        scan = self.manager.get_scan(scan_id)
        self.assertEqual(scan['target'], 'vuln_scanner')


class TestScanManagerExecution(unittest.TestCase):
    """`_run_engine` is called directly (threading.Thread mocked out) so
    these tests run synchronously without touching real subprocesses."""

    def setUp(self):
        self.manager = ScanManager()

    def test_execute_trivy_without_image_ref_is_an_error(self):
        result, commands = self.manager._execute('trivy', 'http://x', None, image_ref=None)
        self.assertIn('error', result)
        self.assertIn('image reference', result['error'])
        self.assertEqual(commands, [])

    def test_execute_nmap_uses_quick_profile(self):
        # 'services' (nmap's ~1000-port default + -sV) was taking 1-2
        # minutes even against localhost — 'quick' caps at the top 100.
        with patch('vuln_scanner.scan_manager.NmapTool') as mock_nmap_cls:
            mock_nmap_cls.return_value.scan.return_value = MagicMock(
                success=True, errors=[], metadata={'command': ['nmap', '-sT']},
            )
            self.manager._execute('nmap', 'http://127.0.0.1', None)

        _, kwargs = mock_nmap_cls.return_value.scan.call_args
        self.assertEqual(kwargs['profile'], 'quick')

    @patch('vuln_scanner.scan_manager.threading.Thread')
    @patch('vuln_scanner.scan_manager.engine_available', return_value=True)
    def test_run_engine_trivy_uses_image_ref_not_target(self, mock_available, mock_thread):
        scan_id = self.manager.create_scan(
            'http://x', ['trivy'], image_ref='alpine:latest', authorized=True,
        )

        with patch('vuln_scanner.scan_manager.TrivyTool') as mock_trivy_cls:
            mock_trivy_cls.return_value.scan.return_value = {'Results': []}
            mock_trivy_cls.return_value.last_command = ['trivy', 'image', '--format', 'json', '--quiet', 'alpine:latest']
            self.manager._run_engine(scan_id, 'trivy')

        mock_trivy_cls.return_value.scan.assert_called_once_with('alpine:latest')
        scan = self.manager.get_scan(scan_id)
        self.assertEqual(scan['engines']['trivy']['status'], 'done')
        self.assertIn('trivy image', scan['engines']['trivy']['command'])

    @patch('vuln_scanner.scan_manager.threading.Thread')
    @patch('vuln_scanner.scan_manager.engine_available', return_value=True)
    def test_run_engine_success_updates_state(self, mock_available, mock_thread):
        scan_id = self.manager.create_scan('http://x', ['nuclei'], authorized=True)

        with patch.object(
            self.manager, '_execute',
            return_value=([{'template-id': 't', 'info': {'severity': 'high'}, 'host': 'http://x'}], []),
        ):
            self.manager._run_engine(scan_id, 'nuclei')

        scan = self.manager.get_scan(scan_id)
        self.assertEqual(scan['engines']['nuclei']['status'], 'done')
        self.assertEqual(scan['engines']['nuclei']['findings_count'], 1)
        self.assertEqual(scan['status'], 'completed')
        self.assertEqual(len(scan['vulnerabilities']), 1)

    @patch('vuln_scanner.scan_manager.threading.Thread')
    @patch('vuln_scanner.scan_manager.engine_available', return_value=True)
    def test_run_engine_tool_error_marks_engine_error(self, mock_available, mock_thread):
        scan_id = self.manager.create_scan('http://x', ['nuclei'], authorized=True)

        with patch.object(self.manager, '_execute', return_value=({'error': 'boom'}, [])):
            self.manager._run_engine(scan_id, 'nuclei')

        scan = self.manager.get_scan(scan_id)
        self.assertEqual(scan['engines']['nuclei']['status'], 'error')
        self.assertEqual(scan['engines']['nuclei']['error'], 'boom')
        self.assertEqual(scan['status'], 'failed')

    @patch('vuln_scanner.scan_manager.threading.Thread')
    @patch('vuln_scanner.scan_manager.engine_available', return_value=False)
    def test_run_engine_missing_binary_marks_error(self, mock_available, mock_thread):
        scan_id = self.manager.create_scan('http://x', ['nmap'], authorized=True)

        self.manager._run_engine(scan_id, 'nmap')

        scan = self.manager.get_scan(scan_id)
        self.assertEqual(scan['engines']['nmap']['status'], 'error')
        self.assertIn('not installed', scan['engines']['nmap']['error'])

    @patch('vuln_scanner.scan_manager.threading.Thread')
    @patch('vuln_scanner.scan_manager.engine_available', return_value=True)
    def test_partial_status_when_some_engines_fail(self, mock_available, mock_thread):
        scan_id = self.manager.create_scan('http://x', ['trivy', 'nuclei'], authorized=True)

        with patch.object(self.manager, '_execute', side_effect=[({'error': 'boom'}, []), ([], [])]):
            self.manager._run_engine(scan_id, 'trivy')
            self.manager._run_engine(scan_id, 'nuclei')

        scan = self.manager.get_scan(scan_id)
        self.assertEqual(scan['status'], 'partial')

    @patch('vuln_scanner.scan_manager.threading.Thread')
    def test_get_scan_unknown_id_returns_none(self, mock_thread):
        self.assertIsNone(self.manager.get_scan('does-not-exist'))

    @patch('vuln_scanner.scan_manager.threading.Thread')
    @patch('vuln_scanner.scan_manager.engine_available', return_value=True)
    def test_get_vulnerabilities_filters_by_severity(self, mock_available, mock_thread):
        scan_id = self.manager.create_scan('http://x', ['nuclei'], authorized=True)

        with patch.object(self.manager, '_execute', return_value=([
            {'template-id': 'a', 'info': {'severity': 'high'}, 'host': 'http://x'},
            {'template-id': 'b', 'info': {'severity': 'low'}, 'host': 'http://x'},
        ], [])):
            self.manager._run_engine(scan_id, 'nuclei')

        high_only = self.manager.get_vulnerabilities(scan_id, severity='high')
        self.assertEqual(len(high_only), 1)
        self.assertEqual(high_only[0]['severity'], 'high')


class TestIsGitUrl(unittest.TestCase):
    def test_recognizes_http_and_https(self):
        self.assertTrue(_is_git_url('https://github.com/org/repo.git'))
        self.assertTrue(_is_git_url('http://internal.git/repo'))

    def test_recognizes_ssh_forms(self):
        self.assertTrue(_is_git_url('git@github.com:org/repo.git'))
        self.assertTrue(_is_git_url('ssh://git@github.com/org/repo.git'))

    def test_rejects_local_paths(self):
        self.assertFalse(_is_git_url('/home/user/project'))
        self.assertFalse(_is_git_url('vuln_scanner'))
        self.assertFalse(_is_git_url(''))
        self.assertFalse(_is_git_url(None))


class TestSemgrepGitSource(unittest.TestCase):
    def setUp(self):
        self.manager = ScanManager()

    @patch('vuln_scanner.scan_manager.shutil.which', return_value=None)
    def test_git_not_installed_is_an_error(self, mock_which):
        result, commands = self.manager._execute('semgrep', 'x', 'https://github.com/org/repo.git')
        self.assertIn('error', result)
        self.assertIn('git is not installed', result['error'])
        self.assertEqual(commands, [])

    @patch('vuln_scanner.scan_manager.shutil.which', return_value='/usr/bin/git')
    @patch('vuln_scanner.scan_manager.subprocess.run')
    def test_clone_failure_is_an_error(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(returncode=128, stdout='', stderr='repository not found')

        result, commands = self.manager._execute('semgrep', 'x', 'https://github.com/org/missing.git')

        self.assertIn('error', result)
        self.assertIn('repository not found', result['error'])
        self.assertEqual(commands[0][:3], ['git', 'clone', '--depth'])

    @patch('vuln_scanner.scan_manager.shutil.which', return_value='/usr/bin/git')
    @patch('vuln_scanner.scan_manager.SemgrepTool')
    @patch('vuln_scanner.scan_manager.subprocess.run')
    def test_successful_clone_delegates_to_semgrep(self, mock_run, mock_semgrep_cls, mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        mock_semgrep_cls.return_value.scan.return_value = {'results': []}
        mock_semgrep_cls.return_value.last_command = ['semgrep', '--config', 'p/ci', '--json', '--quiet', '/tmp/x']

        result, commands = self.manager._execute('semgrep', 'x', 'https://github.com/org/repo.git')

        self.assertEqual(result, {'results': []})
        clone_args = mock_run.call_args[0][0]
        self.assertEqual(clone_args[:3], ['git', 'clone', '--depth'])
        self.assertIn('https://github.com/org/repo.git', clone_args)
        self.assertEqual(commands[0], clone_args)
        self.assertEqual(commands[1], mock_semgrep_cls.return_value.last_command)
        # scanned path is the temp clone dir, not the git URL itself
        scanned_path = mock_semgrep_cls.return_value.scan.call_args[0][0]
        self.assertNotEqual(scanned_path, 'https://github.com/org/repo.git')

    def test_plain_local_path_skips_git_entirely(self):
        with patch('vuln_scanner.scan_manager.SemgrepTool') as mock_semgrep_cls, \
             patch('vuln_scanner.scan_manager.subprocess.run') as mock_run:
            mock_semgrep_cls.return_value.scan.return_value = {'results': []}
            mock_semgrep_cls.return_value.last_command = ['semgrep', '--config', 'p/ci', '--json', '--quiet', 'vuln_scanner']

            result, commands = self.manager._execute('semgrep', 'x', 'vuln_scanner')

            mock_run.assert_not_called()
            mock_semgrep_cls.return_value.scan.assert_called_once_with('vuln_scanner')
            self.assertEqual(result, {'results': []})
            self.assertEqual(commands, [mock_semgrep_cls.return_value.last_command])


class TestFormatCommands(unittest.TestCase):
    def test_formats_commands_for_display(self):
        for commands, expected in FORMAT_COMMANDS_CASES:
            with self.subTest(commands=commands):
                self.assertEqual(ScanManager._format_commands(commands), expected)


class TestScanExposesCommand(unittest.TestCase):
    @patch('vuln_scanner.scan_manager.threading.Thread')
    @patch('vuln_scanner.scan_manager.engine_available', return_value=True)
    def test_completed_scan_includes_the_command_that_ran(self, mock_available, mock_thread):
        manager = ScanManager()
        scan_id = manager.create_scan('http://x', ['nuclei'], authorized=True)

        with patch.object(
            manager, '_execute',
            return_value=([], [['nuclei', '-u', 'http://x', '-jsonl', '-silent', '-no-color']]),
        ):
            manager._run_engine(scan_id, 'nuclei')

        scan = manager.get_scan(scan_id)
        self.assertEqual(
            scan['engines']['nuclei']['command'],
            'nuclei -u http://x -jsonl -silent -no-color',
        )


if __name__ == '__main__':
    unittest.main()
