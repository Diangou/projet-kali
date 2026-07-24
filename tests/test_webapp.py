# tests/test_webapp.py
import unittest
from unittest.mock import patch

import webapp.app as webapp_module
from webapp.app import app


class TestWebappPages(unittest.TestCase):
    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    def test_dashboard_page_loads(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Dashboard', resp.data)

    def test_new_scan_picker_page_loads(self):
        resp = self.client.get('/scan/new')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'New Scan', resp.data)

    def test_tool_scan_page_loads_for_known_tool(self):
        resp = self.client.get('/scan/new/trivy')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Trivy', resp.data)
        self.assertIn(b'Image conteneur', resp.data)

    def test_tool_scan_page_404_for_unknown_tool(self):
        resp = self.client.get('/scan/new/not-a-tool')
        self.assertEqual(resp.status_code, 404)

    def test_history_page_loads(self):
        resp = self.client.get('/history')
        self.assertEqual(resp.status_code, 200)

    def test_results_page_loads_and_embeds_scan_id(self):
        resp = self.client.get('/scan/abc123')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'abc123', resp.data)


class TestWebappApi(unittest.TestCase):
    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    def test_api_engines_lists_all_four_tools(self):
        resp = self.client.get('/api/engines')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(
            set(data.keys()), {'trivy', 'nmap', 'nuclei', 'semgrep'}
        )

    def test_api_dashboard_summary_shape(self):
        resp = self.client.get('/api/dashboard/summary')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for key in ('total_scans', 'total_vulnerabilities', 'severity_counts', 'scans_running', 'engines', 'recent_scans'):
            self.assertIn(key, data)

    def test_api_create_scan_requires_authorization(self):
        resp = self.client.post('/api/scans', json={
            'target': 'http://example.test', 'engines': ['nuclei'], 'authorized': False,
        })
        self.assertEqual(resp.status_code, 403)
        self.assertIn('authoriz', resp.get_json()['error'])

    def test_api_create_scan_rejects_unknown_engine(self):
        resp = self.client.post('/api/scans', json={
            'target': 'http://example.test', 'engines': ['not-a-tool'], 'authorized': True,
        })
        self.assertEqual(resp.status_code, 400)

    @patch.object(webapp_module.manager, 'create_scan', return_value='abc123')
    def test_api_create_scan_success(self, mock_create):
        resp = self.client.post('/api/scans', json={
            'target': 'http://example.test', 'engines': ['nuclei'], 'authorized': True,
        })
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.get_json()['id'], 'abc123')
        mock_create.assert_called_once()

    def test_api_get_scan_not_found(self):
        resp = self.client.get('/api/scans/does-not-exist')
        self.assertEqual(resp.status_code, 404)

    def test_api_get_vulnerabilities_not_found(self):
        resp = self.client.get('/api/scans/does-not-exist/vulnerabilities')
        self.assertEqual(resp.status_code, 404)


if __name__ == '__main__':
    unittest.main()
