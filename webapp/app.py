# webapp/app.py
from flask import Flask, abort, jsonify, render_template, request

from vuln_scanner.scan_manager import ENGINES, ScanManager, engines_status

app = Flask(__name__)
manager = ScanManager()

# The one thing each engine actually needs — drives the single input field
# on its scan page. `param` is the POST /api/scans key that field fills in.
TOOL_FIELDS = {
    'trivy': {'label': 'Image conteneur', 'placeholder': 'bkimminich/juice-shop:latest', 'param': 'image_ref'},
    'nmap': {'label': 'URL cible', 'placeholder': 'https://example.com', 'param': 'target'},
    'nuclei': {'label': 'URL cible', 'placeholder': 'https://example.com', 'param': 'target'},
    'semgrep': {'label': 'Chemin local ou URL git', 'placeholder': 'https://github.com/org/repo.git', 'param': 'source_path'},
}


# ------------------------------------------------------------------ pages
@app.get('/')
def dashboard():
    return render_template('dashboard.html')


@app.get('/scan/new')
def new_scan_picker():
    return render_template('scan_picker.html')


@app.get('/scan/new/<tool_id>')
def new_scan_tool(tool_id):
    if tool_id not in ENGINES:
        abort(404)

    return render_template(
        'tool_scan.html',
        tool_id=tool_id,
        engine=ENGINES[tool_id],
        field=TOOL_FIELDS[tool_id],
    )


@app.get('/scan/<scan_id>')
def scan_results(scan_id):
    return render_template('results.html', scan_id=scan_id)


@app.get('/history')
def history():
    return render_template('history.html')


# ------------------------------------------------------------------- API
@app.get('/api/engines')
def api_engines():
    return jsonify(engines_status())


@app.get('/api/dashboard/summary')
def api_dashboard_summary():
    return jsonify(manager.dashboard_summary())


@app.get('/api/scans')
def api_list_scans():
    return jsonify(manager.list_scans())


@app.post('/api/scans')
def api_create_scan():
    payload = request.get_json(silent=True) or {}

    try:
        scan_id = manager.create_scan(
            target=payload.get('target', ''),
            engines=payload.get('engines', []),
            source_path=payload.get('source_path') or None,
            image_ref=payload.get('image_ref') or None,
            authorized=bool(payload.get('authorized')),
        )
    except PermissionError as exc:
        return jsonify({'error': str(exc)}), 403
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    return jsonify({'id': scan_id}), 201


@app.get('/api/scans/<scan_id>')
def api_get_scan(scan_id):
    scan = manager.get_scan(scan_id)

    if scan is None:
        return jsonify({'error': 'scan not found'}), 404

    return jsonify(scan)


@app.get('/api/scans/<scan_id>/vulnerabilities')
def api_get_vulnerabilities(scan_id):
    severity = request.args.get('severity')
    vulns = manager.get_vulnerabilities(scan_id, severity=severity)

    if vulns is None:
        return jsonify({'error': 'scan not found'}), 404

    return jsonify(vulns)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
