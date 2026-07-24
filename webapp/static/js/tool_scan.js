// webapp/static/js/tool_scan.js — one engine, one field, one result list.
let currentScanId = null;
let activeFilter = 'all';
let scanVulns = [];

function isValidHttpUrl(val) {
  try {
    const u = new URL(val.trim());
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (e) { return false; }
}

function refreshButton() {
  const value = document.getElementById('scan-input').value.trim();
  const authorized = document.getElementById('authz-check').checked;
  const valueOk = FIELD_PARAM === 'target' ? isValidHttpUrl(value) : value.length > 0;
  document.getElementById('scan-btn').disabled = !(valueOk && authorized) || currentScanId !== null;

  const hint = document.getElementById('input-hint');
  if (FIELD_PARAM === 'target' && value.length) {
    hint.textContent = valueOk ? '' : 'URL invalide — utilise le format http(s)://hôte';
  } else {
    hint.textContent = '';
  }
}

async function startScan() {
  const value = document.getElementById('scan-input').value.trim();
  const btn = document.getElementById('scan-btn');

  btn.disabled = true;
  btn.textContent = 'Scan en cours…';
  document.getElementById('result-panel').style.display = 'none';

  try {
    const res = await apiPost('/api/scans', {
      [FIELD_PARAM]: value,
      engines: [TOOL_ID],
      authorized: true,
    });
    currentScanId = res.id;
    pollScan();
  } catch (err) {
    btn.textContent = 'Scanner';
    refreshButton();
    document.getElementById('input-hint').textContent = 'Erreur : ' + err.message;
  }
}

async function pollScan() {
  if (!currentScanId) return;

  const btn = document.getElementById('scan-btn');
  let scan;

  try {
    scan = await apiGet(`/api/scans/${currentScanId}`);
  } catch (err) {
    // A transient network hiccup shouldn't strand the button on "Scan en
    // cours…" forever — keep retrying instead of dying on the first error.
    setTimeout(pollScan, 2000);
    return;
  }

  const engineState = scan.engines[TOOL_ID];

  if (['queued', 'running'].includes(engineState.status)) {
    btn.textContent = engineState.status === 'running' ? 'Scan en cours…' : 'En file d’attente…';
    setTimeout(pollScan, 1200);
    return;
  }

  currentScanId = null;
  btn.textContent = 'Scanner';
  refreshButton();

  if (engineState.status === 'error') {
    document.getElementById('input-hint').textContent = 'Erreur : ' + engineState.error;
    document.getElementById('result-panel').style.display = 'none';
    return;
  }

  renderResults(scan);
}

function renderResults(scan) {
  scanVulns = scan.vulnerabilities;
  activeFilter = 'all';

  document.getElementById('result-panel').style.display = 'block';
  document.getElementById('result-target').textContent = scan.target;
  document.getElementById('result-meta').textContent =
    `${formatDate(scan.created_at)} · ${scanVulns.length} finding(s)`;

  const command = scan.engines[TOOL_ID].command;
  document.getElementById('command-block').style.display = command ? 'flex' : 'none';
  document.getElementById('command-text').textContent = command || '';

  const counts = countBySeverity(scanVulns);
  document.getElementById('result-summary').innerHTML = SEVERITY_ORDER
    .filter(s => counts[s] > 0)
    .map(s => `<span class="sev-badge ${s}">${counts[s]} ${s[0].toUpperCase()}${s.slice(1)}</span>`)
    .join('') || '<span class="sev-badge info">Aucun finding — cible propre</span>';

  const filterRow = document.getElementById('filter-row');
  renderSeverityChips(filterRow, scanVulns, activeFilter, (severity) => {
    activeFilter = severity;
    applyFilter();
  });
  applyFilter();
}

function applyFilter() {
  const items = activeFilter === 'all' ? scanVulns : scanVulns.filter(v => v.severity === activeFilter);
  renderVulnList(document.getElementById('vuln-list'), items);
}

document.getElementById('scan-input').addEventListener('input', refreshButton);
document.getElementById('authz-check').addEventListener('change', refreshButton);
document.getElementById('scan-btn').addEventListener('click', startScan);

refreshButton();
