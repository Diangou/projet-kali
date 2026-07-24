// webapp/static/js/results.js
let ALL_VULNS = [];
let ENGINE_STATES = {};
let activeTool = 'all';
let activeFilter = 'all';

async function loadResults() {
  let scan;
  try {
    scan = await apiGet(`/api/scans/${SCAN_ID}`);
  } catch (err) {
    if (err.message === 'scan not found') {
      document.getElementById('result-target').textContent = 'Scan introuvable';
      document.getElementById('result-meta').textContent = err.message;
      return;
    }
    // Transient network hiccup — don't strand the page on a false "not
    // found" while a scan is genuinely still running server-side.
    setTimeout(loadResults, 2000);
    return;
  }

  ALL_VULNS = scan.vulnerabilities;
  ENGINE_STATES = scan.engines;

  document.getElementById('result-target').textContent = scan.target;
  const engineNames = Object.keys(scan.engines).join(', ');
  const statusLabel = STATUS_LABEL[scan.status] || scan.status;
  document.getElementById('result-meta').textContent =
    `${formatDate(scan.created_at)} · ${engineNames} · ${statusLabel}`;

  const totalCounts = countBySeverity(ALL_VULNS);
  document.getElementById('result-summary').innerHTML = SEVERITY_ORDER
    .filter(s => totalCounts[s] > 0)
    .map(s => `<span class="sev-badge ${s}">${totalCounts[s]} ${s[0].toUpperCase()}${s.slice(1)}</span>`)
    .join('') || '<span class="sev-badge info">Aucun finding</span>';

  renderToolTabs(scan);
  renderScopedSeverityChips();
  renderVulns();

  if (['queued', 'running'].includes(scan.status)) {
    setTimeout(loadResults, 1500);
  }
}

// One tab per engine that ran — each shows only its own findings, so a
// clean Nmap run doesn't get buried under 80 Trivy CVEs.
function renderToolTabs(scan) {
  const tools = Object.keys(scan.engines);
  const row = document.getElementById('tool-row');

  const tabHTML = (id, label, count, engineState) => {
    const failed = engineState && engineState.status === 'error';
    const title = failed ? ` title="${escapeHtml(engineState.error || 'failed')}"` : '';
    return `<div class="filter-chip${failed ? ' tool-error' : ''}" data-tool="${id}"${title}>${escapeHtml(label)} <span class="n">${count}</span></div>`;
  };

  row.innerHTML = [
    tabHTML('all', 'All tools', ALL_VULNS.length, null),
    ...tools.map(t => tabHTML(t, t, ALL_VULNS.filter(v => v.tool === t).length, scan.engines[t])),
  ].join('');

  row.querySelectorAll('.filter-chip').forEach(chip => chip.addEventListener('click', () => {
    row.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    activeTool = chip.dataset.tool;
    activeFilter = 'all';
    renderCommandBlock();
    renderScopedSeverityChips();
    renderVulns();
  }));

  const current = row.querySelector(`[data-tool="${activeTool}"]`) || row.querySelector('[data-tool="all"]');
  current.classList.add('active');
  renderCommandBlock();
}

// Shows the exact CLI invocation for the active tool tab — not meaningful
// for "All tools" since each engine ran its own separate command.
function renderCommandBlock() {
  const block = document.getElementById('command-block');
  const command = activeTool !== 'all' && ENGINE_STATES[activeTool]
    ? ENGINE_STATES[activeTool].command
    : null;

  block.style.display = command ? 'flex' : 'none';
  document.getElementById('command-text').textContent = command || '';
}

function toolScoped() {
  return activeTool === 'all' ? ALL_VULNS : ALL_VULNS.filter(v => v.tool === activeTool);
}

// Severity chips are scoped to the active tool tab, so counts stay honest
// when you switch from "All tools" to a single engine.
function renderScopedSeverityChips() {
  renderSeverityChips(document.getElementById('filter-row'), toolScoped(), activeFilter, (severity) => {
    activeFilter = severity;
    renderVulns();
  });
}

function renderVulns() {
  const scoped = toolScoped();
  const items = activeFilter === 'all' ? scoped : scoped.filter(v => v.severity === activeFilter);
  const list = document.getElementById('vuln-list');

  if (!items.length) {
    const engineState = activeTool !== 'all' ? ENGINE_STATES[activeTool] : null;
    list.innerHTML = engineState && engineState.status === 'error'
      ? `<p class="empty-hint">${escapeHtml(activeTool)} a échoué : ${escapeHtml(engineState.error || 'erreur inconnue')}</p>`
      : '<p class="empty-hint">Aucune vulnérabilité pour ce filtre.</p>';
    return;
  }

  renderVulnList(list, items);
}

loadResults();
