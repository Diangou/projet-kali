// webapp/static/js/dashboard.js
const SEV_COLORS = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)',
  low: 'var(--sev-low)', info: 'var(--sev-info)',
};

async function loadDashboard() {
  let summary;
  try {
    summary = await apiGet('/api/dashboard/summary');
  } catch (err) {
    document.getElementById('stat-grid').innerHTML = `<p class="empty-hint">Erreur: ${escapeHtml(err.message)}</p>`;
    return;
  }

  renderStatGrid(summary);
  renderSeverity(summary.severity_counts);
  renderEngineGrid(summary.engines);
  renderRecentScans(summary.recent_scans);
  renderRunningScans(summary.recent_scans);
}

function renderStatGrid(summary) {
  const available = Object.values(summary.engines).filter(e => e.available).length;
  const total = Object.keys(summary.engines).length;

  document.getElementById('stat-grid').innerHTML = `
    <div class="stat-tile">
      <div class="eyebrow">Total scans</div>
      <div class="stat-value tabular">${summary.total_scans}</div>
      <div class="stat-delta">depuis le démarrage du serveur</div>
    </div>
    <div class="stat-tile">
      <div class="eyebrow">Vulnérabilités trouvées</div>
      <div class="stat-value tabular">${summary.total_vulnerabilities}</div>
      <div class="stat-delta">tous scans confondus</div>
    </div>
    <div class="stat-tile">
      <div class="eyebrow">Scans en cours</div>
      <div class="stat-value tabular">${summary.scans_running}</div>
      <div class="stat-delta">${summary.scans_running ? 'en direct' : 'aucun'}</div>
    </div>
    <div class="stat-tile">
      <div class="eyebrow">Moteurs disponibles</div>
      <div class="stat-value tabular">${available} / ${total}</div>
      <div class="stat-delta">détecté via PATH</div>
    </div>`;
}

function renderSeverity(counts) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  document.getElementById('sev-total').textContent = `${total} findings`;

  const bar = document.getElementById('sev-bar');
  const legend = document.getElementById('sev-legend');

  if (!total) {
    bar.innerHTML = `<span style="width:100%; background:var(--surface-2)"></span>`;
    legend.innerHTML = `<p class="empty-hint">Aucune vulnérabilité détectée pour le moment.</p>`;
    return;
  }

  bar.innerHTML = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => `<span style="width:${(n / total * 100).toFixed(2)}%; background:${SEV_COLORS[sev]}"></span>`)
    .join('');

  legend.innerHTML = Object.entries(counts)
    .map(([sev, n]) => `<div class="sev-legend-item"><span class="sev-dot" style="background:${SEV_COLORS[sev]}"></span>${sev[0].toUpperCase()}${sev.slice(1)} <span class="n">${n}</span></div>`)
    .join('');
}

function renderEngineGrid(engines) {
  document.getElementById('engine-grid').innerHTML = Object.entries(engines).map(([name, e]) => `
    <div class="engine-chip">
      <div class="name">${e.label}</div>
      <div class="ver">${name}</div>
      <div class="status-pill ${e.available ? 'ok' : 'error'}"><span class="dot"></span>${e.available ? 'Operational' : 'Not installed'}</div>
    </div>`).join('');
}

function renderRecentScans(scans) {
  const el = document.getElementById('recent-scans');
  el.innerHTML = scans.length
    ? scans.map(scanRowHTML).join('')
    : '<p class="empty-hint">Aucun scan pour le moment — lancez-en un depuis « New Scan ».</p>';
}

function renderRunningScans(scans) {
  const running = scans.filter(s => ['queued', 'running'].includes(s.status));
  const el = document.getElementById('running-scans');
  el.innerHTML = running.length
    ? running.map(scanRowHTML).join('')
    : '<p class="empty-hint">Aucun scan en cours.</p>';
}

loadDashboard();
setInterval(loadDashboard, 4000);
