// webapp/static/js/app.js — shared helpers used by every page.

async function apiGet(path) {
  const res = await fetch(path);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const STATUS_LABEL = {
  queued: 'Queued', running: 'Running', completed: 'Completed',
  partial: 'Partial error', failed: 'Failed',
};

function countBySeverity(vulns) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  for (const v of vulns || []) {
    if (v.severity in counts) counts[v.severity] += 1;
  }
  return counts;
}

function scanRowHTML(scan) {
  const counts = countBySeverity(scan.vulnerabilities);
  const engineNames = Object.keys(scan.engines);
  const shown = engineNames.slice(0, 3);
  const chips = shown.map(e => `<span class="tool-chip">${e}</span>`).join('');
  const extra = engineNames.length > 3 ? `<span class="tool-chip">+${engineNames.length - 3}</span>` : '';

  const sevBits = [];
  if (counts.critical) sevBits.push(`<b style="color:var(--sev-critical-tint)">${counts.critical} crit</b>`);
  if (counts.high) sevBits.push(`<b style="color:var(--sev-high-tint)">${counts.high} high</b>`);
  if (!sevBits.length && scan.status === 'completed') sevBits.push('<b style="color:var(--good)">clean</b>');
  if (!sevBits.length && scan.status !== 'completed') sevBits.push('<span style="color:var(--text-muted)">—</span>');

  return `
    <a class="scan-row" href="/scan/${scan.id}">
      <div><div class="scan-target">${escapeHtml(scan.target)}</div><div class="scan-meta">${formatDate(scan.created_at)}</div></div>
      <div class="tool-chips">${chips}${extra}</div>
      <div class="sev-counts">${sevBits.join('<span style="color:var(--text-muted)">&middot;</span>')}</div>
      <div class="status-pill ${scan.status}"><span class="dot"></span>${STATUS_LABEL[scan.status] || scan.status}</div>
      <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 6 6 6-6 6"/></svg>
    </a>`;
}

function vulnCardHTML(v) {
  return `
    <div class="vuln-card" data-sev="${v.severity}">
      <div class="vuln-top">
        <div>
          <div class="vuln-title">${escapeHtml(v.title)}</div>
          <div class="vuln-sub">
            <span>${escapeHtml(v.tool)}</span>
            ${v.cve ? `<span>${escapeHtml(v.cve)}</span>` : ''}
            ${v.location ? `<span>${escapeHtml(v.location)}</span>` : ''}
          </div>
        </div>
        <div class="vuln-right">
          <span class="sev-badge ${v.severity}">${v.severity}</span>
          ${v.cvss ? `<span class="cvss-tag">CVSS ${Number(v.cvss).toFixed(1)}</span>` : ''}
          <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 6 6 6-6 6"/></svg>
        </div>
      </div>
      <div class="vuln-detail">
        ${v.description ? `<div class="field"><div class="field-label">Description</div>${escapeHtml(v.description)}</div>` : ''}
        ${v.recommendation ? `<div class="field"><div class="field-label">Recommendation</div><span class="rec">${escapeHtml(v.recommendation)}</span></div>` : ''}
        ${(v.references && v.references.length) ? `<div class="field"><div class="field-label">References</div>${v.references.map(r => `<span class="ref-tag">↗ ${escapeHtml(r)}</span>`).join('')}</div>` : ''}
      </div>
    </div>`;
}

function renderVulnList(container, vulns) {
  container.innerHTML = vulns.length
    ? vulns.map(vulnCardHTML).join('')
    : '<p class="empty-hint">Aucune vulnérabilité pour ce filtre.</p>';

  container.querySelectorAll('.vuln-card').forEach(card =>
    card.addEventListener('click', () => card.classList.toggle('open'))
  );
}

// Renders "All <n> / Critical <n> / …" chips into `row`, wired to call
// `onSelect(severity)` on click. Only severities present in `vulns` get a chip.
function renderSeverityChips(row, vulns, activeFilter, onSelect) {
  const counts = countBySeverity(vulns);

  row.innerHTML = `
    <div class="filter-chip${activeFilter === 'all' ? ' active' : ''}" data-filter="all">All <span class="n">${vulns.length}</span></div>
    ${SEVERITY_ORDER.filter(s => counts[s] > 0).map(s =>
      `<div class="filter-chip${activeFilter === s ? ' active' : ''}" data-filter="${s}">${s[0].toUpperCase()}${s.slice(1)} <span class="n">${counts[s]}</span></div>`
    ).join('')}`;

  row.querySelectorAll('.filter-chip').forEach(chip => chip.addEventListener('click', () => {
    row.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    onSelect(chip.dataset.filter);
  }));
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}
