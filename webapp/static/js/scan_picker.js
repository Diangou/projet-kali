// webapp/static/js/scan_picker.js
const ICONS = {
  trivy: '<path d="M12 2 4 5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V5l-8-3Z"/><path d="m9 12 2 2 4-4"/>',
  nmap: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/>',
  nuclei: '<path d="M13 2 3 14h7l-1 8 11-13h-7l0-7Z"/>',
  semgrep: '<path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/>',
};

async function loadPicker() {
  const engines = await apiGet('/api/engines');

  document.getElementById('picker-cards').innerHTML = Object.entries(engines).map(([id, e]) => `
    <a class="engine-card" href="/scan/new/${id}">
      <div class="engine-card-head">
        <div class="engine-card-title">
          <div class="engine-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[id] || ''}</svg></div>
          <div class="t">${e.label}</div>
        </div>
        <span class="status-pill ${e.available ? 'ok' : 'error'}"><span class="dot"></span>${e.available ? 'Operational' : 'Not installed'}</span>
      </div>
      <p class="desc">${e.description}</p>
    </a>`).join('');
}

loadPicker();
