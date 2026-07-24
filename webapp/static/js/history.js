// webapp/static/js/history.js
async function loadHistory() {
  let scans;
  try {
    scans = await apiGet('/api/scans');
  } catch (err) {
    document.getElementById('all-scans').innerHTML = `<p class="empty-hint">Erreur: ${escapeHtml(err.message)}</p>`;
    return;
  }

  document.getElementById('all-scans').innerHTML = scans.length
    ? scans.map(scanRowHTML).join('')
    : '<p class="empty-hint">Aucun scan pour le moment.</p>';
}

loadHistory();
setInterval(loadHistory, 5000);
