/* app.js - Dashboard upload logic */
'use strict';

const dropZone    = document.getElementById('drop-zone');
const fileInput   = document.getElementById('file-input');
const fileList    = document.getElementById('file-list');
const fileItems   = document.getElementById('file-items');
const clearBtn    = document.getElementById('clear-files');
const runBtn      = document.getElementById('run-btn');
const overlay     = document.getElementById('progress-overlay');
const recentDiv   = document.getElementById('recent-audits');

let selectedFiles = [];


/* -- Error banner ---------------------------------------------------------- */
function showError(msg) {
  overlay.classList.add('d-none');
  let banner = document.getElementById('audit-error-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'audit-error-banner';
    banner.className = 'alert alert-danger d-flex align-items-start gap-2 mt-3';
    banner.innerHTML =
      '<i class="bi bi-exclamation-triangle-fill fs-5 mt-1"></i>' +
      '<div class="flex-grow-1"><strong>Audit Failed</strong>' +
      '<p class="mb-1 mt-1 small" id="audit-error-text"></p>' +
      '<p class="mb-0 small text-muted">Supported formats: .cfg, .conf, or .txt files containing Cisco, Juniper, or Fortinet configs.</p></div>' +
      '<button type="button" class="btn-close btn-close-white" onclick="this.parentElement.remove()"></button>';
    document.querySelector('.content-area').prepend(banner);
  }
  document.getElementById('audit-error-text').textContent = msg;
  banner.scrollIntoView({ behavior: 'smooth' });
}
/* -- File selection -------------------------------------------------------- */
function addFiles(files) {
  for (const f of files) {
    if (!selectedFiles.find(x => x.name === f.name && x.size === f.size))
      selectedFiles.push(f);
  }
  renderFileList();
}

function renderFileList() {
  if (selectedFiles.length === 0) {
    fileList.classList.add('d-none');
    runBtn.disabled = true;
    return;
  }
  fileList.classList.remove('d-none');
  fileItems.innerHTML = '';
  selectedFiles.forEach((f, i) => {
    const li = document.createElement('li');
    li.className = 'file-item';
    const icon = f.name.endsWith('.cfg')  ? 'bi-filetype-txt'
               : f.name.endsWith('.conf') ? 'bi-file-earmark-code'
               : f.name.endsWith('.txt')  ? 'bi-file-text'
               : f.name.endsWith('.log')  ? 'bi-file-earmark-text'
               : 'bi-file-earmark';
    li.innerHTML = `
      <i class="bi ${icon} text-primary"></i>
      <span class="flex-grow-1 small">${f.name}</span>
      <span class="text-muted small">${(f.size/1024).toFixed(1)} KB</span>
      <button class="btn btn-link btn-sm p-0 text-danger" data-idx="${i}">
        <i class="bi bi-x"></i>
      </button>`;
    li.querySelector('button').addEventListener('click', () => {
      selectedFiles.splice(i, 1);
      renderFileList();
    });
    fileItems.appendChild(li);
  });
  runBtn.disabled = false;
}

fileInput.addEventListener('change', () => addFiles([...fileInput.files]));
clearBtn.addEventListener('click', () => { selectedFiles = []; renderFileList(); });

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('hover'); });
dropZone.addEventListener('dragleave', ()  => dropZone.classList.remove('hover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('hover');
  addFiles([...e.dataTransfer.files]);
});
dropZone.addEventListener('click', e => {
  if (!e.target.closest('label')) fileInput.click();
});

/* -- Run audit ------------------------------------------------------------- */
runBtn.addEventListener('click', async () => {
  if (!selectedFiles.length) return;

  const vendor   = document.getElementById('vendor-select').value;
  const severity = document.querySelector('input[name="severity"]:checked').value;

  overlay.classList.remove('d-none');
  document.getElementById('progress-detail').textContent =
    `Auditing ${selectedFiles.length} file(s) with ${selectedFiles.length > 1 ? 'fleet' : 'single-device'} report?`;

  const formData = new FormData();
  selectedFiles.forEach(f => formData.append('files', f));
  formData.append('vendor',   vendor);
  formData.append('severity', severity);

  try {
    const resp = await fetch('/api/audit', { method: 'POST', body: formData });
    const data = await resp.json();
    overlay.classList.add('d-none');

    if (data.error) {
    showError(data.error);
      return;
    }
    window.location.href = '/results/' + data.audit_id;
  } catch (err) {
    overlay.classList.add('d-none');
    showError('Network error: ' + err.message);
  }
});

/* -- Recent audits --------------------------------------------------------- */
async function loadRecent() {
  try {
    const resp = await fetch('/api/history');
    const list = await resp.json();
    if (!list.length) return;

    recentDiv.innerHTML = '';
    list.slice(0, 5).forEach(e => {
      const score = e.avg_score;
      const scoreColor = score === '?' ? '#8892a4'
                       : score >= 80   ? '#22c55e'
                       : score >= 50   ? '#eab308'
                       : '#ef4444';
      const a = document.createElement('a');
      a.href = '/results/' + e.id;
      a.className = 'recent-item';
      a.innerHTML = `
        <div class="recent-score" style="color:${scoreColor}">
          ${score}${score !== '?' ? '' : ''}
          <div style="font-size:.62rem;font-weight:500;color:#8892a4;margin-top:2px">SCORE</div>
        </div>
        <div class="flex-grow-1 overflow-hidden">
          <div class="fw-semibold small text-truncate">
            ${e.files.join(', ')}
          </div>
          <div class="text-muted" style="font-size:.75rem">${e.timestamp} ? ${e.vendor.toUpperCase()}</div>
        </div>
        <i class="bi bi-chevron-right text-muted"></i>`;
      recentDiv.appendChild(a);
    });
  } catch (_) {}
}

loadRecent();
