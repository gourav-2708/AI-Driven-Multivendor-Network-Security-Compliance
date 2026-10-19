/* ════════════════════════════════════════════════════════════════
   app.js  |  Dashboard upload logic + recent audits
   API calls are unchanged. Only UX/interaction improvements.
   ════════════════════════════════════════════════════════════════ */
'use strict';

/* ── DOM refs ─────────────────────────────────────────────────── */
const dropZone  = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileList  = document.getElementById('file-list');
const fileItems = document.getElementById('file-items');
const clearBtn  = document.getElementById('clear-files');
const runBtn    = document.getElementById('run-btn');
const runHint   = document.getElementById('run-btn-hint');
const overlay   = document.getElementById('progress-overlay');
const recentDiv = document.getElementById('recent-content');

let selectedFiles = [];

/* ──────────────────────────────────────────────────────────────
   ERROR BANNER
   ────────────────────────────────────────────────────────────── */
function showError(msg) {
  overlay.classList.add('d-none');
  let banner = document.getElementById('audit-error-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'audit-error-banner';
    banner.className = 'alert-banner alert-danger mb-4';
    banner.setAttribute('role', 'alert');
    banner.setAttribute('aria-live', 'assertive');
    banner.innerHTML =
      '<i class="bi bi-exclamation-triangle-fill" aria-hidden="true"></i>' +
      '<div class="flex-grow-1"><strong>Audit Failed:</strong> ' +
      '<span id="audit-error-text"></span>' +
      '<p style="margin:.4em 0 0;font-size:.8em;opacity:.75">Supported: .cfg, .conf, .txt (Cisco, Juniper, Fortinet)</p></div>' +
      '<button type="button" aria-label="Dismiss error" style="background:none;border:none;color:inherit;cursor:pointer;font-size:1.1rem;opacity:.7" ' +
      'onclick="this.closest(\'[role=alert]\').remove()">×</button>';
    document.querySelector('.content-area').prepend(banner);
  }
  document.getElementById('audit-error-text').textContent = msg;
  banner.scrollIntoView({ behavior: 'smooth', block: 'center' });
}


/* ──────────────────────────────────────────────────────────────
   FILE MANAGEMENT
   ────────────────────────────────────────────────────────────── */
function addFiles(files) {
  let added = 0;
  for (const f of files) {
    if (!selectedFiles.find(x => x.name === f.name && x.size === f.size)) {
      selectedFiles.push(f);
      added++;
    }
  }
  if (added > 0) renderFileList();
}

function formatSize(bytes) {
  if (bytes < 1024)       return bytes + ' B';
  if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function getFileIcon(name) {
  if (name.endsWith('.cfg'))  return 'bi-filetype-txt';
  if (name.endsWith('.conf')) return 'bi-file-earmark-code';
  if (name.endsWith('.txt'))  return 'bi-file-text';
  if (name.endsWith('.log'))  return 'bi-file-earmark-text';
  return 'bi-file-earmark';
}

function renderFileList() {
  if (selectedFiles.length === 0) {
    fileList.classList.add('d-none');
    runBtn.disabled = true;
    if (runHint) runHint.textContent = 'Select files above to enable audit';
    return;
  }

  fileList.classList.remove('d-none');
  fileItems.innerHTML = '';

  selectedFiles.forEach((f, i) => {
    const li = document.createElement('li');
    li.className = 'file-chip-item';
    li.innerHTML = `
      <i class="bi ${getFileIcon(f.name)}" aria-hidden="true"></i>
      <span class="file-chip-name font-mono" title="${f.name}">${f.name}</span>
      <span class="file-chip-size">${formatSize(f.size)}</span>
      <button class="file-chip-remove" data-idx="${i}"
              aria-label="Remove ${f.name}" title="Remove file">
        <i class="bi bi-x" aria-hidden="true"></i>
      </button>`;
    li.querySelector('.file-chip-remove').addEventListener('click', () => {
      selectedFiles.splice(i, 1);
      renderFileList();
    });
    fileItems.appendChild(li);
  });

  runBtn.disabled = false;
  if (runHint) runHint.textContent =
    `${selectedFiles.length} file${selectedFiles.length > 1 ? 's' : ''} ready`;
}

/* File input events */
fileInput.addEventListener('change', () => addFiles([...fileInput.files]));
clearBtn.addEventListener('click', () => { selectedFiles = []; renderFileList(); });

/* Drop zone – drag & drop */
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('hover'); });
dropZone.addEventListener('dragleave', e => {
  if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('hover');
});
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('hover');
  addFiles([...e.dataTransfer.files]);
});

/* Drop zone – keyboard + click */
dropZone.addEventListener('click', e => {
  if (!e.target.closest('label') && !e.target.closest('.file-chip-remove'))
    fileInput.click();
});
dropZone.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('label')) {
    e.preventDefault();
    fileInput.click();
  }
});


/* ──────────────────────────────────────────────────────────────
   CATEGORY CHIPS (visual only – toggleable)
   ────────────────────────────────────────────────────────────── */
document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', function() {
    const active = this.classList.toggle('chip-active');
    this.setAttribute('aria-pressed', String(active));
  });
  chip.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); chip.click(); }
  });
});


/* ──────────────────────────────────────────────────────────────
   PROGRESS ANIMATION
   ────────────────────────────────────────────────────────────── */
let progressTimer = null;
function startProgressAnimation() {
  const steps = ['pstep-1', 'pstep-2', 'pstep-3'];
  let idx = 0;
  function advance() {
    // Mark previous step done
    if (idx > 0) {
      document.getElementById(steps[idx - 1])?.classList.replace('active', 'done');
    }
    const step = document.getElementById(steps[idx]);
    step?.classList.add('active');
    idx++;
    if (idx < steps.length) progressTimer = setTimeout(advance, 1400);
  }
  advance();
}
function resetProgressAnimation() {
  clearTimeout(progressTimer);
  ['pstep-1','pstep-2','pstep-3'].forEach(id => {
    const el = document.getElementById(id);
    el?.classList.remove('active','done');
  });
}


/* ──────────────────────────────────────────────────────────────
   RUN AUDIT  (API call unchanged)
   ────────────────────────────────────────────────────────────── */
runBtn.addEventListener('click', async () => {
  if (!selectedFiles.length) return;

  // Remove old error
  document.getElementById('audit-error-banner')?.remove();

  const vendor   = document.getElementById('vendor-select').value;
  const severity = document.querySelector('input[name="severity"]:checked').value;

  // Show overlay + start animation
  overlay.classList.remove('d-none');
  resetProgressAnimation();
  startProgressAnimation();
  document.getElementById('progress-detail').textContent =
    `Auditing ${selectedFiles.length} file${selectedFiles.length > 1 ? 's' : ''} — ${selectedFiles.length > 1 ? 'fleet' : 'device'} report`;

  const formData = new FormData();
  selectedFiles.forEach(f => formData.append('files', f));
  formData.append('vendor',   vendor);
  formData.append('severity', severity);

  try {
    const resp = await fetch('/api/audit', { method: 'POST', body: formData });
    const data = await resp.json();
    overlay.classList.add('d-none');
    resetProgressAnimation();

    if (data.error) { showError(data.error); return; }
    window.location.href = '/results/' + data.audit_id;
  } catch (err) {
    overlay.classList.add('d-none');
    resetProgressAnimation();
    showError('Network error: ' + err.message);
  }
});


/* ──────────────────────────────────────────────────────────────
   RECENT AUDITS
   ────────────────────────────────────────────────────────────── */
async function loadRecent() {
  const skeleton = document.getElementById('recent-skeleton');
  const empty    = document.getElementById('recent-empty');

  try {
    const resp = await fetch('/api/history');
    const list = await resp.json();

    if (skeleton) skeleton.style.display = 'none';

    if (!list.length) {
      if (empty) empty.classList.remove('d-none');
      return;
    }

    if (recentDiv) {
      recentDiv.classList.remove('d-none');
      recentDiv.innerHTML = '';

      list.slice(0, 5).forEach(e => {
        const score      = e.avg_score;
        const scoreColor = score === '?' ? 'var(--text-muted)'
                         : score >= 80   ? 'var(--good)'
                         : score >= 50   ? 'var(--med)'
                         : 'var(--crit)';

        const a = document.createElement('a');
        a.href = '/results/' + e.id;
        a.className = 'recent-item';
        a.setAttribute('aria-label',
          `Audit from ${e.timestamp}, score ${score}, vendor ${e.vendor}`);
        a.innerHTML = `
          <div class="recent-score" style="color:${scoreColor}" aria-hidden="true">
            ${score === '?' ? '?' : score}
            <div class="recent-score-label">Score</div>
          </div>
          <div style="flex:1;overflow:hidden">
            <div style="font-weight:600;font-size:.83rem;color:var(--text-hi);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
              ${escapeHtml(e.files.join(', '))}
            </div>
            <div style="font-size:.73rem;color:var(--text-muted);margin-top:2px;font-family:'JetBrains Mono',monospace">
              ${escapeHtml(e.timestamp)} &middot; ${escapeHtml(e.vendor.toUpperCase())}
            </div>
          </div>
          <i class="bi bi-chevron-right" style="color:var(--text-muted);font-size:.8rem;flex-shrink:0" aria-hidden="true"></i>`;
        recentDiv.appendChild(a);
      });
    }
  } catch (_) {
    if (skeleton) skeleton.style.display = 'none';
    if (empty) empty.classList.remove('d-none');
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

loadRecent();
