/* =============================================================
   app.js   net-audit Dashboard
   Matches index.html v5 (file chips, segmented severity,
   toggleable category chips, progress steps, recent audits)
   ============================================================= */

'use strict';

/*  DOM refs  */
const dropZone    = document.getElementById('drop-zone');
const fileInput   = document.getElementById('file-input');
const fileList    = document.getElementById('file-list');
const fileItems   = document.getElementById('file-items');
const clearBtn    = document.getElementById('clear-files');
const runBtn      = document.getElementById('run-btn');
const runHint     = document.getElementById('run-btn-hint');
const overlay     = document.getElementById('progress-overlay');
const recentDiv   = document.getElementById('recent-content');

let selectedFiles = [];

/*  File management  */
function formatBytes(b) {
  if (b < 1024)       return b + ' B';
  if (b < 1024*1024)  return (b/1024).toFixed(1) + ' KB';
  return (b/1024/1024).toFixed(1) + ' MB';
}

function renderChips() {
  if (!fileItems) return;
  fileItems.innerHTML = '';
  selectedFiles.forEach((f, i) => {
    const chip = document.createElement('div');
    chip.className = 'file-chip';
    chip.setAttribute('role', 'listitem');
    chip.innerHTML = `
      <span class="file-chip-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</span>
      <span class="file-chip-size">${formatBytes(f.size)}</span>
      <button class="file-chip-remove" data-idx="${i}"
              aria-label="Remove ${escapeHtml(f.name)}" title="Remove file">
        <i class="bi bi-x" aria-hidden="true"></i>
      </button>`;
    fileItems.appendChild(chip);
  });
  /* Remove individual chip */
  fileItems.querySelectorAll('.file-chip-remove').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      selectedFiles.splice(Number(btn.dataset.idx), 1);
      syncUI();
    });
  });
}

function syncUI() {
  renderChips();
  const has = selectedFiles.length > 0;
  if (fileList) fileList.classList.toggle('d-none', !has);
  if (runBtn)   runBtn.disabled = !has;
  if (runHint)  runHint.textContent = has
    ? `${selectedFiles.length} file${selectedFiles.length > 1 ? 's' : ''} ready`
    : 'Select files above to enable audit';
}

function addFiles(newFiles) {
  const allowed = ['.cfg','.conf','.txt','.log'];
  newFiles.forEach(f => {
    const ext = f.name.slice(f.name.lastIndexOf('.')).toLowerCase();
    if (!allowed.includes(ext)) return;
    if (!selectedFiles.find(x => x.name === f.name && x.size === f.size))
      selectedFiles.push(f);
  });
  syncUI();
}

/* File input */
fileInput?.addEventListener('change', () => {
  addFiles([...fileInput.files]);
  fileInput.value = '';
});

/* Clear all */
clearBtn?.addEventListener('click', e => {
  e.stopPropagation();
  selectedFiles = [];
  syncUI();
});

/*  Drop zone  */
dropZone?.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('hover'); });
dropZone?.addEventListener('dragleave', e => {
  if (!dropZone.contains(e.relatedTarget)) dropZone.classList.remove('hover');
});
dropZone?.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('hover');
  addFiles([...e.dataTransfer.files]);
});
dropZone?.addEventListener('click', e => {
  if (!e.target.closest('label') && !e.target.closest('.file-chip-remove'))
    fileInput?.click();
});
dropZone?.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('label')) {
    e.preventDefault();
    fileInput?.click();
  }
});

/*  Category chips  */
document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', function() {
    const active = this.classList.toggle('chip-active');
    this.setAttribute('aria-pressed', String(active));
  });
  chip.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); chip.click(); }
  });
});

/*  Progress animation  */
let progressTimer = null;

function startProgressAnimation() {
  const steps = ['pstep-1','pstep-2','pstep-3'];
  let idx = 0;
  function advance() {
    if (idx > 0)
      document.getElementById(steps[idx-1])?.classList.replace('active','done');
    document.getElementById(steps[idx])?.classList.add('active');
    idx++;
    if (idx < steps.length) progressTimer = setTimeout(advance, 1400);
  }
  advance();
}

function resetProgressAnimation() {
  clearTimeout(progressTimer);
  ['pstep-1','pstep-2','pstep-3'].forEach(id => {
    document.getElementById(id)?.classList.remove('active','done');
  });
}

/*  Show error banner  */
function showError(msg) {
  document.getElementById('audit-error-banner')?.remove();
  const div = document.createElement('div');
  div.id = 'audit-error-banner';
  div.className = 'alert-banner alert-danger';
  div.setAttribute('role','alert');
  div.innerHTML = `<i class="bi bi-exclamation-triangle-fill" aria-hidden="true"></i>
    <div><strong>Audit failed:</strong> ${escapeHtml(msg)}</div>`;
  document.querySelector('.content-area')?.prepend(div);
}

/*  Run audit  */
runBtn?.addEventListener('click', async () => {
  if (!selectedFiles.length) return;

  document.getElementById('audit-error-banner')?.remove();

  const vendor   = document.getElementById('vendor-select')?.value || 'auto';
  const severity = document.querySelector('input[name="severity"]:checked')?.value || 'low';

  overlay?.classList.remove('d-none');
  resetProgressAnimation();
  startProgressAnimation();

  const det = document.getElementById('progress-detail');
  if (det) det.textContent =
    `Auditing ${selectedFiles.length} file${selectedFiles.length > 1 ? 's' : ''}  ${selectedFiles.length > 1 ? 'fleet' : 'device'} report`;

  const fd = new FormData();
  selectedFiles.forEach(f => fd.append('files', f));
  fd.append('vendor',   vendor);
  fd.append('severity', severity);

  try {
    const resp = await fetch('/api/audit', { method:'POST', body:fd });
    const data = await resp.json();
    overlay?.classList.add('d-none');
    resetProgressAnimation();
    if (data.error) { showError(data.error); return; }
    window.location.href = '/results/' + data.audit_id;
  } catch(err) {
    overlay?.classList.add('d-none');
    resetProgressAnimation();
    showError('Network error: ' + err.message);
  }
});

/*  Recent audits  */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function loadRecent() {
  const skeleton = document.getElementById('recent-skeleton');
  const empty    = document.getElementById('recent-empty');
  const content  = document.getElementById('recent-content');

  try {
    const resp = await fetch('/api/history');
    const list = await resp.json();

    if (skeleton) skeleton.style.display = 'none';

    if (!list.length) {
      empty?.classList.remove('d-none');
      return;
    }

    if (content) {
      content.classList.remove('d-none');
      content.innerHTML = '';

      list.slice(0,5).forEach(e => {
        const score = e.avg_score;
        const clr   = score === '?' ? 'var(--text-muted)'
                    : score >= 80   ? 'var(--good)'
                    : score >= 50   ? 'var(--med)'
                    : 'var(--crit)';

        const a = document.createElement('a');
        a.href = '/results/' + e.id;
        a.className = 'recent-item';
        a.setAttribute('aria-label',
          `Audit from ${e.timestamp}, score ${score}, vendor ${e.vendor}`);
        a.innerHTML = `
          <div class="recent-score" style="color:${clr}" aria-hidden="true">
            ${score === '?' ? '?' : score}
            <div class="recent-score-label">Score</div>
          </div>
          <div style="flex:1;overflow:hidden">
            <div style="font-weight:600;font-size:.83rem;color:var(--text-hi);
                        overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
              ${escapeHtml(e.files.join(', '))}
            </div>
            <div style="font-size:.72rem;color:var(--text-muted);margin-top:2px;
                        font-family:'JetBrains Mono',monospace">
              ${escapeHtml(e.timestamp)} &middot; ${escapeHtml(e.vendor.toUpperCase())}
            </div>
          </div>
          <i class="bi bi-chevron-right" style="color:var(--text-muted);font-size:.8rem;flex-shrink:0"
             aria-hidden="true"></i>`;
        content.appendChild(a);
      });
    }
  } catch(_) {
    if (skeleton) skeleton.style.display = 'none';
    empty?.classList.remove('d-none');
  }
}

loadRecent();
