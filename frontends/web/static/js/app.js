/* Audit page: pick files, run the audit, go to the result. */
'use strict';

(function () {
  const ALLOWED = ['.cfg', '.conf', '.txt', '.log'];
  const form  = document.getElementById('audit-form');
  const drop  = document.getElementById('drop');
  const input = document.getElementById('file-input');
  const list  = document.getElementById('files');
  const run   = document.getElementById('run');
  const busy  = document.getElementById('busy');
  const error = document.getElementById('error');
  const maxBytes = Number(form.dataset.maxBytes) || Infinity;
  let files = [];

  function size(b) {
    return b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB'
                                             : (b / 1048576).toFixed(1) + ' MB';
  }

  function render() {
    list.replaceChildren();
    files.forEach(function (f, i) {
      const li = document.createElement('li');
      const name = document.createElement('span');
      name.className = 'name';
      name.textContent = f.name;
      const meta = document.createElement('span');
      meta.className = 'small faint';
      meta.textContent = size(f.size);
      const rm = document.createElement('button');
      rm.type = 'button';
      rm.className = 'btn btn-sm btn-ghost';
      rm.textContent = 'Remove';
      rm.setAttribute('aria-label', 'Remove ' + f.name);
      rm.addEventListener('click', function () { files.splice(i, 1); render(); });
      li.append(name, meta, rm);
      list.append(li);
    });
    list.hidden = files.length === 0;
    run.disabled = files.length === 0;
    run.firstChild.textContent = files.length > 1 ? 'Audit ' + files.length + ' files ' : 'Run audit ';
  }

  function add(newFiles) {
    let skipped = 0;
    newFiles.forEach(function (f) {
      const ext = f.name.slice(f.name.lastIndexOf('.')).toLowerCase();
      if (!ALLOWED.includes(ext)) { skipped++; return; }
      if (!files.some(function (x) { return x.name === f.name && x.size === f.size; })) files.push(f);
    });
    showError(skipped ? skipped + ' file(s) skipped: only .cfg, .conf, .txt and .log are accepted.' : '');
    render();
  }

  function showError(msg) {
    error.textContent = msg;
    error.hidden = !msg;
  }

  input.addEventListener('change', function () { add(Array.from(input.files)); input.value = ''; });

  ['dragenter', 'dragover'].forEach(function (t) {
    drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (t) {
    drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove('over'); });
  });
  drop.addEventListener('drop', function (e) { add(Array.from(e.dataTransfer.files)); });
  drop.tabIndex = 0;
  drop.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!files.length) return;
    const total = files.reduce(function (n, f) { return n + f.size; }, 0);
    if (total > maxBytes) {
      showError('These files total ' + size(total) + '; the limit per audit is ' + size(maxBytes) + '.');
      return;
    }
    showError('');

    const data = new FormData();
    files.forEach(function (f) { data.append('files', f); });
    data.append('vendor', document.getElementById('vendor').value);
    data.append('severity', form.querySelector('input[name=severity]:checked').value);

    document.getElementById('busy-detail').textContent =
      files.length > 1 ? files.length + ' files · fleet report' : files[0].name;
    busy.hidden = false;
    run.disabled = true;
    try {
      const resp = await fetch('/api/audit', { method: 'POST', body: data });
      let body;
      try { body = await resp.json(); }
      catch (_) { throw new Error('The server returned an error (HTTP ' + resp.status + ').'); }
      if (body.error) throw new Error(body.error);
      window.location.href = '/results/' + body.audit_id;
    } catch (err) {
      busy.hidden = true;
      run.disabled = false;
      showError(err.message || 'The audit could not be completed.');
    }
  });
})();
