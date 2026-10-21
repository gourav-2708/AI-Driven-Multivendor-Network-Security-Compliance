/* Results page: severity tabs + text search over findings. */
'use strict';

(function () {
  const q    = document.getElementById('q');
  const tabs = document.querySelectorAll('.tab[data-sev]');
  const none = document.getElementById('no-match');
  if (!q || !tabs.length) return;

  const rows = Array.from(document.querySelectorAll('[data-findings] > li'));
  let level = '';

  /* Counts per tab. */
  document.querySelectorAll('[data-count]').forEach(function (el) {
    const key = el.dataset.count;
    el.textContent = rows.filter(function (r) { return !key || r.dataset.sev === key; }).length;
  });

  function apply() {
    const text = q.value.trim().toLowerCase();
    let shown = 0;
    rows.forEach(function (li) {
      const ok = (!level || li.dataset.sev === level) && (!text || li.dataset.text.includes(text));
      li.hidden = !ok;
      if (ok) shown++;
    });
    /* Fleet view: hide device blocks with nothing left to show. */
    document.querySelectorAll('.device-block').forEach(function (b) {
      const list = b.querySelector('[data-findings]');
      const visible = list ? list.querySelectorAll(':scope > li:not([hidden])').length : 0;
      b.hidden = Boolean(level || text) && visible === 0;
    });
    none.hidden = !(level || text) || shown > 0;
  }

  tabs.forEach(function (t) {
    t.addEventListener('click', function () {
      tabs.forEach(function (x) { x.setAttribute('aria-selected', String(x === t)); });
      level = t.dataset.sev;
      apply();
    });
  });
  q.addEventListener('input', apply);

  /* Deep link from a device card: open its first finding. */
  document.querySelectorAll('a.cyan-card[href^="#device-"]').forEach(function (a) {
    a.addEventListener('click', function () {
      const first = document.querySelector(a.getAttribute('href') + ' details');
      if (first) first.open = true;
    });
  });
})();
