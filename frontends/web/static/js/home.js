/* Home page: vendor panels, solution and audience tabs, the terminal demo. */
'use strict';

(function () {
  /* Vendor tabs follow the panel in view; clicking a tab scrolls to its panel. */
  const vtabs = Array.from(document.querySelectorAll('[data-vtab]'));
  const panels = vtabs.map(function (t) { return document.querySelector('[data-vpanel="' + t.dataset.vtab + '"]'); });
  if (vtabs.length) {
    const select = function (i) {
      vtabs.forEach(function (t, j) { t.setAttribute('aria-selected', String(i === j)); });
      const bar = vtabs[i].parentElement;
      const left = vtabs[i].offsetLeft - (bar.clientWidth - vtabs[i].offsetWidth) / 2;
      if (bar.scrollWidth > bar.clientWidth) bar.scrollTo({ left: left, behavior: 'smooth' });
    };
    let current = 0;
    const spy = function () {
      const line = window.innerHeight * 0.5;
      let i = 0;
      panels.forEach(function (p, j) { if (p && p.getBoundingClientRect().top <= line) i = j; });
      if (i !== current) { current = i; select(i); }
    };
    window.addEventListener('scroll', spy, { passive: true });
    spy();
  }

  /* Tab groups that swap panels in place (solutions list, audiences). */
  function tabGroup(buttonAttr, panelAttr) {
    const buttons = document.querySelectorAll('[' + buttonAttr + ']');
    buttons.forEach(function (b) {
      b.addEventListener('click', function () {
        const key = b.getAttribute(buttonAttr);
        buttons.forEach(function (x) { x.setAttribute('aria-selected', String(x === b)); });
        document.querySelectorAll('[' + panelAttr + ']').forEach(function (p) {
          p.hidden = p.getAttribute(panelAttr) !== key;
        });
      });
    });
  }
  tabGroup('data-sol', 'data-sol-panel');
  tabGroup('data-aud', 'data-aud-panel');
  document.querySelectorAll('[data-sol]').forEach(function (b) {
    b.addEventListener('mouseenter', function () { b.click(); });
  });

  /* Links that preset the audit form (vendor or severity) before jumping to it. */
  document.querySelectorAll('[data-vendor-pick]').forEach(function (a) {
    a.addEventListener('click', function () {
      const select = document.getElementById('vendor');
      if (select) select.value = a.dataset.vendorPick;
    });
  });
  document.querySelectorAll('[data-sev-pick]').forEach(function (a) {
    a.addEventListener('click', function () {
      const radio = document.getElementById('sev-' + a.dataset.sevPick);
      if (radio) radio.checked = true;
    });
  });

  /* Terminal demo: type out a fleet run once it scrolls into view. */
  const out = document.getElementById('typed');
  const caption = document.getElementById('screen-caption');
  if (!out) return;
  const S = [
    ['$ ', 't-dim'], ['net-audit --severity high --dir backups/configs\n', 't-hi'], ['', 'pause'],
    ['[INF] 13 inputs · detecting vendors (40-line probe)\n', 't-dim'],
    ['  core-router-01           cisco      ', ''], ['  2/100  CRITICAL\n', 't-bad'],
    ['  branch-firewall-secure   cisco    ', ''], ['  100/100  SECURE\n', 't-ok'],
    ['  campus-distribution-sw   cisco     ', ''], [' 40/100  CRITICAL\n', 't-bad'],
    ['  juniper-srx-secure       juniper   ', ''], [' 77/100  AT RISK\n', 't-warn'],
    ['  juniper-mx-datacenter    juniper   ', ''], [' 45/100  CRITICAL\n', 't-bad'],
    ['  fortinet-fg-secure       fortinet  ', ''], [' 85/100  SECURE\n', 't-ok'],
    ['  fortinet-branch-medium   fortinet  ', ''], [' 14/100  CRITICAL\n', 't-bad'],
    ['  ...\n', 't-dim'], ['', 'pause'],
    ['\n  [AUTH-001] CRITICAL  Plaintext enable password without enable secret\n', 't-bad'],
    ['             fix: enable secret <hash>\n', 't-dim'],
    ['  [SNMP-001] CRITICAL  SNMPv1/v2c with default or weak community strings\n', 't-bad'],
    ['             fix: SNMPv3 with authPriv, or a strong community bound to an ACL\n', 't-dim'],
    ['  [AUTH-003] HIGH      Telnet permitted for management\n', 't-warn'],
    ['             fix: transport input ssh\n', 't-dim'], ['', 'pause'],
    ['\nFleet: 13 devices · average score 29/100 · exit status 1\n', 't-hi'],
  ];
  const captions = ['net-audit --dir backups/configs', 'Every device scored in one pass', 'Each finding comes with its fix', 'Exit status 1 fails the pipeline'];
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let started = false;

  function render(upto, partial) {
    out.replaceChildren();
    for (let i = 0; i < upto; i++) add(S[i][0], S[i][1]);
    if (partial !== undefined) add(partial, S[upto][1]);
    const c = document.createElement('span');
    c.className = 'cursor';
    out.append(c);
  }
  function add(text, cls) {
    if (!text) return;
    const s = document.createElement('span');
    if (cls && cls !== 'pause') s.className = cls;
    s.textContent = text;
    out.append(s);
  }
  function play() {
    if (reduce) { render(S.length); return; }
    let i = 0, ch = 0, pauses = 0;
    (function step() {
      if (i >= S.length) { setTimeout(play, 6000); return; }
      const [text, cls] = S[i];
      if (cls === 'pause') {
        pauses++;
        caption.textContent = captions[Math.min(pauses, captions.length - 1)];
        i++; render(i); setTimeout(step, 900); return;
      }
      ch += i === 1 ? 2 : 6;
      if (ch >= text.length) { i++; ch = 0; render(i); }
      else render(i, text.slice(0, ch));
      setTimeout(step, i === 1 ? 40 : 12);
    })();
    caption.textContent = captions[0];
  }
  new IntersectionObserver(function (entries, io) {
    if (entries[0].isIntersecting && !started) { started = true; io.disconnect(); play(); }
  }, { threshold: 0.3 }).observe(out);
})();
