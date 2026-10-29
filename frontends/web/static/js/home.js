/* Home page: vendor panels, solution and audience tabs, the terminal demo. */
'use strict';

(function () {
  heroTerminal();

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

/* Hero terminal: type the command, stream the config in, scan it line by line,
   flag each offending line as the scan reaches it, then print the score.
   Lines and scores come from the sample configs in tests/fixtures. */
function heroTerminal() {
  const pre = document.getElementById('hero-term');
  if (!pre || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const file = document.getElementById('ht-file');
  const status = document.getElementById('ht-status');
  const progress = document.getElementById('ht-progress');
  const found = document.getElementById('ht-found');
  const rules = pre.dataset.rules || '17';

  const RUNS = [
    { file: 'core-router-01.cfg', note: '!', score: '2 / 100 · CRITICAL', lines: [
      ['! running-config', 'c'], ['hostname core-router-01'],
      ['enable password C1sc0Lab', 'AUTH-001'], ['ip http server', 'SVC-001'],
      ['snmp-server community public RO', 'SNMP-001'], ['snmp-server community private RW', 'SNMP-001'],
      ['interface GigabitEthernet0/0'], [' description WAN Uplink'], [' ip address 203.0.113.1 255.255.255.252'],
      ['interface GigabitEthernet0/3', 'INTF-001']] },
    { file: 'edge-router-jnpr.conf', note: '##', score: '7 / 100 · CRITICAL', lines: [
      ['system {'], ['  host-name edge-router-jnpr;'], ['  services {'],
      ['    telnet;', 'AUTH-003'], ['    http;', 'SVC-001'], ['  }'], ['snmp {'],
      ['  community public {', 'SNMP-001'], ['  community private {', 'SNMP-001'],
      ['term ALLOW_ALL { then accept; }', 'ACL-001']] },
    { file: 'fortigate-branch.conf', note: '#', score: '6 / 100 · CRITICAL', lines: [
      ['config system global'], ['  set hostname FortiGate-Branch'], ['config system interface'],
      ['  edit "wan1"'], ['    set allowaccess https ssh http telnet', 'AUTH-003'],
      ['config system snmp community'], ['    set name "public"', 'SNMP-001'],
      ['config log syslogd setting'], ['  set status disable', 'LOG-001'],
      ['config firewall policy'], ['    set srcaddr "all"', 'ACL-001']] },
  ];

  /* Only animate while the hero is on screen and the tab is visible. */
  let visible = true;
  new IntersectionObserver(function (e) { visible = e[0].isIntersecting; }).observe(pre);
  const sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
  async function tick(ms) { do { await sleep(ms); } while (!visible || document.hidden); }

  const caret = document.createElement('i');
  caret.className = 'caret';
  function row(text, cls) {
    const s = document.createElement('span');
    s.className = 'tl' + (cls ? ' ' + cls : '');
    s.textContent = text;
    pre.append(s);
    return s;
  }
  async function type(el, text, ms) {
    for (let i = 1; i <= text.length; i++) {
      el.textContent = text.slice(0, i);
      el.append(caret);
      await tick(ms);
    }
    caret.remove();
  }
  function setStatus(text, state) {
    status.textContent = text;
    status.className = 'term-status ' + state;
  }
  function flagged(n) { return n + ' line' + (n === 1 ? '' : 's') + ' flagged'; }

  async function run(r) {
    pre.replaceChildren();
    pre.classList.remove('fade');
    file.textContent = r.file;
    progress.style.width = '0%';
    found.textContent = 'starting';
    setStatus('running', 'run');
    await type(row('', 'cmd'), '$ net-audit ' + r.file, 32);
    await tick(300);

    setStatus('parsing', 'run');
    const lines = r.lines.map(function (l) {
      const el = row(l[0], 'n' + (l[1] === 'c' ? ' c' : ''));
      if (l[1] && l[1] !== 'c') {
        const tag = document.createElement('em');
        tag.textContent = l[1];
        el.append(tag);
        el.dataset.hit = '1';
      }
      el.hidden = true;
      return el;
    });
    for (let i = 0; i < lines.length; i++) {
      lines[i].hidden = false;
      found.textContent = (i + 1) + ' lines read';
      await tick(60);
    }

    setStatus('checking ' + rules + ' rules', 'run');
    found.textContent = flagged(0);
    await tick(250);
    let hits = 0;
    for (let i = 0; i < lines.length; i++) {
      const el = lines[i];
      el.classList.add('scan');
      progress.style.width = ((i + 1) / lines.length * 100) + '%';
      await tick(el.dataset.hit ? 320 : 120);
      el.classList.remove('scan');
      if (el.dataset.hit) {
        /* Flash bright, then settle into the flagged colour. */
        el.classList.add('flash');
        found.textContent = flagged(++hits);
        await tick(140);
        el.classList.replace('flash', 'hit');
      }
    }

    await type(row('', 'c score'), r.note + ' score ' + r.score, 26);
    setStatus(r.score.split(' · ')[0], 'done');
    found.textContent = flagged(hits) + ' · ' + rules + ' rules';
    await tick(3400);
    pre.classList.add('fade');
    await tick(400);
  }

  (async function loop() {
    await tick(900);                       /* let the static first frame land */
    for (let i = 0; ; i = (i + 1) % RUNS.length) await run(RUNS[i]);
  })();
}
