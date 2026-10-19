/* ════════════════════════════════════════════════════════════════
   results.js  |  Initialise charts + results page interactions
   ════════════════════════════════════════════════════════════════ */
'use strict';

const report = window.__REPORT__ || {};

/* ── Device report ─────────────────────────────────────────────── */
if (report.report_type === 'device') {
  buildGauge(report.score || 0);
  buildSeverityBar(
    report.critical || 0,
    report.high     || 0,
    report.medium   || 0,
    report.low      || 0
  );
  buildRadar(report.findings || []);
}

/* ── Aggregate report ──────────────────────────────────────────── */
if (report.report_type === 'aggregate') {
  buildFleetChart(report.devices || []);
  buildAggSeverity(report);
}

/* ── Toggle per-device findings row (aggregate table) ──────────── */
function toggleDeviceFindings(btn, idx) {
  const row = document.getElementById('dev-findings-' + idx);
  if (!row) return;
  const hidden = row.classList.toggle('d-none');
  btn.setAttribute('aria-expanded', String(!hidden));
  btn.querySelector('i').className = hidden ? 'bi bi-chevron-down' : 'bi bi-chevron-up';
}
