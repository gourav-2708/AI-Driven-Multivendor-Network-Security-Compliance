/* ════════════════════════════════════════════════════════════════
   charts.js  |  Chart.js visualisations — unchanged data logic
   Updated: adapted to CSS variable colours + light/dark theme
   ════════════════════════════════════════════════════════════════ */
'use strict';

/* ── Resolve CSS vars at runtime for accurate theming ─────────── */
function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

const COLORS = {
  critical: '#f87171',
  high    : '#fb923c',
  medium  : '#fbbf24',
  low     : '#38bdf8',
  good    : '#34d399',
  accent  : '#818cf8',
  muted   : '#64748b',
};

/* Chart.js defaults */
Chart.defaults.color       = COLORS.muted;
Chart.defaults.borderColor = 'rgba(51,65,85,0.5)';
Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
Chart.defaults.font.size   = 12;


/* ────────────────────────────────────────────────────────────────
   SVG GAUGE  (no canvas needed)
   ────────────────────────────────────────────────────────────── */
function buildGauge(score) {
  const s     = Math.max(0, Math.min(100, Number(score) || 0));
  const arc   = document.getElementById('gauge-arc');
  const num   = document.getElementById('gauge-number');
  const grade = document.getElementById('gauge-grade');
  if (!arc || !num) return;

  const color = s >= 80 ? COLORS.good
              : s >= 50 ? COLORS.medium
              : s >= 25 ? COLORS.high
              : COLORS.critical;

  // Semicircle arc-length = PI × r = PI × 88 ≈ 276.46
  const total  = 276.46;
  const filled = (s / 100) * total;
  const offset = total - filled;

  arc.style.stroke           = color;
  arc.style.strokeDashoffset = offset.toFixed(2);
  num.textContent            = s;
  num.setAttribute('fill', color);

  if (grade) {
    const label = s >= 80 ? 'SECURE' : s >= 50 ? 'AT RISK' : s >= 25 ? 'POOR' : 'CRITICAL';
    grade.textContent = label;
    grade.setAttribute('fill', color);
    grade.style.display = 'block';
    num.setAttribute('y', '90');
    grade.setAttribute('y', '108');
  }

  const label = document.getElementById('gauge-score');
  if (label) { label.textContent = s; label.style.color = color; }
}


/* ────────────────────────────────────────────────────────────────
   SEVERITY BAR CHART
   ────────────────────────────────────────────────────────────── */
function buildSeverityBar(critical, high, medium, low) {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels  : ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data           : [critical, high, medium, low],
        backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low],
        borderRadius   : 6,
        borderSkipped  : false,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend : { display: false },
        tooltip: { callbacks: {
          label: ctx => ` ${ctx.raw} finding${ctx.raw !== 1 ? 's' : ''}`
        }}
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: { stepSize: 1, precision: 0, color: COLORS.muted },
          grid : { color: 'rgba(255,255,255,0.05)' },
        },
        x: { grid: { display: false }, ticks: { color: COLORS.muted } },
      },
      animation: { duration: 700, easing: 'easeOutQuart' },
    }
  });
}


/* ────────────────────────────────────────────────────────────────
   CATEGORY RADAR CHART
   ────────────────────────────────────────────────────────────── */
function buildRadar(findings) {
  const ctx = document.getElementById('radarChart');
  if (!ctx) return;

  const categories = ['AUTH','PASSWD','ACL','SNMP','SVC','LOG','NTP','INTF'];
  const prefix2cat = {
    'AUTH-': 'AUTH', 'PASSWD-': 'PASSWD', 'ACL-': 'ACL',
    'SNMP-': 'SNMP', 'SVC-': 'SVC', 'LOG-': 'LOG',
    'NTP-': 'NTP', 'INTF-': 'INTF',
  };

  const counts = Object.fromEntries(categories.map(c => [c, 0]));
  for (const f of (findings || [])) {
    for (const [pfx, cat] of Object.entries(prefix2cat)) {
      if (f.rule_id && f.rule_id.startsWith(pfx)) { counts[cat]++; break; }
    }
  }

  const scores = categories.map(c => Math.max(0, 100 - counts[c] * 25));

  new Chart(ctx, {
    type: 'radar',
    data: {
      labels  : categories,
      datasets: [{
        label              : 'Compliance',
        data               : scores,
        backgroundColor    : 'rgba(129,140,248,0.12)',
        borderColor        : COLORS.accent,
        pointBackgroundColor: COLORS.accent,
        pointBorderColor   : 'transparent',
        pointHoverRadius   : 5,
        borderWidth        : 1.5,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          beginAtZero: true,
          max: 100,
          ticks        : { display: false, stepSize: 25 },
          grid         : { color: 'rgba(255,255,255,0.06)' },
          angleLines   : { color: 'rgba(255,255,255,0.06)' },
          pointLabels  : { font: { size: 10 }, color: COLORS.muted },
        }
      },
      plugins: { legend: { display: false } },
      animation: { duration: 700, easing: 'easeOutQuart' },
    }
  });
}


/* ────────────────────────────────────────────────────────────────
   FLEET HORIZONTAL BAR CHART
   ────────────────────────────────────────────────────────────── */
function buildFleetChart(devices) {
  const ctx = document.getElementById('fleetChart');
  if (!ctx || !devices) return;

  const labels = devices.map(d => d.hostname || '(unknown)');
  const scores = devices.map(d => d.score);
  const colors = scores.map(s =>
    s >= 80 ? COLORS.good : s >= 50 ? COLORS.medium : COLORS.critical
  );

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label          : 'Compliance Score',
        data           : scores,
        backgroundColor: colors,
        borderRadius   : 6,
        borderSkipped  : false,
      }]
    },
    options: {
      indexAxis : 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend : { display: false },
        tooltip: { callbacks: { label: ctx => ` Score: ${ctx.raw}/100` } }
      },
      scales: {
        x: { beginAtZero: true, max: 100, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: COLORS.muted } },
        y: { grid: { display: false }, ticks: { color: COLORS.muted, font: { family: "'JetBrains Mono', monospace", size: 11 } } },
      },
      animation: { duration: 700, easing: 'easeOutQuart' },
    }
  });
}


/* ────────────────────────────────────────────────────────────────
   AGGREGATE SEVERITY DOUGHNUT
   ────────────────────────────────────────────────────────────── */
function buildAggSeverity(report) {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;
  const { total_critical: c=0, total_high: h=0, total_medium: m=0, total_low: l=0 } = report;

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels  : ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data           : [c, h, m, l],
        backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low],
        borderWidth    : 0,
        hoverOffset    : 4,
      }]
    },
    options: {
      cutout  : '68%',
      plugins : {
        legend: {
          position: 'bottom',
          labels  : { boxWidth: 10, padding: 12, font: { size: 11 }, color: COLORS.muted }
        }
      },
      animation: { duration: 700, easing: 'easeOutQuart' },
    }
  });
}
