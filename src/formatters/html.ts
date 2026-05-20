import type { AuditReport, FormatOptions, Severity, Vulnerability } from '../types.js';
import { filterBySeverity } from '../threshold.js';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'moderate', 'low', 'info'];

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#fee2e2',
  high: '#ffedd5',
  moderate: '#fef9c3',
  low: '#dbeafe',
  info: '#f0fdf4',
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  moderate: 'Moderate',
  low: 'Low',
  info: 'Info',
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  moderate: 3,
  low: 2,
  info: 1,
};

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function countBySeverity(vulns: Vulnerability[]): Record<Severity, number> {
  const r: Record<Severity, number> = { critical: 0, high: 0, moderate: 0, low: 0, info: 0 };
  for (const v of vulns) r[v.severity] += 1;
  return r;
}

export function html(report: AuditReport, opts: FormatOptions = {}): string {
  const title = opts.title ?? 'npm audit report';
  const minSeverity = opts.severity ?? 'info';
  const filtered = filterBySeverity(report.vulnerabilities, minSeverity);
  const date = report.meta.auditedAt ? report.meta.auditedAt.slice(0, 10) : '';

  const styles = `
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 2rem; color: #1f2937; background: #f9fafb; }
    .container { max-width: 1100px; margin: 0 auto; background: #ffffff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); padding: 2rem; }
    h1 { margin: 0 0 0.5rem; font-size: 1.6rem; }
    .meta { color: #6b7280; font-size: 0.9rem; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; font-size: 0.95rem; }
    th, td { padding: 0.6rem 0.75rem; text-align: left; border-bottom: 1px solid #e5e7eb; }
    th { background: #f3f4f6; cursor: pointer; user-select: none; font-weight: 600; }
    th[data-sort] .arrow { color: #9ca3af; font-size: 0.75rem; margin-left: 0.25rem; }
    th.sorted-asc .arrow::after { content: " ▲"; color: #1f2937; }
    th.sorted-desc .arrow::after { content: " ▼"; color: #1f2937; }
    tr.sev-critical { background: ${SEVERITY_COLOR.critical}; }
    tr.sev-high { background: ${SEVERITY_COLOR.high}; }
    tr.sev-moderate { background: ${SEVERITY_COLOR.moderate}; }
    tr.sev-low { background: ${SEVERITY_COLOR.low}; }
    tr.sev-info { background: ${SEVERITY_COLOR.info}; }
    details { margin-bottom: 0.5rem; }
    summary { cursor: pointer; padding: 0.4rem 0; font-weight: 600; }
    .badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge-critical { background: #dc2626; color: white; }
    .badge-high { background: #ea580c; color: white; }
    .badge-moderate { background: #ca8a04; color: white; }
    .badge-low { background: #2563eb; color: white; }
    .badge-info { background: #16a34a; color: white; }
    code { background: #f3f4f6; padding: 0.1rem 0.3rem; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace; font-size: 0.85rem; }
    .empty { padding: 2rem; text-align: center; color: #6b7280; }
    .empty-icon { font-size: 3rem; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
    .summary-card { padding: 0.85rem; border-radius: 6px; border: 1px solid #e5e7eb; }
    .summary-card .label { font-size: 0.75rem; text-transform: uppercase; color: #6b7280; font-weight: 600; letter-spacing: 0.03em; }
    .summary-card .value { font-size: 1.4rem; font-weight: 700; margin-top: 0.15rem; }
    footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 0.85rem; text-align: center; }
    @media print {
      body { background: white; padding: 0; }
      .container { box-shadow: none; padding: 0; }
      th { cursor: default; }
      th .arrow { display: none; }
      details { break-inside: avoid; }
      details[open] summary { display: list-item; }
    }
  `;

  const counts = countBySeverity(filtered);

  let body = '';
  if (filtered.length === 0) {
    body = `<div class="empty"><div class="empty-icon">✅</div><h2>No vulnerabilities found</h2><p>Audited ${report.meta.totalDependencies} dependencies</p></div>`;
  } else {
    const summaryCards = SEVERITY_ORDER.map((sev) => {
      const c = counts[sev];
      return `<div class="summary-card" style="background:${SEVERITY_COLOR[sev]}"><div class="label">${SEVERITY_LABEL[sev]}</div><div class="value">${c}</div></div>`;
    }).join('');

    const rows = filtered
      .map((v) => {
        const fix = v.fixAvailable && v.fixCommand ? `<code>${escapeHtml(v.fixCommand)}</code>` : 'No fix';
        return `<tr class="sev-${v.severity}" data-severity="${SEVERITY_RANK[v.severity]}" data-name="${escapeHtml(v.name)}">
          <td><span class="badge badge-${v.severity}">${SEVERITY_LABEL[v.severity]}</span></td>
          <td><strong>${escapeHtml(v.name)}</strong></td>
          <td>${escapeHtml(v.title)}</td>
          <td><code>${escapeHtml(v.range)}</code></td>
          <td>${fix}</td>
        </tr>`;
      })
      .join('\n');

    body = `
      <div class="summary-grid">${summaryCards}</div>
      <table id="vuln-table">
        <thead>
          <tr>
            <th data-sort="severity">Severity<span class="arrow"></span></th>
            <th data-sort="name">Package<span class="arrow"></span></th>
            <th data-sort="title">Title<span class="arrow"></span></th>
            <th data-sort="range">Range<span class="arrow"></span></th>
            <th data-sort="fix">Fix<span class="arrow"></span></th>
          </tr>
        </thead>
        <tbody>
${rows}
        </tbody>
      </table>
    `;
  }

  const sortScript = `
    (function(){
      var table = document.getElementById('vuln-table');
      if (!table) return;
      var headers = table.querySelectorAll('th[data-sort]');
      headers.forEach(function(h, idx){
        h.addEventListener('click', function(){
          var asc = !h.classList.contains('sorted-asc');
          headers.forEach(function(other){ other.classList.remove('sorted-asc','sorted-desc'); });
          h.classList.add(asc ? 'sorted-asc' : 'sorted-desc');
          var tbody = table.querySelector('tbody');
          var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
          rows.sort(function(a, b){
            var key = h.getAttribute('data-sort');
            var av, bv;
            if (key === 'severity') {
              av = parseInt(a.getAttribute('data-severity'), 10);
              bv = parseInt(b.getAttribute('data-severity'), 10);
            } else {
              av = a.children[idx].textContent.trim().toLowerCase();
              bv = b.children[idx].textContent.trim().toLowerCase();
            }
            if (av < bv) return asc ? -1 : 1;
            if (av > bv) return asc ? 1 : -1;
            return 0;
          });
          rows.forEach(function(r){ tbody.appendChild(r); });
        });
      });
    })();
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} — ${escapeHtml(date)}</title>
<style>${styles}</style>
</head>
<body>
<div class="container">
  <h1>${escapeHtml(title)}</h1>
  <div class="meta">Audited ${escapeHtml(date)} · ${report.meta.totalDependencies} dependencies · ${filtered.length} vulnerabilities</div>
  ${body}
  <footer>Generated by audit-report</footer>
</div>
<script>${sortScript}</script>
</body>
</html>`;
}
