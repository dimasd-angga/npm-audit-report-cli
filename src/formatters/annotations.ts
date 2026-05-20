import type { AuditReport, FormatOptions, Severity } from '../types.js';
import { filterBySeverity } from '../threshold.js';

type AnnotationLevel = 'error' | 'warning' | 'notice';

function severityToAnnotation(s: Severity): AnnotationLevel {
  if (s === 'critical' || s === 'high') return 'error';
  if (s === 'moderate') return 'warning';
  return 'notice';
}

function escapeAnnotation(s: string): string {
  return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProperty(s: string): string {
  return escapeAnnotation(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

export function annotations(report: AuditReport, opts: FormatOptions = {}): string {
  const minSeverity = opts.severity ?? 'info';
  const filtered = filterBySeverity(report.vulnerabilities, minSeverity);

  const lines = filtered.map((v) => {
    const level = severityToAnnotation(v.severity);
    const fixPart = v.fixAvailable && v.fixCommand ? `fix: ${v.fixCommand}` : 'no fix';
    const message = `${v.name} — ${v.title}, affected: ${v.range} (${fixPart})`;
    const titleProp = escapeProperty(v.id);
    return `::${level} file=package.json,title=${titleProp}::${escapeAnnotation(message)}`;
  });

  return lines.join('\n');
}
