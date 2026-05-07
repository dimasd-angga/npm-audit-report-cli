import type { AuditReport, Severity, Vulnerability } from './types.js';

const SEVERITY_ORDER: Severity[] = ['info', 'low', 'moderate', 'high', 'critical'];

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(threshold);
}

export function shouldFail(report: AuditReport, failOn: Severity | 'none'): boolean {
  if (failOn === 'none') return false;
  return report.vulnerabilities.some((v) => meetsThreshold(v.severity, failOn));
}

export function filterBySeverity(vulns: Vulnerability[], minSeverity: Severity): Vulnerability[] {
  return vulns.filter((v) => meetsThreshold(v.severity, minSeverity));
}
