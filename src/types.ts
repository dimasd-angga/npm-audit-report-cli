export type Severity = 'critical' | 'high' | 'moderate' | 'low' | 'info';
export type Format = 'markdown' | 'html' | 'sarif' | 'annotations';

export interface Vulnerability {
  id: string;
  name: string;
  severity: Severity;
  title: string;
  url: string;
  range: string;
  fixAvailable: boolean;
  fixCommand?: string;
  paths: string[];
}

export interface AuditMeta {
  npmVersion: string;
  nodeVersion: string;
  auditedAt: string;
  totalDependencies: number;
}

export interface AuditSummary {
  critical: number;
  high: number;
  moderate: number;
  low: number;
  info: number;
  total: number;
}

export interface AuditReport {
  meta: AuditMeta;
  summary: AuditSummary;
  vulnerabilities: Vulnerability[];
}

export interface FormatOptions {
  format?: Format;
  severity?: Severity;
  failOn?: Severity | 'none';
  title?: string;
  template?: string;
}
