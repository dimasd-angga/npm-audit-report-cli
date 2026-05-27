import { describe, it, expect } from 'vitest';
import { meetsThreshold, shouldFail, filterBySeverity } from '../src/threshold.js';
import type { AuditReport, Vulnerability } from '../src/types.js';

function mkVuln(severity: Vulnerability['severity'], name = 'pkg'): Vulnerability {
  return {
    id: 'id',
    name,
    severity,
    title: 't',
    url: '',
    range: '*',
    fixAvailable: false,
    paths: [],
  };
}

function mkReport(vulns: Vulnerability[]): AuditReport {
  return {
    meta: { npmVersion: '', nodeVersion: '', auditedAt: '', totalDependencies: 0 },
    summary: { critical: 0, high: 0, moderate: 0, low: 0, info: 0, total: vulns.length },
    vulnerabilities: vulns,
  };
}

describe('threshold', () => {
  it('meetsThreshold critical >= high', () => {
    expect(meetsThreshold('critical', 'high')).toBe(true);
  });
  it('meetsThreshold low < high', () => {
    expect(meetsThreshold('low', 'high')).toBe(false);
  });
  it('meetsThreshold equal is true', () => {
    expect(meetsThreshold('high', 'high')).toBe(true);
  });
  it('shouldFail returns false when failOn is none', () => {
    const r = mkReport([mkVuln('critical')]);
    expect(shouldFail(r, 'none')).toBe(false);
  });
  it('shouldFail true when threshold met', () => {
    const r = mkReport([mkVuln('critical')]);
    expect(shouldFail(r, 'high')).toBe(true);
  });
  it('shouldFail false when threshold not met', () => {
    const r = mkReport([mkVuln('low')]);
    expect(shouldFail(r, 'high')).toBe(false);
  });
  it('filterBySeverity removes entries below threshold', () => {
    const vulns = [mkVuln('low', 'a'), mkVuln('high', 'b'), mkVuln('critical', 'c')];
    const filtered = filterBySeverity(vulns, 'high');
    expect(filtered.map((v) => v.name)).toEqual(['b', 'c']);
  });
});
