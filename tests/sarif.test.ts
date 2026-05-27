import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from '../src/parse.js';
import { sarif } from '../src/formatters/sarif.js';

const fixturesDir = join(__dirname, 'fixtures');
const v7 = readFileSync(join(fixturesDir, 'v7-audit.json'), 'utf8');

describe('sarif formatter', () => {
  it('output is valid JSON', () => {
    const r = parse(v7);
    const out = sarif(r);
    expect(() => JSON.parse(out)).not.toThrow();
  });

  it('contains $schema field pointing to SARIF 2.1.0', () => {
    const r = parse(v7);
    const out = sarif(r);
    const doc = JSON.parse(out);
    expect(doc.$schema).toContain('sarif-schema-2.1.0.json');
    expect(doc.version).toBe('2.1.0');
  });

  it('level is "error" for critical and high', () => {
    const r = parse(v7);
    const out = sarif(r);
    const doc = JSON.parse(out);
    const results = doc.runs[0].results;
    const errorCount = results.filter((x: { level: string }) => x.level === 'error').length;
    expect(errorCount).toBeGreaterThanOrEqual(2);
  });

  it('level is "warning" for moderate', () => {
    const r = parse(v7);
    const out = sarif(r);
    const doc = JSON.parse(out);
    const results = doc.runs[0].results;
    const warningCount = results.filter((x: { level: string }) => x.level === 'warning').length;
    expect(warningCount).toBeGreaterThanOrEqual(1);
  });

  it('level is "note" for low/info', () => {
    const lowJson = JSON.stringify({
      auditReportVersion: 2,
      vulnerabilities: {
        foo: {
          name: 'foo',
          severity: 'low',
          via: [{ source: 1, title: 't', url: 'u', range: '<1' }],
          range: '<1',
          nodes: ['node_modules/foo'],
          fixAvailable: false,
        },
      },
      metadata: { vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 1, info: 0, total: 1 }, totalDependencies: 1 },
    });
    const r = parse(lowJson);
    const out = sarif(r);
    const doc = JSON.parse(out);
    expect(doc.runs[0].results[0].level).toBe('note');
  });

  it('output is pretty-printed (2-space indent)', () => {
    const r = parse(v7);
    const out = sarif(r);
    expect(out).toContain('\n  ');
  });
});
