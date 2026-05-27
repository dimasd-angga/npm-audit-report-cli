import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from '../src/parse.js';
import { annotations } from '../src/formatters/annotations.js';

const fixturesDir = join(__dirname, 'fixtures');
const v7 = readFileSync(join(fixturesDir, 'v7-audit.json'), 'utf8');

describe('annotations formatter', () => {
  it('critical entry produces ::error line', () => {
    const r = parse(v7);
    const out = annotations(r);
    const lines = out.split('\n');
    const critLine = lines.find((l) => l.includes('lodash'));
    expect(critLine).toBeDefined();
    expect(critLine!.startsWith('::error')).toBe(true);
  });

  it('moderate entry produces ::warning line', () => {
    const r = parse(v7);
    const out = annotations(r);
    const lines = out.split('\n');
    const modLine = lines.find((l) => l.includes('minimatch'));
    expect(modLine).toBeDefined();
    expect(modLine!.startsWith('::warning')).toBe(true);
  });

  it('low severity produces ::notice line', () => {
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
    const out = annotations(r);
    expect(out.startsWith('::notice')).toBe(true);
  });

  it('every line contains file=package.json', () => {
    const r = parse(v7);
    const out = annotations(r);
    const lines = out.split('\n');
    for (const line of lines) {
      expect(line).toContain('file=package.json');
    }
  });
});
