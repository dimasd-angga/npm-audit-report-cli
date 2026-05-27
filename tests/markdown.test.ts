import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from '../src/parse.js';
import { markdown } from '../src/formatters/markdown.js';

const fixturesDir = join(__dirname, 'fixtures');
const v7 = readFileSync(join(fixturesDir, 'v7-audit.json'), 'utf8');
const empty = readFileSync(join(fixturesDir, 'empty-audit.json'), 'utf8');

describe('markdown formatter', () => {
  it('contains severity summary table', () => {
    const r = parse(v7);
    const md = markdown(r);
    expect(md).toContain('| Severity | Count | Fixable |');
    expect(md).toContain('Critical');
    expect(md).toContain('High');
    expect(md).toContain('Moderate');
  });

  it('contains <details> block for each severity group present', () => {
    const r = parse(v7);
    const md = markdown(r);
    const detailsCount = (md.match(/<details>/g) || []).length;
    expect(detailsCount).toBe(3);
  });

  it('zero vulns => contains "No vulnerabilities found"', () => {
    const r = parse(empty);
    const md = markdown(r);
    expect(md).toContain('No vulnerabilities found');
  });

  it('respects severity filter (low excluded when --severity high)', () => {
    const r = parse(v7);
    const md = markdown(r, { severity: 'high' });
    expect(md).toContain('Critical');
    expect(md).toContain('High');
    expect(md).not.toContain('Moderate (');
  });

  it('no external image URLs in output', () => {
    const r = parse(v7);
    const md = markdown(r);
    expect(md).not.toMatch(/!\[[^\]]*\]\(https?:\/\//);
  });

  it('honors custom title', () => {
    const r = parse(v7);
    const md = markdown(r, { title: 'My Audit' });
    expect(md).toContain('## My Audit');
  });
});
