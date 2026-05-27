import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from '../src/parse.js';
import { html } from '../src/formatters/html.js';

const fixturesDir = join(__dirname, 'fixtures');
const v7 = readFileSync(join(fixturesDir, 'v7-audit.json'), 'utf8');
const empty = readFileSync(join(fixturesDir, 'empty-audit.json'), 'utf8');

describe('html formatter', () => {
  it('output is valid HTML (contains <html>, <head>, <body>)', () => {
    const r = parse(v7);
    const out = html(r);
    expect(out).toContain('<html');
    expect(out).toContain('<head>');
    expect(out).toContain('<body>');
    expect(out).toContain('</html>');
  });

  it('contains no external resource URLs in src= or href=', () => {
    const r = parse(v7);
    const out = html(r);
    expect(out).not.toMatch(/\b(?:src|href)\s*=\s*["']https?:\/\//);
  });

  it('contains severity color styling', () => {
    const r = parse(v7);
    const out = html(r);
    expect(out).toContain('#fee2e2');
    expect(out).toContain('#ffedd5');
    expect(out).toContain('#fef9c3');
  });

  it('zero vulns case handled', () => {
    const r = parse(empty);
    const out = html(r);
    expect(out).toContain('No vulnerabilities found');
  });

  it('output size under 80KB even with vulns', () => {
    const r = parse(v7);
    const out = html(r);
    expect(Buffer.byteLength(out, 'utf8')).toBeLessThan(80 * 1024);
  });
});
