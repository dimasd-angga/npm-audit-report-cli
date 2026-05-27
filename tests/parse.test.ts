import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse, ParseError } from '../src/parse.js';

const fixturesDir = join(__dirname, 'fixtures');
const v6 = readFileSync(join(fixturesDir, 'v6-audit.json'), 'utf8');
const v7 = readFileSync(join(fixturesDir, 'v7-audit.json'), 'utf8');
const empty = readFileSync(join(fixturesDir, 'empty-audit.json'), 'utf8');

describe('parse', () => {
  it('parses v6 fixture without error', () => {
    const r = parse(v6);
    expect(r.vulnerabilities.length).toBe(3);
    expect(r.meta.totalDependencies).toBe(342);
  });

  it('parses v7 fixture without error', () => {
    const r = parse(v7);
    expect(r.vulnerabilities.length).toBe(3);
    expect(r.meta.totalDependencies).toBe(342);
  });

  it('parses empty fixture, returns empty vulnerabilities array', () => {
    const r = parse(empty);
    expect(r.vulnerabilities).toEqual([]);
    expect(r.summary.total).toBe(0);
  });

  it('throws ParseError on invalid JSON', () => {
    expect(() => parse('{not valid')).toThrow(ParseError);
    expect(() => parse('{not valid')).toThrow('Invalid JSON input');
  });

  it('throws ParseError on unknown schema', () => {
    expect(() => parse(JSON.stringify({ foo: 'bar' }))).toThrow(ParseError);
    expect(() => parse(JSON.stringify({ foo: 'bar' }))).toThrow('Unrecognized npm audit schema');
  });

  it('v6 and v7 fixtures produce equivalent normalized output for same vulns', () => {
    const a = parse(v6);
    const b = parse(v7);

    const aSorted = [...a.vulnerabilities].sort((x, y) => x.name.localeCompare(y.name));
    const bSorted = [...b.vulnerabilities].sort((x, y) => x.name.localeCompare(y.name));

    expect(aSorted.length).toBe(bSorted.length);
    for (let i = 0; i < aSorted.length; i++) {
      expect(aSorted[i]!.name).toBe(bSorted[i]!.name);
      expect(aSorted[i]!.severity).toBe(bSorted[i]!.severity);
      expect(aSorted[i]!.range).toBe(bSorted[i]!.range);
      expect(aSorted[i]!.title).toBe(bSorted[i]!.title);
      expect(aSorted[i]!.fixAvailable).toBe(bSorted[i]!.fixAvailable);
    }

    expect(a.summary.critical).toBe(b.summary.critical);
    expect(a.summary.high).toBe(b.summary.high);
    expect(a.summary.moderate).toBe(b.summary.moderate);
  });
});
