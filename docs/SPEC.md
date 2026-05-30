# audit-report — Agent Build Spec

## What you are building

A zero-dependency TypeScript CLI + Node.js library called `audit-report`.

It reads `npm audit --json` output (stdin or file) and converts it to Markdown, HTML, SARIF, or GitHub Actions annotations.

**npm publish target:** `audit-report` (check if name is taken first, fallback: `@dimasctech/audit-report`)

---

## Repository structure

```
audit-report/
  src/
    cli.ts              # Entry point — arg parsing, stdin/file input
    parse.ts            # JSON normalization (npm v6 + v7 schemas)
    threshold.ts        # Exit code logic by severity
    types.ts            # All shared TypeScript interfaces
    index.ts            # Public library API exports
    formatters/
      markdown.ts
      html.ts
      sarif.ts
      annotations.ts
  tests/
    parse.test.ts
    markdown.test.ts
    html.test.ts
    sarif.test.ts
    annotations.test.ts
    threshold.test.ts
    fixtures/
      v6-audit.json     # Real npm v6 audit JSON sample
      v7-audit.json     # Real npm v7+ audit JSON sample
      empty-audit.json  # Zero vulnerabilities case
  dist/                 # Compiled output — gitignored
  action.yml            # GitHub composite action
  package.json
  tsconfig.json
  tsconfig.build.json
  .github/
    workflows/
      ci.yml
  README.md
  CHANGELOG.md
```

---

## package.json

```json
{
  "name": "audit-report",
  "version": "1.0.0",
  "description": "Convert npm audit JSON to Markdown, HTML, SARIF, or GitHub annotations — zero dependencies",
  "license": "MIT",
  "type": "module",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "require": "./dist/index.cjs"
    }
  },
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "bin": {
    "audit-report": "./dist/cli.js"
  },
  "files": ["dist", "action.yml"],
  "engines": { "node": ">=18.0.0" },
  "scripts": {
    "build": "tsup",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "tsc --noEmit",
    "prepublishOnly": "npm run build && npm test"
  },
  "devDependencies": {
    "tsup": "^8.0.0",
    "typescript": "^5.4.0",
    "vitest": "^1.6.0"
  }
}
```

**Zero runtime dependencies. devDependencies only.**

---

## tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noImplicitAny": true,
    "noUncheckedIndexedAccess": true,
    "declaration": true,
    "outDir": "dist"
  },
  "include": ["src"]
}
```

## tsconfig.build.json

```json
{
  "extends": "./tsconfig.json",
  "exclude": ["src/**/*.test.ts", "tests"]
}
```

---

## tsup config (in package.json or tsup.config.ts)

```ts
// tsup.config.ts
import { defineConfig } from 'tsup';
export default defineConfig({
  entry: { index: 'src/index.ts', cli: 'src/cli.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  minify: false,
});
```

---

## src/types.ts

```ts
export type Severity = 'critical' | 'high' | 'moderate' | 'low' | 'info';
export type Format = 'markdown' | 'html' | 'sarif' | 'annotations';

export interface Vulnerability {
  id: string;           // Advisory ID or CVE (e.g. "GHSA-xxxx" or "CVE-2024-1234")
  name: string;         // Package name (e.g. "lodash")
  severity: Severity;
  title: string;        // Human-readable title
  url: string;          // Advisory URL
  range: string;        // Vulnerable version range (e.g. "<4.17.21")
  fixAvailable: boolean;
  fixCommand?: string;  // e.g. "npm install lodash@4.17.21"
  paths: string[];      // Dependency paths where this appears
}

export interface AuditMeta {
  npmVersion: string;
  nodeVersion: string;
  auditedAt: string;    // ISO 8601
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
  template?: string;    // Path to custom Markdown template
}
```

---

## src/parse.ts

Normalize both npm audit JSON schemas into `AuditReport`.

### npm v6 shape (key fields)
```json
{
  "auditReportVersion": 1,
  "advisories": {
    "1234": {
      "id": 1234,
      "title": "Prototype Pollution",
      "severity": "high",
      "url": "https://npmjs.com/advisories/1234",
      "vulnerable_versions": "<4.17.21",
      "cves": ["CVE-2021-23337"],
      "findings": [{ "paths": ["lodash"] }],
      "fixAvailable": true
    }
  },
  "metadata": {
    "vulnerabilities": { "critical": 0, "high": 1, "moderate": 0, "low": 0 },
    "totalDependencies": 342
  }
}
```

### npm v7+ shape (key fields)
```json
{
  "auditReportVersion": 2,
  "vulnerabilities": {
    "lodash": {
      "name": "lodash",
      "severity": "high",
      "via": [{ "title": "Prototype Pollution", "url": "https://...", "range": "<4.17.21", "cwe": [] }],
      "fixAvailable": { "name": "lodash", "version": "4.17.21" },
      "nodes": ["node_modules/lodash"]
    }
  },
  "metadata": {
    "vulnerabilities": { "critical": 0, "high": 1, "moderate": 0, "low": 0, "info": 0, "total": 1 },
    "totalDependencies": 342
  }
}
```

### Detection logic
- `auditReportVersion === 1` → v6 parser
- `auditReportVersion === 2` → v7 parser
- If field missing, try v7 parser first, fallback to v6

### Error handling
- Invalid JSON → throw `ParseError` with message "Invalid JSON input"
- Unknown schema → throw `ParseError` with message "Unrecognized npm audit schema"
- Empty/zero vulnerabilities → return valid `AuditReport` with empty array (not an error)

---

## src/threshold.ts

```ts
const SEVERITY_ORDER: Severity[] = ['info', 'low', 'moderate', 'high', 'critical'];

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(threshold);
}

export function shouldFail(report: AuditReport, failOn: Severity | 'none'): boolean {
  if (failOn === 'none') return false;
  return report.vulnerabilities.some(v => meetsThreshold(v.severity, failOn));
}

export function filterBySeverity(vulns: Vulnerability[], minSeverity: Severity): Vulnerability[] {
  return vulns.filter(v => meetsThreshold(v.severity, minSeverity));
}
```

---

## src/formatters/markdown.ts

Output is GitHub Flavored Markdown.

### Structure
```
## {title}

> {total} vulnerabilities found · audited {date} · {totalDeps} dependencies

| Severity | Count | Fixable |
|----------|-------|---------|
| 🔴 Critical | N | N |
| 🟠 High | N | N |
| 🟡 Moderate | N | N |
| 🔵 Low | N | N |

---

<details>
<summary>🔴 Critical (N)</summary>

### {package-name}
- **ID:** {id}
- **Title:** {title}
- **Range:** `{range}`
- **Fix:** `{fixCommand}` / No fix available
- **Advisory:** {url}
- **Paths:** `{paths.join(', ')}`

</details>

---
*Generated by [audit-report](https://github.com/dimasdarfi/audit-report) v{version}*
```

Rules:
- One `<details>` block per severity group, sorted critical → info
- Skip severity groups with zero findings
- If zero total vulnerabilities: output `## ✅ No vulnerabilities found` and summary line only
- No external image URLs anywhere
- Use emoji severity indicators (not images)

---

## src/formatters/html.ts

Single self-contained HTML file. No external resources.

Rules:
- All CSS in a `<style>` block in `<head>`
- No external fonts, CDN links, or JavaScript libraries
- Severity row colors: critical=`#fee2e2`, high=`#ffedd5`, moderate=`#fef9c3`, low=`#dbeafe`, info=`#f0fdf4`
- Sortable table via ~30 lines of vanilla JS (column header click toggles asc/desc)
- `@media print` CSS: hides sort controls, expands all details
- Target total file size: under 80KB
- Include `<meta charset="utf-8">` and `<meta name="viewport" ...>`
- Title: `{title} — {date}`

---

## src/formatters/sarif.ts

SARIF 2.1.0. Must pass schema validation.

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "npm-audit",
        "version": "{npmVersion}",
        "informationUri": "https://docs.npmjs.com/cli/commands/npm-audit",
        "rules": [
          {
            "id": "{vuln.id}",
            "name": "{vuln.name}",
            "shortDescription": { "text": "{vuln.title}" },
            "helpUri": "{vuln.url}",
            "properties": { "severity": "{vuln.severity}" }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "{vuln.id}",
        "level": "error|warning|note",
        "message": { "text": "{vuln.title}. Affected range: {vuln.range}. {fixCommand or 'No fix available.'}" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "package.json" }
          }
        }]
      }
    ]
  }]
}
```

Level mapping:
- `critical` | `high` → `"error"`
- `moderate` → `"warning"`
- `low` | `info` → `"note"`

---

## src/formatters/annotations.ts

Write GitHub Actions workflow commands to stdout.

Format: `::LEVEL file=package.json,title={id}::{name}@{range} — {title} ({fixCommand or 'no fix'})`

Level mapping:
- `critical` | `high` → `::error`
- `moderate` → `::warning`
- `low` | `info` → `::notice`

Example output:
```
::error file=package.json,title=CVE-2021-23337::lodash — Prototype Pollution, affected: <4.17.21 (fix: npm install lodash@4.17.21)
::warning file=package.json,title=GHSA-cph5-m8f7-6c5x::axios — SSRF vulnerability (no fix available)
```

---

## src/cli.ts

```ts
#!/usr/bin/env node
```

### Arg parsing — no dependencies, manual parsing

Flags to support:
```
--format, -f    markdown|html|sarif|annotations   default: markdown
--output, -o    <filepath>                         default: stdout
--severity, -s  critical|high|moderate|low|info   default: low
--fail-on       critical|high|moderate|low|none   default: high
--file          <filepath>                         default: stdin
--title         <string>                           default: "npm audit report"
--template      <filepath>                         custom markdown template
--no-color      flag
--quiet, -q     flag
--version, -v   flag  → print version from package.json and exit 0
--help, -h      flag  → print usage and exit 0
```

### Input reading
- If `--file` provided: `fs.readFileSync(path, 'utf8')`
- Else: read all of stdin with `process.stdin` async iterator
- If stdin is a TTY and no `--file`: print helpful error message and exit 1

### Exit codes
- `0` — success, no findings at or above `--fail-on` threshold
- `1` — findings found at or above `--fail-on` threshold
- `2` — invalid input (bad JSON, unrecognized schema)
- `3` — file not found (`--file` path doesn't exist)

---

## src/index.ts (public library API)

```ts
export { parse } from './parse.js';
export { format } from './formatters/index.js';
export { meetsThreshold, shouldFail, filterBySeverity } from './threshold.js';
export type { AuditReport, Vulnerability, AuditSummary, AuditMeta, FormatOptions, Severity, Format } from './types.js';

// Convenience: parse + format in one call
export function report(json: string, opts: FormatOptions = {}): string {
  const parsed = parse(json);
  return format(parsed, opts);
}
```

---

## src/formatters/index.ts

```ts
import { markdown } from './markdown.js';
import { html } from './html.js';
import { sarif } from './sarif.js';
import { annotations } from './annotations.js';
import type { AuditReport, FormatOptions } from '../types.js';

export function format(report: AuditReport, opts: FormatOptions = {}): string {
  const fmt = opts.format ?? 'markdown';
  switch (fmt) {
    case 'markdown': return markdown(report, opts);
    case 'html': return html(report, opts);
    case 'sarif': return sarif(report, opts);
    case 'annotations': return annotations(report, opts);
    default: throw new Error(`Unknown format: ${fmt}`);
  }
}
```

---

## Test fixtures (tests/fixtures/)

### v6-audit.json — include at minimum:
- 1 critical vulnerability (lodash, prototype pollution)
- 1 high vulnerability (axios, SSRF)
- 1 moderate vulnerability
- metadata with totalDependencies count
- `auditReportVersion: 1`

### v7-audit.json — include at minimum:
- Same vulnerabilities mapped to v7 schema
- `auditReportVersion: 2`
- fixAvailable as object `{ name, version }` for some, `false` for others

### empty-audit.json:
```json
{
  "auditReportVersion": 2,
  "vulnerabilities": {},
  "metadata": {
    "vulnerabilities": { "critical": 0, "high": 0, "moderate": 0, "low": 0, "info": 0, "total": 0 },
    "totalDependencies": 120
  }
}
```

---

## Tests — what to cover

### parse.test.ts
- Parses v6 fixture without error
- Parses v7 fixture without error
- Parses empty fixture, returns empty vulnerabilities array
- Throws ParseError on invalid JSON
- Throws ParseError on unknown schema
- v6 and v7 fixtures produce equivalent normalized output for same vulns

### markdown.test.ts
- Contains severity summary table
- Contains `<details>` block for each severity group present
- Zero vulns → contains "No vulnerabilities found"
- Respects `--severity` filter (low severity excluded when `--severity high`)
- No external image URLs in output

### html.test.ts
- Output is valid HTML (contains `<html>`, `<head>`, `<body>`)
- No external resource URLs (no `http://` or `https://` in `src=` or `href=`)
- Contains severity color styling
- Zero vulns case handled

### sarif.test.ts
- Output is valid JSON
- Contains `$schema` field pointing to SARIF 2.1.0
- `results[].level` is `"error"` for critical/high
- `results[].level` is `"warning"` for moderate
- `results[].level` is `"note"` for low/info

### annotations.test.ts
- Critical → line starts with `::error`
- Moderate → line starts with `::warning`
- Low → line starts with `::notice`
- Each line contains `file=package.json`

### threshold.test.ts
- `meetsThreshold('critical', 'high')` → true
- `meetsThreshold('low', 'high')` → false
- `shouldFail` returns false when `failOn === 'none'`
- `filterBySeverity` removes entries below threshold

---

## action.yml

```yaml
name: 'audit-report'
description: 'Convert npm audit JSON to Markdown, HTML, SARIF, or GitHub annotations'
author: 'Dimas Darfi Angga'

inputs:
  format:
    description: 'Output format: markdown|html|sarif|annotations'
    default: 'markdown'
  severity:
    description: 'Minimum severity to include: critical|high|moderate|low|info'
    default: 'low'
  fail-on:
    description: 'Exit 1 if findings at or above this severity: critical|high|moderate|low|none'
    default: 'high'
  output-file:
    description: 'Output filename'
    default: 'audit-report.md'
  upload-artifact:
    description: 'Upload output as GitHub Actions artifact'
    default: 'true'

runs:
  using: 'composite'
  steps:
    - name: Run audit and report
      shell: bash
      run: |
        npm audit --json | npx audit-report \
          --format ${{ inputs.format }} \
          --severity ${{ inputs.severity }} \
          --fail-on ${{ inputs.fail-on }} \
          --output ${{ inputs.output-file }}
    - name: Upload artifact
      if: ${{ inputs.upload-artifact == 'true' }}
      uses: actions/upload-artifact@v4
      with:
        name: audit-report
        path: ${{ inputs.output-file }}
```

---

## .github/workflows/ci.yml

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        node: [18, 20, 22]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - run: npm ci
      - run: npm run lint
      - run: npm test
      - run: npm run build
```

---

## README.md — sections to include

1. One-line description
2. Install: `npm install -D audit-report` or `npx audit-report`
3. Quick start (3 copy-paste examples: markdown, SARIF, annotations)
4. All CLI flags table
5. GitHub Actions usage example (full workflow snippet)
6. Node.js library usage (import + 5 lines)
7. Output format previews (fenced code blocks)
8. Contributing
9. License

---

## Hard rules

- **Zero runtime dependencies.** If you find yourself reaching for a library, implement it inline.
- **No `any` types** in public-facing API (`types.ts`, `index.ts`). Internal use: sparingly with a comment.
- **Dual ESM + CJS output** via tsup. The `exports` field in package.json must have both.
- **`#!/usr/bin/env node`** must be the first line of `cli.ts` and preserved in compiled `dist/cli.js`.
- **stdin detection**: if `process.stdin.isTTY === true` and no `--file` flag, print a helpful error (don't hang).
- **All formatter functions** must be pure: `(report: AuditReport, opts: FormatOptions) => string`. No side effects.
- **SARIF output** must be pretty-printed JSON (2-space indent) for human readability.
- **HTML output** must work when opened directly from the filesystem (`file://` protocol). No fetch calls.
- Tests use **vitest** only. No jest, no mocha.
- Build with **tsup** only.
