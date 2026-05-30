# audit-report

> Convert `npm audit --json` output to Markdown, HTML, SARIF, or GitHub Actions annotations. Zero runtime dependencies.

## Install

```bash
# Project-local
npm install -D audit-report

# Or run directly
npx audit-report --help
```

## Quick start

### Markdown report

```bash
npm audit --json | npx audit-report --format markdown > audit.md
```

### SARIF (for GitHub code scanning)

```bash
npm audit --json | npx audit-report --format sarif > audit.sarif
```

### GitHub Actions annotations

```bash
npm audit --json | npx audit-report --format annotations
```

## CLI flags

| Flag | Alias | Default | Description |
|---|---|---|---|
| `--format <fmt>` | `-f` | `markdown` | Output format: `markdown`, `html`, `sarif`, `annotations` |
| `--output <path>` | `-o` | stdout | Write output to a file instead of stdout |
| `--severity <sev>` | `-s` | `low` | Minimum severity to include |
| `--fail-on <sev>` | | `high` | Exit code 1 when findings meet or exceed this severity. Use `none` to never fail |
| `--file <path>` | | stdin | Read audit JSON from a file instead of stdin |
| `--title <text>` | | `npm audit report` | Title for the generated report |
| `--template <path>` | | | Reserved for future use |
| `--no-color` | | | Reserved (no-op) |
| `--quiet` | `-q` | | Suppress non-essential stderr output |
| `--version` | `-v` | | Print version and exit |
| `--help` | `-h` | | Print usage and exit |

### Exit codes

- `0` — no findings at/above `--fail-on` threshold
- `1` — findings at/above `--fail-on` threshold
- `2` — invalid input (bad JSON or unrecognized npm audit schema)
- `3` — `--file` path does not exist

## GitHub Actions

Use the bundled composite action:

```yaml
name: Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci
      - uses: dimasdarfi/audit-report@v1
        with:
          format: sarif
          severity: low
          fail-on: high
          output-file: audit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: audit.sarif
```

Or call the CLI directly:

```yaml
- run: npm audit --json | npx audit-report -f annotations
```

## Node.js library

```ts
import { parse, format, report } from 'audit-report';

// One-shot
const md = report(jsonString, { format: 'markdown' });

// Two-step
const r = parse(jsonString);
const html = format(r, { format: 'html', title: 'Weekly audit' });
```

### Types

```ts
import type { AuditReport, Vulnerability, Severity, Format, FormatOptions } from 'audit-report';
```

## Output preview — Markdown

```markdown
## npm audit report

> 3 vulnerabilities found · audited 2026-06-09 · 342 dependencies

| Severity | Count | Fixable |
|----------|-------|---------|
| 🔴 Critical | 1 | 1 |
| 🟠 High | 1 | 1 |
| 🟡 Moderate | 1 | 0 |

<details>
<summary>🔴 Critical (1)</summary>

### lodash
- **ID:** GHSA-1065
- **Title:** Prototype Pollution
- **Range:** `<4.17.21`
- **Fix:** `npm install lodash@4.17.21`
- **Advisory:** https://npmjs.com/advisories/1065
- **Paths:** `node_modules/lodash`

</details>
```

## Output preview — SARIF

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "npm-audit", "rules": [...] } },
      "results": [
        {
          "ruleId": "GHSA-1065",
          "level": "error",
          "message": { "text": "Prototype Pollution. Affected range: <4.17.21. Fix: npm install lodash@4.17.21" },
          "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "package.json" } } }]
        }
      ]
    }
  ]
}
```

## Output preview — GitHub annotations

```
::error file=package.json,title=GHSA-1065::lodash — Prototype Pollution, affected: <4.17.21 (fix: npm install lodash@4.17.21)
::warning file=package.json,title=GHSA-1779::minimatch — Inefficient Regular Expression Complexity in minimatch, affected: <3.0.5 (no fix)
```

## Contributing

PRs welcome. Run locally:

```bash
npm install
npm run lint
npm test
npm run build
```

## License

MIT
