# Build Plan — audit-report

## Folder convention
- `docs/` — all AI-generated markdown (specs, plans, agent instructions, CLAUDE.md, skills.md). No source code here.
- `src/` — all TypeScript source code.
- `tests/` — vitest test files and JSON fixtures.

## Build order (sequenced for dependency flow)

### Phase 1 — Project scaffold
1. `package.json` — zero runtime deps, tsup + vitest + typescript devDeps
2. `tsconfig.json` + `tsconfig.build.json` — strict mode, ES2022
3. `tsup.config.ts` — dual ESM/CJS build of `index.ts` + `cli.ts`
4. `.gitignore` — `dist/`, `node_modules/`

### Phase 2 — Core types and parsing
5. `src/types.ts` — `Severity`, `Format`, `Vulnerability`, `AuditMeta`, `AuditSummary`, `AuditReport`, `FormatOptions`
6. `src/parse.ts` — `ParseError` class + `parse(json)` handling v1 (npm v6) and v2 (npm v7+) schemas
7. `src/threshold.ts` — `meetsThreshold`, `shouldFail`, `filterBySeverity`

### Phase 3 — Formatters (all pure, all `(report, opts) => string`)
8. `src/formatters/markdown.ts`
9. `src/formatters/html.ts` — self-contained, inline CSS + ~30 lines vanilla JS
10. `src/formatters/sarif.ts` — SARIF 2.1.0 pretty-printed
11. `src/formatters/annotations.ts` — `::error|warning|notice` lines
12. `src/formatters/index.ts` — dispatcher

### Phase 4 — Public surface
13. `src/index.ts` — library exports + `report(json, opts)` convenience
14. `src/cli.ts` — manual arg parsing, stdin/file input, exit codes 0/1/2/3

### Phase 5 — Tests
15. `tests/fixtures/v6-audit.json` (critical lodash, high axios, moderate)
16. `tests/fixtures/v7-audit.json` (same vulns in v2 schema)
17. `tests/fixtures/empty-audit.json`
18. `tests/parse.test.ts`
19. `tests/threshold.test.ts`
20. `tests/markdown.test.ts`
21. `tests/html.test.ts`
22. `tests/sarif.test.ts`
23. `tests/annotations.test.ts`

### Phase 6 — Distribution
24. `action.yml` — composite GitHub Action
25. `.github/workflows/ci.yml` — matrix: ubuntu/mac/windows × node 18/20/22
26. `README.md`
27. `CHANGELOG.md`

## Key design decisions
- **Schema detection**: prefer `auditReportVersion` field; fallback heuristic = v2 if `vulnerabilities` is an object keyed by name, v1 if `advisories` exists.
- **Vulnerability ID resolution**: v2 schema lacks a stable per-package ID — synthesize from first CVE/GHSA in `via[]`, fallback to `npm:{name}`.
- **Empty meta fields**: npm audit JSON does not contain `npmVersion` / `nodeVersion` / `auditedAt` — fill from `process` at parse time when possible, else empty strings.
- **Markdown template**: `opts.template` reading is a CLI concern (filesystem) — the formatter itself stays pure; CLI reads the file and passes content via... defer for v1 (treat template as not-yet-supported; spec says "custom" but no shape given).

## Out of scope for v1
- Custom markdown templates (flag accepted, no-op with stderr warning)
- Color terminal output (`--no-color` flag accepted, no-op — we don't colorize anything yet)

## Verification
- `npm run lint` → zero TS errors
- `npm test` → all green
- `npm run build` → `dist/index.js`, `dist/index.cjs`, `dist/cli.js`, `dist/index.d.ts`
- Smoke: `cat tests/fixtures/v7-audit.json | node dist/cli.js -f markdown`
