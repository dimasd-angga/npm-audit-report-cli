# Changelog

## 1.0.0 — 2026-06-09

Initial release.

- CLI: read `npm audit --json` from stdin or `--file`, output `markdown`, `html`, `sarif`, or `annotations`
- Library: `parse`, `format`, `report`, `meetsThreshold`, `shouldFail`, `filterBySeverity`
- Supports both npm v6 (`auditReportVersion: 1`) and npm v7+ (`auditReportVersion: 2`) audit schemas
- Threshold-based exit codes (0/1/2/3) for CI integration
- Self-contained HTML output (no external resources)
- SARIF 2.1.0 compliant output
- GitHub Actions composite action via `action.yml`
- Zero runtime dependencies
- Dual ESM + CJS distribution
