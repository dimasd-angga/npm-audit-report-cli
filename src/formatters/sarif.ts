import type { AuditReport, FormatOptions, Severity } from '../types.js';
import { filterBySeverity } from '../threshold.js';

type SarifLevel = 'error' | 'warning' | 'note';

function severityToLevel(s: Severity): SarifLevel {
  if (s === 'critical' || s === 'high') return 'error';
  if (s === 'moderate') return 'warning';
  return 'note';
}

export function sarif(report: AuditReport, opts: FormatOptions = {}): string {
  const minSeverity = opts.severity ?? 'info';
  const filtered = filterBySeverity(report.vulnerabilities, minSeverity);

  const rulesMap = new Map<
    string,
    {
      id: string;
      name: string;
      shortDescription: { text: string };
      helpUri?: string;
      properties: { severity: Severity };
    }
  >();

  for (const v of filtered) {
    if (!rulesMap.has(v.id)) {
      const rule: {
        id: string;
        name: string;
        shortDescription: { text: string };
        helpUri?: string;
        properties: { severity: Severity };
      } = {
        id: v.id,
        name: v.name,
        shortDescription: { text: v.title },
        properties: { severity: v.severity },
      };
      if (v.url) rule.helpUri = v.url;
      rulesMap.set(v.id, rule);
    }
  }

  const results = filtered.map((v) => {
    const fixText = v.fixAvailable && v.fixCommand ? `Fix: ${v.fixCommand}` : 'No fix available.';
    const messageText = `${v.title}. Affected range: ${v.range}. ${fixText}`;
    return {
      ruleId: v.id,
      level: severityToLevel(v.severity),
      message: { text: messageText },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: 'package.json' },
          },
        },
      ],
    };
  });

  const doc = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'npm-audit',
            version: report.meta.npmVersion || '0.0.0',
            informationUri: 'https://docs.npmjs.com/cli/commands/npm-audit',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(doc, null, 2);
}
