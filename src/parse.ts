import type { AuditMeta, AuditReport, AuditSummary, Severity, Vulnerability } from './types.js';

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'moderate', 'low', 'info'];

function normalizeSeverity(value: unknown): Severity {
  if (typeof value === 'string' && (VALID_SEVERITIES as string[]).includes(value)) {
    return value as Severity;
  }
  return 'info';
}

function buildSummary(vulns: Vulnerability[], metaCounts?: Partial<AuditSummary>): AuditSummary {
  const summary: AuditSummary = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    info: 0,
    total: 0,
  };
  for (const v of vulns) {
    summary[v.severity] += 1;
    summary.total += 1;
  }
  if (metaCounts && summary.total === 0) {
    return {
      critical: metaCounts.critical ?? 0,
      high: metaCounts.high ?? 0,
      moderate: metaCounts.moderate ?? 0,
      low: metaCounts.low ?? 0,
      info: metaCounts.info ?? 0,
      total:
        metaCounts.total ??
        (metaCounts.critical ?? 0) +
          (metaCounts.high ?? 0) +
          (metaCounts.moderate ?? 0) +
          (metaCounts.low ?? 0) +
          (metaCounts.info ?? 0),
    };
  }
  return summary;
}

function buildMeta(raw: Record<string, unknown> | undefined): AuditMeta {
  const totalDependencies =
    raw && typeof raw['totalDependencies'] === 'number' ? (raw['totalDependencies'] as number) : 0;
  return {
    npmVersion: '',
    nodeVersion: typeof process !== 'undefined' && process.version ? process.version : '',
    auditedAt: new Date().toISOString(),
    totalDependencies,
  };
}

function parseV1(data: Record<string, unknown>): AuditReport {
  const advisories = (data['advisories'] as Record<string, Record<string, unknown>> | undefined) ?? {};
  const vulns: Vulnerability[] = [];

  for (const key of Object.keys(advisories)) {
    const adv = advisories[key];
    if (!adv) continue;

    const cves = Array.isArray(adv['cves']) ? (adv['cves'] as string[]) : [];
    const firstCve = cves.length > 0 ? cves[0] : undefined;
    const advisoryId = adv['id'];
    const idStr =
      firstCve ??
      (typeof advisoryId === 'number' || typeof advisoryId === 'string'
        ? `npm-advisory-${String(advisoryId)}`
        : `npm-advisory-${key}`);

    const findings = Array.isArray(adv['findings']) ? (adv['findings'] as Array<Record<string, unknown>>) : [];
    const paths: string[] = [];
    for (const f of findings) {
      const p = f['paths'];
      if (Array.isArray(p)) {
        for (const path of p) {
          if (typeof path === 'string') paths.push(path);
        }
      }
    }

    const fixAvailable = adv['fixAvailable'] === true;
    const name = typeof adv['module_name'] === 'string'
      ? (adv['module_name'] as string)
      : typeof adv['name'] === 'string'
        ? (adv['name'] as string)
        : (paths[0] ?? 'unknown');

    const range = typeof adv['vulnerable_versions'] === 'string' ? (adv['vulnerable_versions'] as string) : '*';
    const patched = typeof adv['patched_versions'] === 'string' ? (adv['patched_versions'] as string) : undefined;

    const vuln: Vulnerability = {
      id: idStr,
      name,
      severity: normalizeSeverity(adv['severity']),
      title: typeof adv['title'] === 'string' ? (adv['title'] as string) : 'Unknown vulnerability',
      url: typeof adv['url'] === 'string' ? (adv['url'] as string) : '',
      range,
      fixAvailable,
      paths,
    };
    if (fixAvailable && patched && patched !== '<0.0.0') {
      vuln.fixCommand = `npm install ${name}@${patched}`;
    } else if (fixAvailable) {
      vuln.fixCommand = `npm audit fix`;
    }
    vulns.push(vuln);
  }

  const metadata = (data['metadata'] as Record<string, unknown> | undefined) ?? {};
  const metaCounts = (metadata['vulnerabilities'] as Partial<AuditSummary> | undefined) ?? undefined;

  return {
    meta: buildMeta(metadata),
    summary: buildSummary(vulns, metaCounts),
    vulnerabilities: vulns,
  };
}

function parseV2(data: Record<string, unknown>): AuditReport {
  const vulnsRaw = (data['vulnerabilities'] as Record<string, Record<string, unknown>> | undefined) ?? {};
  const vulns: Vulnerability[] = [];

  for (const name of Object.keys(vulnsRaw)) {
    const entry = vulnsRaw[name];
    if (!entry) continue;

    const via = Array.isArray(entry['via']) ? (entry['via'] as Array<Record<string, unknown> | string>) : [];

    // Take first object via for canonical details
    let title = 'Unknown vulnerability';
    let url = '';
    let range = typeof entry['range'] === 'string' ? (entry['range'] as string) : '*';
    let id = `npm:${name}`;

    for (const v of via) {
      if (typeof v === 'object' && v !== null) {
        if (typeof v['title'] === 'string') title = v['title'] as string;
        if (typeof v['url'] === 'string') url = v['url'] as string;
        if (typeof v['range'] === 'string') range = v['range'] as string;
        if (typeof v['source'] === 'number' || typeof v['source'] === 'string') {
          id = `GHSA-${String(v['source'])}`;
        }
        break;
      }
    }

    const fix = entry['fixAvailable'];
    let fixAvailable = false;
    let fixCommand: string | undefined;
    if (fix === true) {
      fixAvailable = true;
      fixCommand = `npm audit fix`;
    } else if (typeof fix === 'object' && fix !== null) {
      fixAvailable = true;
      const fixObj = fix as Record<string, unknown>;
      const fixName = typeof fixObj['name'] === 'string' ? (fixObj['name'] as string) : name;
      const fixVersion = typeof fixObj['version'] === 'string' ? (fixObj['version'] as string) : undefined;
      if (fixVersion) {
        fixCommand = `npm install ${fixName}@${fixVersion}`;
      } else {
        fixCommand = `npm audit fix`;
      }
      const isSemVerMajor = fixObj['isSemVerMajor'] === true;
      if (isSemVerMajor) {
        fixCommand = `npm audit fix --force`;
      }
    }

    const nodes = Array.isArray(entry['nodes']) ? (entry['nodes'] as string[]) : [];

    const vuln: Vulnerability = {
      id,
      name: typeof entry['name'] === 'string' ? (entry['name'] as string) : name,
      severity: normalizeSeverity(entry['severity']),
      title,
      url,
      range,
      fixAvailable,
      paths: nodes.filter((n): n is string => typeof n === 'string'),
    };
    if (fixCommand) vuln.fixCommand = fixCommand;
    vulns.push(vuln);
  }

  const metadata = (data['metadata'] as Record<string, unknown> | undefined) ?? {};
  const metaCounts = (metadata['vulnerabilities'] as Partial<AuditSummary> | undefined) ?? undefined;

  return {
    meta: buildMeta(metadata),
    summary: buildSummary(vulns, metaCounts),
    vulnerabilities: vulns,
  };
}

function looksLikeV2(data: Record<string, unknown>): boolean {
  const v = data['vulnerabilities'];
  if (typeof v !== 'object' || v === null) return false;
  // v2 has `vulnerabilities` as an object keyed by package name.
  // v1 has `vulnerabilities` only inside `metadata`, not at the top level.
  return !Array.isArray(v);
}

function looksLikeV1(data: Record<string, unknown>): boolean {
  return typeof data['advisories'] === 'object' && data['advisories'] !== null;
}

export function parse(input: string): AuditReport {
  let data: unknown;
  try {
    data = JSON.parse(input);
  } catch {
    throw new ParseError('Invalid JSON input');
  }

  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new ParseError('Unrecognized npm audit schema');
  }

  const obj = data as Record<string, unknown>;
  const version = obj['auditReportVersion'];

  if (version === 1) return parseV1(obj);
  if (version === 2) return parseV2(obj);

  if (looksLikeV2(obj)) return parseV2(obj);
  if (looksLikeV1(obj)) return parseV1(obj);

  throw new ParseError('Unrecognized npm audit schema');
}
