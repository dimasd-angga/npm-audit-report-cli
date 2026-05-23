import { parse } from './parse.js';
import { format } from './formatters/index.js';
import type { FormatOptions } from './types.js';

export { parse, ParseError } from './parse.js';
export { format } from './formatters/index.js';
export { meetsThreshold, shouldFail, filterBySeverity } from './threshold.js';
export type {
  AuditReport,
  Vulnerability,
  AuditSummary,
  AuditMeta,
  FormatOptions,
  Severity,
  Format,
} from './types.js';

export function report(json: string, opts: FormatOptions = {}): string {
  const parsed = parse(json);
  return format(parsed, opts);
}
