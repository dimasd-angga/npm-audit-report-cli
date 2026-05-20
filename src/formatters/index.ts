import { markdown } from './markdown.js';
import { html } from './html.js';
import { sarif } from './sarif.js';
import { annotations } from './annotations.js';
import type { AuditReport, FormatOptions } from '../types.js';

export function format(report: AuditReport, opts: FormatOptions = {}): string {
  const fmt = opts.format ?? 'markdown';
  switch (fmt) {
    case 'markdown':
      return markdown(report, opts);
    case 'html':
      return html(report, opts);
    case 'sarif':
      return sarif(report, opts);
    case 'annotations':
      return annotations(report, opts);
    default:
      throw new Error(`Unknown format: ${String(fmt)}`);
  }
}

export { markdown, html, sarif, annotations };
