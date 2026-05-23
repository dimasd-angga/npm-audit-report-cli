#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { parse, ParseError } from './parse.js';
import { format } from './formatters/index.js';
import { shouldFail } from './threshold.js';
import type { Format, FormatOptions, Severity } from './types.js';

const VERSION = '1.0.0';

const VALID_FORMATS: Format[] = ['markdown', 'html', 'sarif', 'annotations'];
const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'moderate', 'low', 'info'];
const VALID_FAIL_ON: Array<Severity | 'none'> = ['critical', 'high', 'moderate', 'low', 'info', 'none'];

interface CliArgs {
  format: Format;
  output?: string;
  severity: Severity;
  failOn: Severity | 'none';
  file?: string;
  title: string;
  template?: string;
  quiet: boolean;
}

function printHelp(): void {
  const help = `audit-report v${VERSION}

Convert npm audit JSON to Markdown, HTML, SARIF, or GitHub annotations.

Usage:
  npm audit --json | audit-report [options]
  audit-report --file audit.json [options]

Options:
  -f, --format <fmt>       Output format: markdown|html|sarif|annotations (default: markdown)
  -o, --output <path>      Write to file instead of stdout
  -s, --severity <sev>     Minimum severity to include: critical|high|moderate|low|info (default: low)
      --fail-on <sev>      Exit 1 if findings at/above this severity: critical|high|moderate|low|info|none (default: high)
      --file <path>        Read audit JSON from file (default: stdin)
      --title <text>       Report title (default: "npm audit report")
      --template <path>    Custom markdown template (reserved; not yet implemented)
      --no-color           Disable colored output (no-op)
  -q, --quiet              Suppress non-essential stderr output
  -v, --version            Print version and exit
  -h, --help               Print this help and exit

Exit codes:
  0  success, no findings at/above --fail-on threshold
  1  findings at/above --fail-on threshold
  2  invalid input (bad JSON, unrecognized schema)
  3  --file not found
`;
  process.stdout.write(help);
}

function isFormat(s: string): s is Format {
  return (VALID_FORMATS as string[]).includes(s);
}
function isSeverity(s: string): s is Severity {
  return (VALID_SEVERITIES as string[]).includes(s);
}
function isFailOn(s: string): s is Severity | 'none' {
  return (VALID_FAIL_ON as string[]).includes(s);
}

function fail(msg: string, code: number): never {
  process.stderr.write(`audit-report: ${msg}\n`);
  process.exit(code);
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    format: 'markdown',
    severity: 'low',
    failOn: 'high',
    title: 'npm audit report',
    quiet: false,
  };

  const take = (i: number, flag: string): string => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('-')) fail(`missing value for ${flag}`, 2);
    return v as string;
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    switch (a) {
      case '-h':
      case '--help':
        printHelp();
        process.exit(0);
        break;
      case '-v':
      case '--version':
        process.stdout.write(`${VERSION}\n`);
        process.exit(0);
        break;
      case '-f':
      case '--format': {
        const v = take(i, a);
        if (!isFormat(v)) fail(`invalid format: ${v}`, 2);
        args.format = v;
        i++;
        break;
      }
      case '-o':
      case '--output':
        args.output = take(i, a);
        i++;
        break;
      case '-s':
      case '--severity': {
        const v = take(i, a);
        if (!isSeverity(v)) fail(`invalid severity: ${v}`, 2);
        args.severity = v;
        i++;
        break;
      }
      case '--fail-on': {
        const v = take(i, a);
        if (!isFailOn(v)) fail(`invalid fail-on: ${v}`, 2);
        args.failOn = v;
        i++;
        break;
      }
      case '--file':
        args.file = take(i, a);
        i++;
        break;
      case '--title':
        args.title = take(i, a);
        i++;
        break;
      case '--template':
        args.template = take(i, a);
        i++;
        break;
      case '--no-color':
        break;
      case '-q':
      case '--quiet':
        args.quiet = true;
        break;
      default:
        fail(`unknown argument: ${a}`, 2);
    }
  }

  return args;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  let input: string;
  if (args.file) {
    if (!existsSync(args.file)) fail(`file not found: ${args.file}`, 3);
    try {
      input = readFileSync(args.file, 'utf8');
    } catch (e) {
      fail(`could not read file: ${args.file}`, 3);
    }
  } else {
    if (process.stdin.isTTY) {
      fail(
        'no input. Pipe `npm audit --json` to this command or use --file <path>. Run with --help for usage.',
        1,
      );
    }
    input = await readStdin();
  }

  let report;
  try {
    report = parse(input);
  } catch (e) {
    const msg = e instanceof ParseError ? e.message : 'failed to parse input';
    fail(msg, 2);
  }

  if (args.template && !args.quiet) {
    process.stderr.write('audit-report: --template is reserved for future use and is being ignored\n');
  }

  const opts: FormatOptions = {
    format: args.format,
    severity: args.severity,
    failOn: args.failOn,
    title: args.title,
  };
  const output = format(report, opts);

  if (args.output) {
    writeFileSync(args.output, output, 'utf8');
  } else {
    process.stdout.write(output);
    if (!output.endsWith('\n')) process.stdout.write('\n');
  }

  if (shouldFail(report, args.failOn)) {
    process.exit(1);
  }
  process.exit(0);
}

main().catch((e) => {
  process.stderr.write(`audit-report: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(2);
});
