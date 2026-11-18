import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { run } from 'node:test';
import { spec as specReporter, tap as tapReporter } from 'node:test/reporters';
import { fileURLToPath, pathToFileURL } from 'node:url';

const e2eDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(e2eDir, '..', '..');

export const TIER_THRESHOLDS = Object.freeze({
  tier1: 105,
  tier2: 105,
  tier3: 21,
  tier4: 11
});

const VALID_TIERS = new Set(['1', '2', '3', '4', 'all']);
const VALID_FORMATS = new Set(['tap', 'json', 'spec']);

export function parseCliArgs(argv) {
  const opts = {
    tier: null,
    suite: null,
    format: 'spec',
    enforceCounts: false,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      opts.help = true;
      continue;
    }
    if (arg === '--enforce-counts') {
      opts.enforceCounts = true;
      continue;
    }
    if (arg === '--tier' || arg.startsWith('--tier=')) {
      const val = arg.includes('=') ? arg.split('=')[1] : argv[++i];
      if (!val || !VALID_TIERS.has(val)) {
        throw new Error(`Invalid --tier value "${val}". Expected 1, 2, 3, 4, or all.`);
      }
      opts.tier = val;
      continue;
    }
    if (arg === '--suite' || arg.startsWith('--suite=')) {
      const val = arg.includes('=') ? arg.split('=')[1] : argv[++i];
      if (!val) {
        throw new Error('--suite requires a value.');
      }
      opts.suite = val;
      continue;
    }
    if (arg === '--format' || arg.startsWith('--format=')) {
      const val = arg.includes('=') ? arg.split('=')[1] : argv[++i];
      if (!val || !VALID_FORMATS.has(val)) {
        throw new Error(`Invalid --format value "${val}". Expected tap, json, or spec.`);
      }
      opts.format = val;
      continue;
    }
    throw new Error(`Unknown CLI argument: ${arg}`);
  }

  if (!opts.tier && !opts.suite) {
    opts.tier = 'all';
  }

  return opts;
}

function walkFiles(dirPath) {
  if (!fs.existsSync(dirPath)) {
    return [];
  }
  const results = [];
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkFiles(full));
    } else if (entry.isFile()) {
      results.push(full);
    }
  }
  return results.sort();
}

function classifyTier(relPosixPath) {
  if (relPosixPath.startsWith('harness/')) {
    return 'harness';
  }
  if (relPosixPath.startsWith('tier1/')) {
    return 'tier1';
  }
  if (relPosixPath.startsWith('tier2/')) {
    return 'tier2';
  }
  if (relPosixPath.startsWith('tier3/')) {
    return 'tier3';
  }
  if (relPosixPath.startsWith('tier4/')) {
    return 'tier4';
  }
  return 'other';
}

function matchesSuite(relPosixPath, suiteName) {
  const normalized = suiteName.toLowerCase().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  const relLower = relPosixPath.toLowerCase();
  if (normalized === 'harness') {
    return relPosixPath === 'harness/harness.smoke.test.mjs' ||
      relPosixPath === 'harness/console.smoke.spec.mjs';
  }
  if (normalized === 'tier1' || normalized === 'tier2' || normalized === 'tier3' || normalized === 'tier4') {
    return relLower.startsWith(`${normalized}/`);
  }
  if (normalized === 'workloads') {
    return relLower.startsWith('tier4/workloads/');
  }
  if (normalized === 'console') {
    return relLower.startsWith('tier4/console/');
  }
  if (normalized === 'console-smoke') {
    return relLower.startsWith('tier1/console-smoke.spec.');
  }
  if (relLower.startsWith(`${normalized}/`)) {
    return true;
  }
  const relNoExt = relLower.replace(/\.(test|spec)\.(mjs|ts)$/, '');
  if (relLower === normalized || relNoExt === normalized) {
    return true;
  }
  const base = path.posix.basename(relLower);
  const stem = base.replace(/\.(test|spec)\.(mjs|ts)$/, '');
  return stem === normalized ||
    stem.startsWith(`${normalized}-`) ||
    stem.includes(normalized);
}

export function discoverTestFiles(options = {}) {
  const roots = ['harness', 'tier1', 'tier2', 'tier3', 'tier4'];
  const all = [];

  for (const root of roots) {
    for (const fullPath of walkFiles(path.join(e2eDir, root))) {
      const relPosix = path.relative(e2eDir, fullPath).replace(/\\/g, '/');
      const isNodeTest = relPosix.endsWith('.test.mjs');
      const isPlaywright = /\.spec\.(mjs|ts)$/.test(relPosix);
      if (!isNodeTest && !isPlaywright) {
        continue;
      }
      all.push({
        fullPath,
        relPosix,
        tier: classifyTier(relPosix),
        runner: isPlaywright ? 'playwright' : 'node:test'
      });
    }
  }

  let selected = all;

  if (options.tier && options.tier !== 'all') {
    const targetTier = `tier${options.tier}`;
    selected = selected.filter((f) => f.tier === targetTier);
  } else if (!options.suite && options.tier === 'all') {
    selected = selected.filter((f) => f.tier !== 'harness');
  }

  if (options.suite) {
    selected = selected.filter((f) => matchesSuite(f.relPosix, options.suite));
  }

  return selected;
}

async function runNodeTestGroup(files, format) {
  if (files.length === 0) {
    return {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      durationMs: 0,
      success: true,
      cases: []
    };
  }

  const startedAt = Date.now();
  const cases = [];
  let leafPassed = 0;
  let leafFailed = 0;
  let leafSkipped = 0;
  let aggregateSummary = null;

  const stream = run({
    files: files.map((f) => f.fullPath),
    execArgv: []
  });

  stream.on('test:pass', (data) => {
    if (data.details?.type !== 'suite') {
      if (data.skip) {
        leafSkipped += 1;
      } else {
        leafPassed += 1;
      }
      cases.push({
        name: data.name,
        file: data.file ?? null,
        status: data.skip ? 'skipped' : 'passed',
        durationMs: data.details?.duration_ms ?? 0
      });
    }
  });

  stream.on('test:fail', (data) => {
    if (data.details?.type !== 'suite') {
      leafFailed += 1;
      cases.push({
        name: data.name,
        file: data.file ?? null,
        status: 'failed',
        durationMs: data.details?.duration_ms ?? 0,
        error: data.details?.error?.message ?? String(data.details?.error ?? 'Test failed')
      });
    }
  });

  stream.on('test:summary', (data) => {
    if (data.file === undefined) {
      aggregateSummary = data;
    }
  });

  let reporterStream = null;
  if (format === 'tap') {
    reporterStream = stream.compose(tapReporter);
  } else if (format === 'spec') {
    reporterStream = stream.compose(specReporter);
  }

  if (reporterStream) {
    reporterStream.pipe(process.stdout, { end: false });
    await new Promise((resolve, reject) => {
      reporterStream.on('end', resolve);
      reporterStream.on('error', reject);
      stream.on('error', reject);
    });
  } else {
    await new Promise((resolve, reject) => {
      stream.resume();
      stream.on('end', resolve);
      stream.on('error', reject);
    });
  }

  const total = aggregateSummary?.counts?.tests ?? (leafPassed + leafFailed + leafSkipped);
  const passed = aggregateSummary?.counts?.passed ?? leafPassed;
  const failed = aggregateSummary?.counts?.failed ?? leafFailed;
  const skipped = (aggregateSummary?.counts?.skipped ?? 0) + (aggregateSummary?.counts?.todo ?? 0);

  return {
    total,
    passed,
    failed,
    skipped,
    durationMs: aggregateSummary?.counts?.duration_ms ?? (Date.now() - startedAt),
    success: Boolean(aggregateSummary ? aggregateSummary.success : leafFailed === 0) && failed === 0 && skipped === 0,
    cases
  };
}

function collectPlaywrightSpecs(suite, out = []) {
  if (Array.isArray(suite.specs)) {
    for (const spec of suite.specs) {
      for (const testItem of spec.tests ?? []) {
        const latest = testItem.results?.[testItem.results.length - 1];
        out.push({
          name: spec.title,
          file: spec.file ?? suite.file ?? null,
          status: testItem.status === 'expected' ? 'passed' : testItem.status,
          durationMs: latest?.duration ?? 0,
          error: latest?.error?.message ?? undefined
        });
      }
    }
  }
  if (Array.isArray(suite.suites)) {
    for (const child of suite.suites) {
      collectPlaywrightSpecs(child, out);
    }
  }
  return out;
}

function runPlaywrightGroup(files, format) {
  if (files.length === 0) {
    return {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      durationMs: 0,
      success: true,
      cases: []
    };
  }

  const playwrightCli = path.join(repoRoot, 'node_modules', '@playwright', 'test', 'cli.js');
  const configPath = path.join(e2eDir, 'playwright.config.mjs');
  const tempJsonPath = path.join(
    os.tmpdir(),
    `relayquill-pw-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`
  );

  const suppressChildStdout = format === 'json' || format === 'tap';
  const reporterFlag = suppressChildStdout ? '--reporter=json' : '--reporter=list,json';
  const args = [
    playwrightCli,
    'test',
    '-c',
    configPath,
    reporterFlag,
    ...files.map((f) => f.relPosix)
  ];

  const startedAt = Date.now();
  try {
    const res = spawnSync(process.execPath, args, {
      cwd: repoRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        PLAYWRIGHT_JSON_OUTPUT_FILE: tempJsonPath
      },
      stdio: suppressChildStdout ? ['ignore', 'pipe', 'pipe'] : ['ignore', 'inherit', 'inherit']
    });

    let report = null;
    if (fs.existsSync(tempJsonPath)) {
      const raw = fs.readFileSync(tempJsonPath, 'utf8');
      if (raw.trim()) {
        report = JSON.parse(raw);
      }
    }

    const cases = [];
    for (const suite of report?.suites ?? []) {
      collectPlaywrightSpecs(suite, cases);
    }

    const stats = report?.stats ?? {};
    const passed = stats.expected ?? cases.filter((c) => c.status === 'passed').length;
    const failed = (stats.unexpected ?? 0) + (stats.flaky ?? 0);
    const skipped = stats.skipped ?? 0;
    const total = passed + failed + skipped;

    return {
      total,
      passed,
      failed,
      skipped,
      durationMs: stats.duration ?? (Date.now() - startedAt),
      success: res.status === 0 && failed === 0,
      cases,
      exitCode: res.status
    };
  } finally {
    fs.rmSync(tempJsonPath, { force: true });
  }
}

export async function runE2E(options) {
  const files = discoverTestFiles(options);

  if (options.suite && files.length === 0) {
    throw new Error(`No E2E test files matched --suite "${options.suite}".`);
  }

  const tiersToRun = options.tier && options.tier !== 'all'
    ? [`tier${options.tier}`]
    : ['harness', 'tier1', 'tier2', 'tier3', 'tier4'];

  const tierResults = {};
  const allCases = [];
  let overallSuccess = true;

  for (const tierName of tiersToRun) {
    const tierFiles = files.filter((f) => f.tier === tierName);
    const explicitlyRequestedTier = options.tier === 'all'
      ? tierName in TIER_THRESHOLDS
      : options.tier !== null && `tier${options.tier}` === tierName;
    if (tierFiles.length === 0 && !(tierName in TIER_THRESHOLDS && (explicitlyRequestedTier || options.enforceCounts))) {
      continue;
    }
    if (tierFiles.length === 0 && !options.enforceCounts && (!explicitlyRequestedTier || options.suite)) {
      continue;
    }

    const nodeFiles = tierFiles.filter((f) => f.runner === 'node:test');
    const pwFiles = tierFiles.filter((f) => f.runner === 'playwright');

    const nodeRes = await runNodeTestGroup(nodeFiles, options.format);
    const pwRes = runPlaywrightGroup(pwFiles, options.format);

    if (options.format === 'tap' && pwFiles.length > 0) {
      if (nodeFiles.length === 0) {
        process.stdout.write(`TAP version 13\n1..${pwRes.cases.length}\n`);
        pwRes.cases.forEach((c, idx) => {
          const okPrefix = c.status === 'passed' ? 'ok' : 'not ok';
          const skipSuffix = c.status === 'skipped' ? ' # SKIP' : '';
          process.stdout.write(`${okPrefix} ${idx + 1} - ${c.name}${skipSuffix}\n`);
          if (c.error) {
            process.stdout.write(`  # error: ${String(c.error).replace(/\r?\n/g, ' ')}\n`);
          }
        });
      } else {
        process.stdout.write('# Playwright spec results:\n');
        for (const c of pwRes.cases) {
          process.stdout.write(`# ${c.status}: ${c.name} (${Math.round(c.durationMs)}ms)\n`);
          if (c.error) {
            process.stdout.write(`#   error: ${String(c.error).replace(/\r?\n/g, ' ')}\n`);
          }
        }
      }
    }

    const skipped = nodeRes.skipped + pwRes.skipped;
    const summary = {
      files: tierFiles.length,
      total: nodeRes.total + pwRes.total,
      passed: nodeRes.passed + pwRes.passed,
      failed: nodeRes.failed + pwRes.failed,
      skipped,
      durationMs: Math.round(nodeRes.durationMs + pwRes.durationMs),
      success: nodeRes.success && pwRes.success && skipped === 0
    };

    tierResults[tierName] = summary;
    allCases.push(...nodeRes.cases.map((c) => ({ tier: tierName, ...c })));
    allCases.push(...pwRes.cases.map((c) => ({ tier: tierName, ...c })));

    if (!summary.success) {
      overallSuccess = false;
    }
  }

  const thresholdFailures = [];
  if (options.enforceCounts) {
    const checkedTiers = options.tier && options.tier !== 'all'
      ? [`tier${options.tier}`]
      : Object.keys(TIER_THRESHOLDS);

    for (const tierName of checkedTiers) {
      const required = TIER_THRESHOLDS[tierName];
      if (!required) {
        continue;
      }
      const stats = tierResults[tierName];
      const passed = stats?.passed ?? 0;
      const skipped = stats?.skipped ?? 0;
      if (passed < required) {
        thresholdFailures.push(`${tierName}: expected >= ${required} passed tests, passed ${passed}`);
        overallSuccess = false;
      }
      if (skipped > 0) {
        thresholdFailures.push(`${tierName}: expected 0 skipped tests, skipped ${skipped}`);
        overallSuccess = false;
      }
    }
  }

  return {
    ok: overallSuccess && thresholdFailures.length === 0,
    format: options.format,
    enforceCounts: options.enforceCounts,
    tiers: tierResults,
    thresholds: TIER_THRESHOLDS,
    thresholdFailures,
    tests: allCases
  };
}

function printUsage() {
  console.log(
    'Usage: node tests/e2e/run.mjs [--tier <1|2|3|4|all>] [--suite <name>] [--format <tap|json|spec>] [--enforce-counts]'
  );
}

async function main() {
  const opts = parseCliArgs(process.argv.slice(2));
  if (opts.help) {
    printUsage();
    return;
  }

  const report = await runE2E(opts);

  if (opts.format === 'json') {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else if (opts.format === 'tap') {
    if (report.tests.length === 0) {
      process.stdout.write('TAP version 13\n1..0\n');
    }
    process.stdout.write('# === Relayquill E2E Summary ===\n');
    for (const [tier, s] of Object.entries(report.tiers)) {
      process.stdout.write(
        `# ${tier.padEnd(8)} total=${s.total} passed=${s.passed} failed=${s.failed} skipped=${s.skipped} (${s.durationMs}ms)\n`
      );
    }
    if (report.thresholdFailures.length > 0) {
      for (const msg of report.thresholdFailures) {
        process.stdout.write(`# threshold failure: ${msg}\n`);
      }
    }
  } else {
    console.log('\n=== Relayquill E2E Summary ===');
    for (const [tier, s] of Object.entries(report.tiers)) {
      console.log(
        `${tier.padEnd(8)} total=${s.total} passed=${s.passed} failed=${s.failed} skipped=${s.skipped} (${s.durationMs}ms)`
      );
    }
    if (report.thresholdFailures.length > 0) {
      console.error('Threshold failures:');
      for (const msg of report.thresholdFailures) {
        console.error(`  - ${msg}`);
      }
    }
  }

  if (!report.ok) {
    process.exitCode = 1;
  }
}

const isEntrypoint = process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isEntrypoint) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
