#!/usr/bin/env node
// HAR Analytics command-line tool: the same analysis as har-analyzer.html, under Node.
// Runs locally; makes no network requests. No dependencies beyond Node 18+.
import vm from 'node:vm';
import { readFileSync, writeFileSync, mkdirSync, statSync, readdirSync, existsSync } from 'node:fs';
import { basename, join, resolve, extname } from 'node:path';
import { coreSource } from '../tools/build.mjs';

const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const HELP = `HAR Analytics ${VERSION} — analyze HAR files and Chrome NetLogs locally

Usage:
  har-analytics <file-or-folder>... [options]

Inputs are .har files or Chrome NetLog .json files (chrome://net-export); a folder
means every .har / .json file in it (add --recursive for subfolders).

Options:
  --format text|md|json   What to print (default: text summary; md = full reports)
  --out DIR               Also write <name>.diagnosis.md, <name>.auth.md and <name>.json to DIR
  --redact DIR            Write a redacted copy of each HAR (<name>-redacted.har) to DIR
  --keep-bodies           With --redact / --bundle: keep response bodies (masked) instead of removing them
  --no-pii                With --redact / --bundle: do not mask personal data
  --bundle DIR            Write a case bundle (<name>-case.zip) for each file to DIR
  --compare B.har         Compare the (single) input with B.har; prints a comparison report
  --settings FILE         Settings exported from the page (Settings → Export…)
  --fail-on error|warn    Exit with code 2 if any problem at or above this severity is found
  --recursive             Look into subfolders
  --quiet                 Print nothing except errors (useful with --out / --fail-on)
  -h, --help              Show this help
  -v, --version           Show the version

Exit codes: 0 = done, 2 = problems found at the --fail-on level, 1 = usage or input error.
`;

function parseArgs(argv) {
  const o = { files: [], format: 'text', failOn: 'none' }, need = ['--format', '--out', '--redact', '--bundle', '--compare', '--settings', '--fail-on'];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a === '--recursive') o.recursive = true;
    else if (a === '--quiet') o.quiet = true;
    else if (a === '--keep-bodies') o.keepBodies = true;
    else if (a === '--no-pii') o.noPii = true;
    else if (need.includes(a)) { if (i + 1 >= argv.length) throw new Error(a + ' needs a value'); o[a.slice(2).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = argv[++i]; }
    else if (a.startsWith('-')) throw new Error('unknown option ' + a);
    else o.files.push(a);
  }
  if (!['text', 'md', 'json'].includes(o.format)) throw new Error('--format must be text, md or json');
  if (!['none', 'error', 'warn'].includes(o.failOn)) throw new Error('--fail-on must be error or warn');
  return o;
}
function collect(paths, recursive) {
  const out = [];
  const walk = (p, top) => {
    const st = statSync(p);
    if (st.isDirectory()) { if (!top && !recursive) return; for (const f of readdirSync(p).sort()) walk(join(p, f), false); }
    else if (top || /\.(har|json)$/i.test(p)) out.push(p);
  };
  for (const p of paths) { if (!existsSync(p)) throw new Error('not found: ' + p); walk(p, true); }
  return out;
}

// Load the analysis modules into an isolated context (no DOM; a small XML reader stands in for DOMParser).
const ctx = vm.createContext({ console, URL, URLSearchParams, TextDecoder, TextEncoder, atob, btoa, crypto: globalThis.crypto, Blob, Response, DecompressionStream, CompressionStream, setTimeout, clearTimeout });
vm.runInContext("'use strict';\n" + coreSource() + '\n;globalThis.__core = { S, A, D, DCATS, DCAT_LABEL, RULES, CONF_LABEL, PII_KINDS, normalize, analyze, analyzeAuth, runDiagnostics, isNetLog, parseNetLogText, netlogToHar, diagReport, authReport, diagSummaryText, verdictText, buildRedacted, redactUrl, scrub, maskPii, scanPii, makeZip, csvText, compareHars, compareReport, applySettings, timelineInsights, fmtBytes };', ctx, { filename: 'har-analytics-core.js' });
const K = ctx.__core;

async function analyzeFile(file) {
  const text = readFileSync(file, 'utf8').replace(/^﻿/, '');
  let data;
  try { data = /^\s*\{\s*"constants"/.test(text.slice(0, 200)) ? K.parseNetLogText(text) : JSON.parse(text); }
  catch (err) { throw new Error('not valid JSON (' + err.message + ')'); }
  let har = data, netlog = null;
  if (K.isNetLog(data)) { const c = K.netlogToHar(data); har = c.har; netlog = c.info; }
  const n = K.normalize(har);
  Object.assign(K.S, { fileName: basename(file), har, pages: n.pages, entries: n.entries, base: n.base, netlog });
  K.analyze();
  await K.analyzeAuth();
  K.runDiagnostics();
  return { file, name: basename(file), har, n };
}
const sevRank = { error: 0, warn: 1, info: 2 };
function problems() {
  const diag = K.D.events.filter(v => !v.normal && v.sev !== 'info').map(v => ({ area: K.DCAT_LABEL[v.cat], severity: v.sev, headline: v.headline, cause: v.causes[0] ? v.causes[0].title : '', causeId: v.causes[0] ? v.causes[0].id : '', confidence: v.causes[0] ? v.causes[0].conf : '', request: v.e ? v.e.i : null, url: v.e ? K.redactUrl(v.e.url) : null, evidence: v.evidence.slice(0, 8), related: v.related.slice(0, 40).map(x => x.i) }));
  const auth = K.A.events.filter(v => !v.normal).map(v => ({ area: 'Authentication', severity: v.recovered ? 'warn' : 'error', headline: v.headline, cause: v.causes[0] ? v.causes[0].title : '', causeId: v.causes[0] ? v.causes[0].id : '', confidence: v.causes[0] ? v.causes[0].conf : '', request: v.e.i, url: K.redactUrl(v.e.url), evidence: v.evidence.slice(0, 8), recovered: v.recovered ? v.recovered.i : null }));
  return [...auth, ...diag].sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);
}
function summaryJson(r) {
  const E = K.S.entries, { byKind } = K.scanPii(E);
  return JSON.parse(K.scrub(JSON.stringify({
    file: r.name, source: K.S.netlog ? 'Chrome NetLog' : 'HAR', requests: E.length,
    failed: E.filter(e => e.status === 0).length, httpErrors: E.filter(e => e.status >= 400).length,
    transferredBytes: E.reduce((a, e) => a + e.transfer, 0),
    findings: K.S.findings.map(f => ({ code: f.code, severity: f.sev, title: K.RULES[f.code] ? K.RULES[f.code].title : f.code, detail: f.detail, request: f.e.i })),
    problems: problems(), timeline: K.timelineInsights(E).map(i => i.text),
    personalData: Object.fromEntries([...byKind].map(([k, v]) => [k, v.count])),
    summary: { diagnosis: K.diagSummaryText(), authentication: K.verdictText() },
  })));
}
function textSummary(r) {
  const E = K.S.entries, P = problems(), L = [];
  L.push(r.name + ' — ' + E.length + ' requests' + (K.S.netlog ? ' (Chrome NetLog)' : '') + ', ' + E.filter(e => e.status === 0).length + ' failed, ' + E.filter(e => e.status >= 400).length + ' HTTP errors');
  L.push('  Diagnosis: ' + K.diagSummaryText());
  L.push('  Authentication: ' + K.verdictText());
  for (const p of P.slice(0, 12)) L.push('  ' + (p.severity === 'error' ? '✗' : '!') + ' [' + p.area + '] ' + p.headline + (p.cause && !p.headline.includes(p.cause) ? ' — ' + p.cause : '') + (p.request ? ' (#' + p.request + ')' : ''));
  if (P.length > 12) L.push('  … ' + (P.length - 12) + ' more (use --format md or --out for everything)');
  return L.join('\n');
}
const stem = name => name.replace(/\.(har|json)$/i, '');
async function bundleFor(r, opts) {
  const o = { params: true, pii: !opts.noPii, reqBody: false, resBody: !opts.keepBodies };
  const red = K.buildRedacted(o), mask = s => (o.pii ? K.maskPii(s) : s);
  const files = [
    { name: 'README.md', data: '# Case bundle: ' + r.name + '\n\nCreated ' + new Date().toISOString() + ' by the HAR Analytics command-line tool (locally).\n\n- Diagnosis: ' + K.diagSummaryText() + '\n- Authentication: ' + K.verdictText() + '\n- Redaction: credentials, cookies and token-like parameters masked' + (o.pii ? '; personal data masked' : '') + (o.resBody ? '; response bodies removed' : '') + '\n' },
    { name: stem(r.name) + '-redacted.har', data: JSON.stringify(red, null, 2) },
    { name: 'diagnosis.md', data: mask(K.diagReport()) }, { name: 'authentication.md', data: mask(K.authReport()) },
  ];
  return K.makeZip(files);
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (err) { console.error('har-analytics: ' + err.message + '\n\n' + HELP); return 1; }
  if (opts.help) { console.log(HELP); return 0; }
  if (opts.version) { console.log(VERSION); return 0; }
  if (!opts.files.length) { console.error(HELP); return 1; }
  if (opts.settings) { try { K.applySettings(JSON.parse(readFileSync(opts.settings, 'utf8'))); } catch (err) { console.error('har-analytics: cannot read settings: ' + err.message); return 1; } }
  let files; try { files = collect(opts.files, opts.recursive); } catch (err) { console.error('har-analytics: ' + err.message); return 1; }
  if (!files.length) { console.error('har-analytics: no .har or .json files found'); return 1; }
  for (const d of [opts.out, opts.redact, opts.bundle]) if (d) mkdirSync(d, { recursive: true });
  const say = s => { if (!opts.quiet) console.log(s); };

  if (opts.compare) {
    if (files.length !== 1) { console.error('har-analytics: --compare needs exactly one input'); return 1; }
    const b = await analyzeFile(resolve(opts.compare));
    const B = { entries: K.S.entries, pages: K.S.pages, base: K.S.base, creator: '' };
    await analyzeFile(files[0]);
    const r = K.compareHars({ entries: K.S.entries, pages: K.S.pages, base: K.S.base, creator: '' }, B);
    const md = K.compareReport(r, basename(files[0]), b.name);
    if (opts.format === 'json') say(K.scrub(JSON.stringify({ a: basename(files[0]), b: b.name, differences: r.explain.map(x => x.text), changed: r.changed.map(c => ({ request: c.k, a: c.sa, b: c.sb })) }, null, 2)));
    else say(md);
    if (opts.out) writeFileSync(join(opts.out, stem(basename(files[0])) + '-vs-' + stem(b.name) + '.compare.md'), md);
    return opts.failOn !== 'none' && r.explain.some(x => x.rank <= 1) ? 2 : 0;
  }

  let worst = 'none';
  const rows = [], jsonAll = [];
  for (const file of files) {
    let r;
    try { r = await analyzeFile(file); } catch (err) { console.error('har-analytics: ' + file + ': ' + err.message); worst = worst === 'none' ? 'input' : worst; rows.push([basename(file), 'error: ' + err.message]); continue; }
    const P = problems();
    if (P.some(p => p.severity === 'error')) worst = 'error'; else if (P.length && worst !== 'error') worst = 'warn';
    if (opts.format === 'text') say(textSummary(r) + '\n');
    else if (opts.format === 'md') say(K.diagReport() + '\n\n' + K.authReport());
    else jsonAll.push(summaryJson(r));
    if (opts.out) {
      writeFileSync(join(opts.out, stem(r.name) + '.diagnosis.md'), K.diagReport());
      writeFileSync(join(opts.out, stem(r.name) + '.auth.md'), K.authReport());
      writeFileSync(join(opts.out, stem(r.name) + '.json'), JSON.stringify(summaryJson(r), null, 2));
    }
    if (opts.redact) writeFileSync(join(opts.redact, stem(r.name) + '-redacted.har'), JSON.stringify(K.buildRedacted({ params: true, pii: !opts.noPii, reqBody: false, resBody: !opts.keepBodies }), null, 2));
    if (opts.bundle) writeFileSync(join(opts.bundle, stem(r.name) + '-case.zip'), await bundleFor(r, opts));
    rows.push([r.name, K.S.entries.length + ' requests', P.filter(p => p.severity === 'error').length + ' errors', P.filter(p => p.severity === 'warn').length + ' warnings']);
  }
  if (opts.format === 'json') say(JSON.stringify(files.length === 1 ? jsonAll[0] : jsonAll, null, 2));
  if (opts.format === 'text' && files.length > 1) { say('Summary'); for (const r of rows) say('  ' + r.join('  ·  ')); }
  if (worst === 'input') return 1;
  if (opts.failOn === 'error' && worst === 'error') return 2;
  if (opts.failOn === 'warn' && (worst === 'error' || worst === 'warn')) return 2;
  return 0;
}
main().then(code => { process.exitCode = code; }, err => { console.error('har-analytics: ' + (err && err.stack || err)); process.exitCode = 1; });
