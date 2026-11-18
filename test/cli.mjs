// Tests for the command-line tool (cli/har-analytics.mjs). Usage: node test/cli.mjs
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync, writeFileSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';
import assert from 'node:assert/strict';

const run = promisify(execFile);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'cli', 'har-analytics.mjs'), sample = f => join(root, 'sample', f);
const har = async (...args) => { try { const r = await run('node', [cli, ...args], { maxBuffer: 64e6 }); return { code: 0, out: r.stdout, err: r.stderr }; } catch (e) { return { code: e.code, out: e.stdout, err: e.stderr }; } };
const tmp = mkdtempSync(join(tmpdir(), 'cli-'));
let passed = 0;
const step = async (name, fn) => { await fn(); passed++; console.log('  ✓ ' + name); };

await step('help, version and usage errors', async () => {
  const h = await har('--help'); assert.equal(h.code, 0); assert.match(h.out, /Usage:\n  har-analytics <file-or-folder>/);
  assert.equal((await har('--version')).out.trim(), JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version);
  const bad = await har('--bogus'); assert.equal(bad.code, 1); assert.match(bad.err, /unknown option --bogus/);
  const missing = await har(join(tmp, 'nope.har')); assert.equal(missing.code, 1); assert.match(missing.err, /not found/);
  writeFileSync(join(tmp, 'broken.har'), '{ not json');
  const broken = await har(join(tmp, 'broken.har')); assert.equal(broken.code, 1); assert.match(broken.err, /not valid JSON/);
});

await step('same analysis as the browser: diagnostics.har causes', async () => {
  const j = JSON.parse((await har(sample('diagnostics.har'), '--format', 'json')).out);
  const ids = new Set(j.problems.map(p => p.causeId));
  for (const id of ['cors_method', 'cors_wildcard_credentials', 'cors_origin_mismatch', 'cors_multi_acao', 'cors_pna', 'net_CERT_DATE_INVALID', 'net_outage', 'server_nginx_reverse_proxy_', 'server_aws_load_balancer_alb_elb_', 'server_cloudflare_edge', 'server_envoy_service_mesh', 'timeout_cluster', 'rate_limited', 'retry_storm', 'graphql_errors', 'html_not_json', 'js_undefined_url', 'req_json_wrong_type', 'bad_json', 'grpc_permission_denied', 'loop_scheme', 'downgrade', 'ws_200', 'cdn_setcookie', 'cached_cookie', 'secret_in_url', 'cleartext_creds', 'csp_violation'])
    assert.ok(ids.has(id), 'missing ' + id);
  assert.equal(j.requests, 121);
  assert.ok(j.findings.length > 50);
});

await step('same analysis as the browser: authentication incl. SAML and PKCE (no DOM under Node)', async () => {
  const j = JSON.parse((await har(sample('auth-failures.har'), '--format', 'json')).out);
  const auth = j.problems.filter(p => p.area === 'Authentication');
  assert.equal(auth.length, 17);
  for (const id of ['insufficient_scope', 'id_token_as_access', 'header_dropped_redirect', 'oauth_login_required', 'pkce_mismatch', 'basic_rejected', 'ntlm_split', 'cookie_samesite', 'session_invalid', 'csrf', 'saml_audience', 'presign_expired', 'proxy_required', 'api_key_rejected', 'client_cert', 'jwt_expired', 'oauth_invalid_grant'])
    assert.ok(auth.some(p => p.causeId === id), 'missing ' + id);
  assert.ok(!/eyJ[\w-]{10,}\.eyJ/.test(JSON.stringify(j)), 'tokens leaked into JSON output');
});

await step('NetLogs: certificate facts from the decoded certificates', async () => {
  const t = await har(sample('netlog-failures.json'));
  assert.match(t.out, /10 requests \(Chrome NetLog\)/);
  assert.match(t.out, /The certificate expired \d+ days before this request/);
  assert.match(t.out, /The certificate is for wrong-host\.example, not localhost/);
});

await step('--fail-on sets the exit code for CI', async () => {
  assert.equal((await har(sample('diagnostics.har'), '--quiet', '--fail-on', 'error')).code, 2);
  assert.equal((await har(sample('personal-data.har'), '--quiet', '--fail-on', 'error')).code, 0, 'only warnings');
  assert.equal((await har(sample('personal-data.har'), '--quiet', '--fail-on', 'warn')).code, 2);
  assert.equal((await har(sample('compare-working.har'), '--quiet', '--fail-on', 'warn')).code, 0);
});

await step('--settings applies rules and ignored hosts', async () => {
  writeFileSync(join(tmp, 'settings.json'), JSON.stringify({ ignoreHosts: ['analytics.example-tracker.com'], rules: [{ name: 'Slow API', host: 'api.example-shop.net', check: 'slower', value: '1000', severity: 'error' }] }));
  const j = JSON.parse((await har(sample('diagnostics.har'), '--format', 'json', '--settings', join(tmp, 'settings.json'))).out);
  assert.ok(j.problems.some(p => p.area === 'Your rules' && /^Slow API — \d+ requests/.test(p.headline)));
  assert.ok(!JSON.stringify(j.problems).includes('analytics.example-tracker.com'));
});

await step('--out, --redact and --bundle write files without secrets or personal data', async () => {
  const d = join(tmp, 'o');
  const r = await har(sample('personal-data.har'), sample('auth-failures.har'), '--quiet', '--out', d, '--redact', d, '--bundle', d);
  assert.equal(r.code, 0);
  const files = readdirSync(d).sort();
  for (const f of ['auth-failures-case.zip', 'auth-failures-redacted.har', 'auth-failures.auth.md', 'auth-failures.diagnosis.md', 'auth-failures.json', 'personal-data-case.zip', 'personal-data-redacted.har']) assert.ok(files.includes(f), 'missing ' + f + ' in ' + files.join(', '));
  const all = files.filter(f => !f.endsWith('.zip')).map(f => readFileSync(join(d, f), 'utf8')).join('\n');
  for (const s of ['alex.example@mail.example', '4111 1111 1111 1111', '123-45-6789', 'wrong-pass-123', 'rt-opaque-0f9e8d7c6b5a49382716', 'k-live-SAMPLEKEY-9f8e7d6c5b4a', 's3ss10n-abc123def456']) assert.ok(!all.includes(s), 'leaked ' + s);
  const zip = readFileSync(join(d, 'personal-data-case.zip'));
  let end = zip.length - 22; while (zip.readUInt32LE(end) !== 0x06054b50) end--;
  let p = zip.readUInt32LE(end + 16); const names = [];
  for (let k = 0; k < zip.readUInt16LE(end + 10); k++) { const nl = zip.readUInt16LE(p + 28), off = zip.readUInt32LE(p + 42), cs = zip.readUInt32LE(p + 20), m = zip.readUInt16LE(p + 10); names.push(zip.slice(p + 46, p + 46 + nl).toString()); const lnl = zip.readUInt16LE(off + 26), lxl = zip.readUInt16LE(off + 28); const data = zip.slice(off + 30 + lnl + lxl, off + 30 + lnl + lxl + cs); assert.ok(!(m === 8 ? inflateRawSync(data) : data).toString().includes('alex.example@mail.example')); p += 46 + nl + zip.readUInt16LE(p + 30) + zip.readUInt16LE(p + 32); }
  assert.deepEqual(names.sort(), ['README.md', 'authentication.md', 'diagnosis.md', 'personal-data-redacted.har']);
});

await step('--compare prints the ranked differences', async () => {
  const r = await har(sample('compare-working.har'), '--compare', sample('compare-broken.har'), '--fail-on', 'error');
  assert.equal(r.code, 2);
  assert.match(r.out, /1\. Works in A \(200\) but fails in B \(401\): GET api\.example\.com\/api\/orders\. Differences on this request: Request Authorization Bearer … → \(none\)/);
  assert.match(r.out, /Requested in A but never in B: POST api\.example\.com\/api\/token/);
});

await step('folders: every HAR / NetLog with a summary table', async () => {
  const r = await har(join(root, 'sample'));
  assert.match(r.out, /Summary\n(  .*\n){9}/);
  assert.match(r.out, /timeline\.har  ·  698 requests/);
});

rmSync(tmp, { recursive: true, force: true });
console.log(`\n${passed} checks passed`);
