// End-to-end test of the Authentication analysis using sample/auth-failures.har.
// Usage: node test/auth.mjs [screenshot-dir]
import { createRequire } from 'node:module';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';

const { chromium } = createRequire(import.meta.url)('playwright');
const here = dirname(fileURLToPath(import.meta.url));
const appUrl = pathToFileURL(join(here, '..', 'har-analyzer.html')).href;
const sample = join(here, '..', 'sample', 'auth-failures.har');
const shots = process.argv[2];
if (shots) mkdirSync(shots, { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1400, height: 1000 } });
const page = await ctx.newPage();
const errors = [], network = [];
page.on('pageerror', e => errors.push('pageerror: ' + e.message));
page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
page.on('request', r => { if (!/^(file|data|blob):/.test(r.url())) network.push(r.url()); });
let passed = 0;
const step = async (name, fn) => { await fn(); passed++; console.log('  ✓ ' + name); };

await page.goto(appUrl);
await page.setInputFiles('#file', sample);
await page.waitForSelector('#view-overview:not(.hidden)');

// Main (first-listed) cause expected for each failure, keyed by a fragment of the request URL.
const EXPECTED = [
  ['/v1/orders', 'insufficient_scope', 'POST'],
  ['/v1/profile', 'id_token_as_access'],
  ['files.example-storage.net', 'header_dropped_redirect'],
  ['prompt=none', 'oauth_login_required'],
  ['CODE-TWO', null], // the admin token request is matched below by its cause
  ['intranet.example.local', 'basic_rejected'],
  ['portal.corp.example', 'ntlm_split'],
  ['/api/cart', 'cookie_samesite'],
  ['/api/orders/history', 'session_invalid'],
  ['/api/address', 'csrf'],
  ['/saml/acs', 'saml_audience'],
  ['q3.pdf', 'presign_expired'],
  ['setup.zip', 'proxy_required'],
  ['geocode', 'api_key_rejected'],
  ['secure.partner.example', 'client_cert'],
];

await step('finds every failure and gives the right main cause', async () => {
  await page.click('#tabs button[data-view="auth"]');
  const cards = await page.$$eval('#view-auth .av > .acard', cs => cs.map(c => ({ cause: c.dataset.cause, cls: c.className, url: c.querySelector('.aurl')?.textContent || '' })));
  const fails = cards.filter(c => /\bfail\b|\brecovered\b/.test(c.cls) && !/\bflow\b/.test(c.cls));
  assert.equal(fails.length, 17, 'expected 17 failures, got ' + fails.length + ':\n' + fails.map(f => f.cause + ' ' + f.url).join('\n'));
  for (const [frag, cause, method] of EXPECTED) {
    if (!cause) continue;
    const hit = fails.find(f => f.url.includes(frag) && (!method || f.url.startsWith(method + ' ')) && f.cause === cause);
    assert.ok(hit, `no failure for ${frag} with main cause ${cause}. Got: ` + fails.filter(f => f.url.includes(frag)).map(f => f.cause).join(', '));
  }
  const causes = fails.map(f => f.cause);
  for (const c of ['pkce_mismatch', 'jwt_expired', 'oauth_invalid_grant']) assert.ok(causes.includes(c), 'missing main cause ' + c);
  assert.equal(await page.textContent('#b-auth'), '17');
});

await step('separates normal challenge steps from failures', async () => {
  const normals = await page.$$eval('details.normals .acard', cs => cs.map(c => c.querySelector('.aurl').textContent));
  assert.equal(normals.length, 4, normals.join('\n'));
  assert.ok(normals.some(u => u.includes('intranet')) && normals.some(u => u.includes('hr.corp')) && normals.filter(u => u.includes('portal.corp')).length === 2);
});

await step('identifies the authentication methods in use', async () => {
  const text = await page.textContent('#view-auth');
  for (const m of ['Bearer token (JWT)', 'HTTP Basic', 'NTLM', 'Kerberos (Negotiate)', 'Session cookie', 'AWS presigned URL', 'API key', 'OAuth 2.0 / OIDC sign-in', 'SAML 2.0 sign-in', 'Proxy asks for Negotiate/Basic']) assert.ok(text.includes(m), 'missing method ' + m);
});

await step('reconstructs sign-in flows with their checks', async () => {
  const flows = await page.$$eval('#view-auth .acard.flow', fs => fs.map(f => f.textContent));
  assert.ok(flows.some(f => /PKCE code_verifier matches/.test(f) && /ID token nonce matches/.test(f)), 'successful OIDC flow checks');
  assert.ok(flows.some(f => /PKCE code_verifier does not match/.test(f)), 'PKCE mismatch flow');
  assert.ok(flows.some(f => /split across connections \(501 → 502\)/.test(f)), 'NTLM flow');
  assert.ok(flows.some(f => /Audience does not match/.test(f) && /InResponseTo matches AuthnRequest _req-7f3a9c/.test(f)), 'SAML flow');
  assert.ok(flows.some(f => /Authenticated with Kerberos/.test(f)), 'Kerberos flow');
});

await step('explains the details: expiry times, scopes, users, clock skew', async () => {
  const text = await page.textContent('#view-auth');
  const has = re => assert.ok(re.test(text), 'Authentication view is missing ' + re);
  has(/The token expired 1 min before this request/);
  has(/lacks the required scope: orders:write/);
  has(/The token has: orders:read/);
  has(/user name or password for "jsmith"/);
  has(/The presigned URL expired 61 min before it was used/);
  has(/SameSite=unspecified \(treated as Lax\)/);
  has(/api\.example\.com is about 2 min ahead/);
  has(/AADSTS501481/);
  has(/sent unencrypted over HTTP/);
  const tokens = await page.$$eval('table.tokens tbody tr', rs => rs.map(r => r.textContent));
  assert.ok(tokens.some(r => /access/.test(r) && /after expiry/.test(r)), 'token table marks expired use');
  if (shots) await page.screenshot({ path: join(shots, 'auth-view.png'), fullPage: true });
});

await step('shows decoded credentials in the request Auth tab', async () => {
  await page.click('#view-auth .acard[data-cause="ntlm_split"] .ahead a');
  await page.waitForSelector('#detail:not(.hidden) .dtabs button[data-tab="auth"].active');
  let t = await page.textContent('#detail .dbody');
  assert.match(t, /CORP/); assert.match(t, /jsmith/); assert.match(t, /NTLMv2 \(48 bytes\)/); assert.match(t, /LAPTOP-7/);
  if (shots) await page.screenshot({ path: join(shots, 'auth-detail.png') });
  await page.click('#tabs button[data-view="auth"]');
  await page.click('#view-auth .acard[data-cause="id_token_as_access"] .ahead a');
  await page.waitForSelector('#detail .dtabs button[data-tab="auth"].active');
  t = await page.textContent('#detail .dbody');
  assert.match(t, /nonce/); assert.match(t, /spa-client-123/); assert.match(t, /signature is not verified/);
  for (const tab of ['headers', 'payload', 'response', 'timing', 'cookies', 'auth', 'issues']) {
    await page.click(`#detail .dtabs button[data-tab="${tab}"]`);
    const x = await page.textContent('#detail');
    assert.ok(!/\[object |\bundefined\b|\bNaN\b/.test(x), 'bad text in ' + tab);
  }
});

await step('auth:fail filter and findings integration', async () => {
  await page.click('#tabs button[data-view="requests"]');
  await page.fill('#q', 'auth:fail');
  await page.waitForFunction(() => document.querySelector('#count').textContent.startsWith('17 of 34'));
  await page.fill('#q', '');
  await page.click('#tabs button[data-view="findings"]');
  assert.equal(await page.$$eval('#fg-auth tbody tr', r => r.length), 17);
  assert.equal((await page.$$('#fg-client_error')).length, 0, 'auth failures should not also be listed as generic client errors');
});

await step('report is complete and contains no secrets', async () => {
  await page.click('#tabs button[data-view="auth"]');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#auth-dl')]);
  assert.equal(dl.suggestedFilename(), 'auth-failures-auth-report.md');
  const md = readFileSync(await dl.path(), 'utf8');
  assert.match(md, /^# Authentication report/);
  assert.match(md, /17 authentication failures/);
  assert.match(md, /PKCE code_verifier does not match/);
  const har = readFileSync(sample, 'utf8');
  const secrets = ['wrong-pass-123', 'rt-opaque-0f9e8d7c6b5a49382716', 'k-live-SAMPLEKEY-9f8e7d6c5b4a', 's3ss10n-abc123def456', 'c0ffee5ignature', 'CODE-ONE-1111', 'CODE-TWO-2222', 'regenerated-verifier', 'v1-correct-horse', 'hunter2-sample', 'AKIAEXAMPLE7SAMPLE00'];
  for (const m of har.matchAll(/"(eyJ[\w-]+\.[\w-]+\.[\w-]+)"/g)) secrets.push(m[1], m[1].split('.')[1]);
  for (const s of secrets) assert.ok(!md.includes(s), 'secret in report: ' + s.slice(0, 30));
});

await step('dark theme and phone width', async () => {
  await page.click('#btn-theme');
  await page.setViewportSize({ width: 390, height: 900 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert.equal(overflow, false);
  if (shots) await page.screenshot({ path: join(shots, 'auth-mobile-dark.png') });
});

await step('made no network requests and logged no errors', async () => {
  assert.deepEqual(network, []);
  assert.deepEqual(errors, []);
});

await browser.close();
console.log(`\n${passed} checks passed`);
