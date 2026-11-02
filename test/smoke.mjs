// End-to-end smoke test for har-analyzer.html using Playwright + Chromium.
// Usage: node test/smoke.mjs [screenshot-dir]
import { createRequire } from 'node:module';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';

// createRequire resolves a globally installed playwright too (ESM imports do not use NODE_PATH).
const { chromium } = createRequire(import.meta.url)('playwright');

const here = dirname(fileURLToPath(import.meta.url));
const appUrl = pathToFileURL(join(here, '..', 'har-analyzer.html')).href;
const sample = join(here, '..', 'sample', 'sample.har');
const shots = process.argv[2];
if (shots) mkdirSync(shots, { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1400, height: 900 } });
const page = await ctx.newPage();

const errors = [];
const network = [];
page.on('pageerror', e => errors.push('pageerror: ' + e.message));
page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
page.on('request', r => { if (!/^(file|data|blob):/.test(r.url())) network.push(r.url()); });

let passed = 0;
const step = async (name, fn) => { await fn(); passed++; console.log('  ✓ ' + name); };
// Type a filter and wait until the (debounced) list shows exactly one row whose URL contains `expect`.
const filterTo = async (q, expect) => {
  await page.fill('#q', q);
  await page.waitForFunction(x => { const r = document.querySelectorAll('#rows .row'); return r.length === 1 && r[0].title.includes(x); }, expect);
};

await page.goto(appUrl);

await step('rejects a file that is not a HAR', async () => {
  await page.setInputFiles('#file', { name: 'bad.har', mimeType: 'application/json', buffer: Buffer.from('{"hello":1}') });
  await page.waitForFunction(() => document.querySelector('#loaderr').textContent.includes('does not look like a HAR'));
});

await step('loads the sample HAR and shows the overview', async () => {
  await page.setInputFiles('#file', sample);
  await page.waitForSelector('#view-overview:not(.hidden) .cards');
  const info = await page.textContent('#fileinfo');
  assert.match(info, /sample\.har · 33 requests/);
  if (shots) await page.screenshot({ path: join(shots, '1-overview.png'), fullPage: true });
});

await step('detects every kind of finding', async () => {
  const codes = await page.$$eval('#view-findings details', ds => ds.map(d => d.id.replace('fg-', '')));
  for (const c of ['failed', 'preflight', 'server_error', 'client_error', 'cors', 'mixed', 'redirect_chain', 'insecure_cookie',
    'slow_ttfb', 'slow_total', 'slow_dns', 'slow_connect', 'slow_tls', 'queued', 'large', 'uncompressed', 'no_cache', 'duplicate']) {
    assert.ok(codes.includes(c), 'missing finding: ' + c + ' (got ' + codes.join(', ') + ')');
  }
  const count = (code) => page.$$eval(`#fg-${code} tbody tr`, r => r.length);
  assert.equal(await count('failed'), 2);
  assert.equal(await count('server_error'), 2);
  assert.equal(await count('duplicate'), 2);
  assert.equal(await count('redirect_chain'), 1);
  assert.equal(await count('mixed'), 1, 'only the http:// image is mixed content, not the http→https navigation');
});

await step('findings view renders', async () => {
  await page.click('#tabs button[data-view="findings"]');
  if (shots) await page.screenshot({ path: join(shots, '2-findings.png'), fullPage: true });
});

await step('filters requests with the query syntax', async () => {
  await page.click('#tabs button[data-view="requests"]');
  await page.fill('#q', 'status:5xx');
  await page.waitForFunction(() => document.querySelector('#count').textContent.startsWith('2 of 33'));
  await page.fill('#q', 'api -partner method:GET');
  await page.waitForFunction(() => /^\d+ of 33/.test(document.querySelector('#count').textContent));
  const urls = await page.$$eval('#rows .row', rs => rs.map(r => r.title));
  assert.ok(urls.length > 0 && urls.every(u => u.includes('api') && !u.includes('partner')), urls.join('\n'));
  await page.fill('#q', 'slower:1s');
  await page.waitForFunction(() => document.querySelector('#count').textContent.startsWith('3 of 33'));
  await page.fill('#q', 'hunter2');
  await page.waitForFunction(() => document.querySelector('#count').textContent.startsWith('0 of 33'));
  await page.check('#f-deep');
  await page.waitForFunction(() => document.querySelector('#count').textContent.startsWith('1 of 33'));
  await page.uncheck('#f-deep');
  await page.fill('#q', '');
  await page.selectOption('#f-status', 'errors');
  await page.waitForFunction(() => document.querySelector('#count').textContent.startsWith('7 of 33'));
  await page.selectOption('#f-status', '');
  await page.waitForFunction(() => document.querySelector('#count').textContent === '33 requests');
});

await step('sorts by time and opens request details', async () => {
  await page.click('#thead [data-key="time"]');
  const first = await page.$eval('#rows .row', r => r.title);
  assert.match(first, /\/api\/orders/);
  await page.click('#rows .row');
  await page.waitForSelector('#detail:not(.hidden) .dhead');
  assert.match(await page.textContent('#detail .status-pill'), /500/);
  await page.click('#detail .dtabs button[data-tab="timing"]');
  assert.match(await page.textContent('#detail .dbody'), /Waiting \(TTFB\)/);
  if (shots) await page.screenshot({ path: join(shots, '3-requests-timing.png') });
  await page.click('#detail .dtabs button[data-tab="issues"]');
  assert.match(await page.textContent('#detail .dbody'), /Server error/);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Escape');
  await page.waitForSelector('#detail.hidden', { state: 'attached' });
});

await step('shows formatted JSON bodies, request payloads and image previews', async () => {
  await page.click('#thead [data-key="i"]');
  await filterTo('/api/login', '/api/login');
  await page.click('#rows .row');
  await page.click('#detail .dtabs button[data-tab="payload"]');
  assert.match(await page.textContent('#detail .dbody'), /"password": "hunter2"/);
  await page.click('#detail .dtabs button[data-tab="response"]');
  assert.match(await page.textContent('#detail .dbody'), /JSON \(formatted\)/);
  await filterTo('logo.png', 'logo.png');
  await page.click('#rows .row');
  await page.click('#detail .dtabs button[data-tab="response"]');
  await page.waitForSelector('#detail img.imgprev');
  await page.fill('#q', '');
});

await step('redirect chain is linked in the detail pane', async () => {
  await filterTo('shop.example.com/home', '/home');
  await page.click('#rows .row');
  await page.click('#detail .dtabs button[data-tab="headers"]');
  const chain = await page.$$eval('#detail .chain div', d => d.length);
  assert.equal(chain, 4);
  await page.fill('#q', '');
});

await step('exports a redacted HAR with secrets removed', async () => {
  await page.click('#btn-export');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#x-har')]);
  assert.equal(dl.suggestedFilename(), 'sample-redacted.har');
  const text = readFileSync(await dl.path(), 'utf8');
  for (const secret of ['hunter2', 's3cr3tSessionValue', 'eyJhbGciOiJIUzI1NiJ9', 'AKIA-SAMPLE-KEY-123']) {
    assert.ok(!text.includes(secret), 'secret leaked into redacted HAR: ' + secret);
  }
  const har = JSON.parse(text);
  assert.equal(har.log.entries.length, 33);
  assert.ok(text.includes('alex@example.com'), 'non-sensitive data should be kept');
});

await step('exports the filtered request list as CSV', async () => {
  await page.selectOption('#f-status', 'failed');
  await page.click('#btn-export');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#x-csv')]);
  const csv = readFileSync(await dl.path(), 'utf8').trim().split(/\r\n/);
  assert.equal(csv.length, 3);
  assert.match(csv[1], /ERR_NAME_NOT_RESOLVED|ERR_CONNECTION_REFUSED/);
});

await step('dark theme and narrow screens render', async () => {
  await page.selectOption('#f-status', '');
  await page.click('#btn-theme');
  await page.click('#tabs button[data-view="overview"]');
  if (shots) await page.screenshot({ path: join(shots, '4-overview-dark.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 800 });
  await page.click('#tabs button[data-view="requests"]');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert.equal(overflow, false, 'page scrolls horizontally on a phone-width screen');
  if (shots) await page.screenshot({ path: join(shots, '5-mobile.png') });
});

await step('never renders stringified objects or nulls', async () => {
  await page.setViewportSize({ width: 1400, height: 900 });
  const chips = await page.$$eval('#type-chips .chip', cs => cs.map(c => c.textContent));
  assert.deepEqual(chips, ['All', 'Document', 'XHR / Fetch', 'Script', 'Stylesheet', 'Image', 'Font', 'Other']);
  assert.ok((await page.$$eval('#f-domain option', o => o.length)) === 9);
  const texts = [];
  for (const v of ['overview', 'findings']) { await page.click(`#tabs button[data-view="${v}"]`); texts.push(await page.textContent('main')); }
  await page.click('#tabs button[data-view="requests"]');
  for (const n of [0, 3, 8]) {
    await page.click(`#rows .row >> nth=${n}`);
    for (const t of ['headers', 'payload', 'response', 'timing', 'cookies', 'issues']) {
      await page.click(`#detail .dtabs button[data-tab="${t}"]`);
      texts.push(await page.textContent('#detail'));
    }
  }
  for (const t of texts) {
    const m = /[^]{0,60}(\[object |\bnull\b|undefined|NaN)[^]{0,60}/.exec(t);
    assert.equal(m, null, 'bad text rendered: ' + (m && m[0]));
  }
});

await step('made no network requests and logged no errors', async () => {
  assert.deepEqual(network, [], 'unexpected network requests: ' + network.join(', '));
  assert.deepEqual(errors, []);
});

await browser.close();
console.log(`\n${passed} checks passed`);
