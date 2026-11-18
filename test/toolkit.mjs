// End-to-end tests for the toolkit features: settings and rules, safer sharing,
// body tools, copy-as formats, timeline, sequence diagrams and NetLog.
// Usage: node test/toolkit.mjs [screenshot-dir]
import { createRequire } from 'node:module';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';
import { inflateRawSync, gzipSync } from 'node:zlib';

const { chromium } = createRequire(import.meta.url)('playwright');
const here = dirname(fileURLToPath(import.meta.url));
const appUrl = pathToFileURL(join(here, '..', 'har-analyzer.html')).href;
const sample = f => join(here, '..', 'sample', f);
const shots = process.argv[2];
if (shots) mkdirSync(shots, { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1400, height: 1000 } });
await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
const page = await ctx.newPage();
const errors = [], network = [];
page.on('pageerror', e => errors.push('pageerror: ' + e.message));
page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
page.on('request', r => { if (!/^(file|data|blob|about):/.test(r.url())) network.push(r.url()); });
let passed = 0;
const step = async (name, fn) => { await fn(); passed++; console.log('  ✓ ' + name); };
const open = async f => {
  await page.setInputFiles('#file', sample(f));
  await page.waitForFunction(n => document.querySelector('#fileinfo').textContent.startsWith(n) && document.querySelector('#loading').classList.contains('hidden'), f);
};
// Minimal .zip reader (central directory) to check the case bundle.
function unzip(buf) {
  const out = {}; let end = buf.length - 22; while (end >= 0 && buf.readUInt32LE(end) !== 0x06054b50) end--;
  let p = buf.readUInt32LE(end + 16); const n = buf.readUInt16LE(end + 10);
  for (let k = 0; k < n; k++) {
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32), off = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nlen).toString('utf8');
    const lnl = buf.readUInt16LE(off + 26), lxl = buf.readUInt16LE(off + 28), data = buf.slice(off + 30 + lnl + lxl, off + 30 + lnl + lxl + csize);
    out[name] = (method === 8 ? inflateRawSync(data) : data).toString('utf8');
    p += 46 + nlen + xlen + clen;
  }
  return out;
}
const download = async (click) => { const [dl] = await Promise.all([page.waitForEvent('download'), click()]); return { name: dl.suggestedFilename(), path: await dl.path() }; };

await page.goto(appUrl);

await step('settings: rules, ignored hosts and first-party hosts change the analysis', async () => {
  await open('diagnostics.har');
  await page.click('#btn-settings');
  await page.fill('#set-first', 'example-shop.com\nexample-shop.net');
  await page.fill('#set-ignore', 'analytics.example-tracker.com');
  await page.click('#set-add-rule');
  const r1 = page.locator('#set-rules .rule').nth(0);
  await r1.locator('.r-name').fill('API calls under 1 s');
  await r1.locator('.r-host').fill('api.example-shop.net');
  await r1.locator('.r-path').fill('/v1/*');
  await r1.locator('.r-check').selectOption('slower');
  await r1.locator('.r-value').fill('1000');
  await r1.locator('.r-sev').selectOption('error');
  await page.click('#set-add-rule');
  const r2 = page.locator('#set-rules .rule').nth(1);
  await r2.locator('.r-host').fill('www.example-shop.com');
  await r2.locator('.r-path').fill('/api/*');
  await r2.locator('.r-check').selectOption('reqHeaderMissing');
  await r2.locator('.r-value').fill('X-Request-Id');
  await page.click('#set-save');
  await page.waitForFunction(() => /Saved/.test(document.querySelector('#set-status').textContent));
  await page.click('#tabs button[data-view="diag"]');
  const rules = await page.$$eval('#dsec-rules .acard', cs => cs.map(c => c.textContent));
  assert.equal(rules.length, 2, rules.join('\n'));
  assert.ok(rules.some(t => /API calls under 1 s — 2 requests/.test(t) && /took 1\.0 min \(limit 1\.00 s\)|took 60\.\d s/.test(t)), rules[0]);
  assert.ok(rules.some(t => /request had no X-Request-Id header/.test(t)));
  const net = await page.textContent('#view-diag');
  assert.ok(!/analytics\.example-tracker\.com/.test(net), 'ignored host still diagnosed');
  await page.click('#tabs button[data-view="findings"]');
  assert.ok(await page.$('#fg-diag_rules'), 'rule matches should be listed in Findings');
});

await step('settings: persist across reloads and round-trip through export / import', async () => {
  await page.reload();
  await page.click('#btn-settings');
  assert.equal(await page.inputValue('#set-ignore'), 'analytics.example-tracker.com');
  assert.equal(await page.locator('#set-rules .rule').count(), 2);
  const ex = await download(() => page.click('#set-export'));
  assert.equal(ex.name, 'har-analytics-settings.json');
  const saved = JSON.parse(readFileSync(ex.path, 'utf8'));
  assert.equal(saved.rules.length, 2);
  page.once('dialog', d => d.accept());
  await page.click('#set-reset');
  await page.waitForFunction(() => document.querySelectorAll('#set-rules .rule').length === 0);
  await page.setInputFiles('#settings-file', ex.path);
  await page.waitForFunction(() => document.querySelectorAll('#set-rules .rule').length === 2);
});

await step('settings: expected token issuer / audience make the auth diagnosis definite', async () => {
  await page.click('#btn-settings');
  await page.click('#set-add-token');
  const t = page.locator('#set-tokens .tok').nth(0);
  await t.locator('.t-hosts').fill('api.example.com');
  await t.locator('.t-iss').fill('https://login.example-idp.com');
  await t.locator('.t-aud').fill('api://orders');
  await page.click('#set-save');
  await open('auth-failures.har');
  await page.click('#tabs button[data-view="auth"]');
  const txt = await page.textContent('#view-auth');
  assert.match(txt, /The token is for https:\/\/api\.example\.com, but this API expects api:\/\/orders/);
  assert.ok(await page.$('#view-auth [data-cause="jwt_audience_mismatch"]'));
});

await step('settings: custom redaction patterns are applied to exported HARs', async () => {
  await page.click('#btn-settings');
  await page.fill('#set-redact', 'alex@example\\.com\nCUST-[0-9]+\n([bad');
  await page.click('#set-save');
  assert.match(await page.textContent('#set-redact-msg'), /\(\[bad/);
  await page.click('#btn-export');
  const ex = await download(() => page.click('#x-har'));
  const text = readFileSync(ex.path, 'utf8');
  assert.ok(!text.includes('alex@example.com'), 'custom pattern not applied');
  page.once('dialog', d => d.accept());
  await page.click('#btn-settings');
  await page.click('#set-reset');
});

const PII = ['alex.example@mail.example', 'jane@mail.example', 'jane%40mail.example', '4111 1111 1111 1111', '123-45-6789', 'GB82 WEST 1234 5698 7654 32', '(512) 555-0147', '198.51.100.23', 'sample-opaque-token-1234567890'];

await step('sharing: personal data is found, with validators keeping false alarms out', async () => {
  await open('personal-data.har');
  await page.click('#tabs button[data-view="diag"]');
  const card = await page.textContent('#view-diag .acard[data-cause="pii"]');
  assert.match(card, /Email address: 3/); assert.match(card, /Payment card number: 1 \(e\.g\. 41\*+1111\)/);
  assert.match(card, /US Social Security number: 1/); assert.match(card, /Bank account \(IBAN\): 1/); assert.match(card, /Phone number: 1 /); assert.match(card, /Client IP address/);
  assert.ok(!/4111111111111112|20261102160000/.test(card), 'near-misses must not be reported or shown');
  await page.click('#btn-export');
  assert.match(await page.textContent('#x-pii-summary'), /payment card number ×1/);
});

await step('sharing: preview lists every change, and the redacted HAR has no personal data', async () => {
  await page.click('#x-preview');
  const prev = await page.textContent('#x-preview-out');
  for (const label of ['URLs (query parameters or personal data)', 'Request header: authorization', 'Request header: x-forwarded-for', 'Request bodies (fields masked)', 'Response bodies removed']) assert.ok(prev.includes(label), 'preview missing ' + label + '\n' + prev);
  for (const v of PII) assert.ok(!prev.includes(v), 'preview shows ' + v);
  await page.uncheck('#x-resbody');
  await page.waitForFunction(() => /Response bodies \(fields masked\)/.test(document.querySelector('#x-preview-out').textContent));
  const ex = await download(() => page.click('#x-har'));
  const har = readFileSync(ex.path, 'utf8');
  for (const v of PII) assert.ok(!har.includes(v), 'redacted HAR still contains ' + v);
  assert.ok(har.includes('4111111111111112') && har.includes('A-1001'), 'non-personal values must be kept');
  await page.click('#btn-export');
  await page.uncheck('#x-pii');
  const ex2 = await download(() => page.click('#x-har'));
  assert.ok(readFileSync(ex2.path, 'utf8').includes('alex.example@mail.example'), 'personal data kept when masking is switched off');
});

await step('notes: star and annotate requests; notes persist, filter and show in rows', async () => {
  await page.click('#tabs button[data-view="requests"]');
  await page.fill('#q', 'api/checkout');
  await page.waitForFunction(() => document.querySelectorAll('#rows .row').length === 1);
  await page.click('#rows .row');
  await page.click('#note-star');
  await page.click('#note-btn');
  await page.fill('#note-text', 'Customer says the order failed here; card ending 1111.');
  await page.waitForTimeout(400);
  assert.match(await page.textContent('#rows .row'), /★/);
  await page.reload();
  await open('personal-data.har');
  await page.click('#tabs button[data-view="requests"]');
  await page.fill('#q', 'note:any');
  await page.waitForFunction(() => /^1 of 4/.test(document.querySelector('#count').textContent));
  await page.click('#rows .row');
  assert.equal(await page.inputValue('#note-text'), 'Customer says the order failed here; card ending 1111.');
  await page.fill('#q', '');
});

await step('sharing: the case bundle contains every file and no secrets or personal data', async () => {
  await page.click('#btn-export');
  const ex = await download(() => page.click('#x-bundle'));
  assert.equal(ex.name, 'personal-data-case.zip');
  const files = unzip(readFileSync(ex.path));
  assert.deepEqual(Object.keys(files).sort(), ['README.md', 'authentication.md', 'diagnosis.md', 'notes.md', 'personal-data-redacted.har', 'requests.csv']);
  const all = Object.values(files).join('\n');
  for (const v of PII) assert.ok(!all.includes(v), 'bundle contains ' + v);
  assert.match(files['README.md'], /Payment card number: 1/); assert.match(files['README.md'], /Personal data \(emails.*\) masked/);
  assert.match(files['notes.md'], /★ #2 POST https:\/\/checkout\.example-store\.com\/api\/checkout/);
  assert.match(files['notes.md'], /Customer says the order failed here/);
  JSON.parse(files['personal-data-redacted.har']);
});

const selectRow = async (q, expectN = 1) => {
  await page.click('#tabs button[data-view="requests"]');
  await page.fill('#q', q);
  await page.waitForFunction(n => document.querySelectorAll('#rows .row').length === n, expectN);
  await page.click('#rows .row');
  await page.waitForSelector('#detail:not(.hidden)');
};

await step('body tools: JSON tree, path search and path errors', async () => {
  await open('diagnostics.har');
  await selectRow('graphql', 3);
  await page.click('#detail .dtabs button[data-tab="response"]');
  await page.waitForSelector('#detail .jtree');
  assert.match(await page.textContent('#detail .jtree'), /"errors": \[1\]/);
  await page.fill('#detail .jpath', 'errors[*].extensions.code');
  await page.waitForFunction(() => /1 match/.test(document.querySelector('#detail .jmatches').textContent));
  assert.match(await page.textContent('#detail .jmatches'), /\$\.errors\[0\]\.extensions\.code\s*GRAPHQL_VALIDATION_FAILED/);
  await page.fill('#detail .jpath', 'errors[?(@.x)]');
  await page.waitForFunction(() => /Path error: unsupported/.test(document.querySelector('#detail .jmatches').textContent));
  await page.click('#detail .dtabs button[data-tab="payload"]');
  assert.match(await page.textContent('#detail .jtree'), /"operationName": "GetCart"/);
});

await step('body tools: sandboxed HTML preview loads nothing from the network', async () => {
  await selectRow('wishlist');
  await page.click('#detail .dtabs button[data-tab="response"]');
  await page.click('#detail .bmode button[data-mode="preview"]');
  const fr = await page.waitForSelector('#detail iframe.hprev');
  assert.equal(await fr.getAttribute('sandbox'), '');
  const frame = await fr.contentFrame();
  await frame.waitForSelector('#root', { state: 'attached' });
  assert.equal(await frame.title(), 'Example Shop');
  if (shots) await page.screenshot({ path: join(shots, 'html-preview.png') });
});

await step('body tools: decoder handles JWT, base64 + gzip and timestamps', async () => {
  await page.click('#btn-decode');
  await page.fill('#dec-in', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1IiwiZXhwIjoxNzkzNjM1MjMwfQ.c2ln');
  await page.waitForFunction(() => /JWT payload/.test(document.querySelector('#dec-out').textContent));
  assert.match(await page.textContent('#dec-out'), /exp: 2026-11-02 16:00:30 UTC/);
  await page.fill('#dec-in', gzipSync('compressed text here').toString('base64'));
  await page.waitForFunction(() => /Base64 \+ gzip/.test(document.querySelector('#dec-out').textContent));
  assert.match(await page.textContent('#dec-out'), /compressed text here/);
  await page.fill('#dec-in', '1793635230');
  await page.waitForFunction(() => /Unix time \(seconds\)/.test(document.querySelector('#dec-out').textContent));
  await page.click('#dec-close');
});

await step('body tools: compare responses (JSON structure and headers)', async () => {
  await selectRow('v1/search', 2);
  await page.click('#btn-diff');
  await page.waitForSelector('#dlg-diff[open] #diff-out h4');
  const t = await page.textContent('#diff-out');
  assert.match(t, /The JSON bodies are identical|identical/);
  assert.match(t, /retry-after\s*30\s*28/);
  await page.click('#diff-close');
  await selectRow('graphql', 3);
  await page.click('#btn-diff');
  const opts = await page.$$eval('#diff-with option', o => o.map(x => x.textContent));
  assert.ok(opts.length >= 2 && /graphql/.test(opts[0]), 'same-endpoint requests should be offered first');
  await page.selectOption('#diff-with', { index: 1 });
  await page.waitForFunction(() => /\$\.data/.test(document.querySelector('#diff-out').textContent));
  if (shots) await page.screenshot({ path: join(shots, 'diff.png') });
  await page.click('#diff-close');
  await page.fill('#q', '');
});

await step('copy as: every format is offered and copies runnable code', async () => {
  await open('auth-failures.har');
  await selectRow('/v1/orders', 3);
  await page.click('#btn-copy');
  const formats = await page.$$eval('#copy-menu button', b => b.map(x => x.textContent));
  assert.deepEqual(formats, ['URL', 'cURL (bash)', 'JavaScript fetch', 'PowerShell', 'Python requests', 'HTTPie', 'wget']);
  const copied = {};
  for (const f of ['url', 'curl', 'fetch', 'powershell', 'python', 'httpie', 'wget']) {
    if (f !== 'url') await page.click('#btn-copy');
    await page.click(`#copy-menu button[data-format="${f}"]`);
    copied[f] = await page.evaluate(() => navigator.clipboard.readText());
  }
  assert.match(copied.url, /^https:\/\/api\.example\.com\/v1\/orders$/);
  assert.match(copied.curl, /^curl 'https:\/\/api\.example\.com\/v1\/orders' \\\n  -H 'user-agent:/);
  assert.match(copied.fetch, /await fetch\("https:\/\/api\.example\.com\/v1\/orders", \{\n  method: "GET"/);
  assert.match(copied.powershell, /Invoke-WebRequest -Uri 'https:\/\/api\.example\.com\/v1\/orders'/);
  assert.match(copied.python, /requests\.request\(\n    "GET",/);
  assert.match(copied.httpie, /^http \\\n  GET \\\n  'https:/);
  assert.match(copied.wget, /^wget --quiet --output-document=- --method=GET/);
  assert.ok(!(await page.isVisible('#copy-menu')), 'menu closes after copying');
});

await step('copy as: Postman collection of the filtered requests, credentials as variables', async () => {
  await page.click('#btn-export');
  const ex = await download(() => page.click('#x-postman'));
  assert.equal(ex.name, 'auth-failures.postman_collection.json');
  const pm = JSON.parse(readFileSync(ex.path, 'utf8'));
  assert.equal(pm.info.schema, 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json');
  assert.equal(pm.item.length, 3, 'only the filtered requests');
  const text = JSON.stringify(pm);
  assert.ok(!/eyJ[\w-]+\.eyJ/.test(text), 'no live tokens in the collection');
  assert.ok(pm.item.some(i => i.request.header.some(h => h.key.toLowerCase() === 'authorization' && h.value === 'Bearer {{token}}')));
  assert.ok(pm.variable.some(v => v.key === 'token'));
  await page.fill('#q', '');
});

await step('timeline: insights, charts, and click-through filters', async () => {
  await open('timeline.har');
  await page.click('#tabs button[data-view="timeline"]');
  const ins = await page.textContent('#view-timeline ul.insights');
  assert.match(ins, /Errors start at \+6:0\d .*0% of requests failed before, \d+% after/);
  assert.match(ins, /Requests got slower: median \d+ ms in the first third of the capture, \d+ ms in the last third/);
  const bars = await page.$$('#view-timeline svg.chart g.bucket');
  assert.ok(bars.length >= 20 && bars.length <= 100, 'bucket count ' + bars.length);
  assert.ok(await page.$('#view-timeline .line-p95'), 'p95 line drawn');
  const rows = await page.$$eval('#view-timeline table.eps tbody tr', r => r.map(x => x.textContent));
  assert.match(rows[0], /GET api\.example\.com\/api\/orders\/:n599\d+ \(\d+%\)/);
  if (shots) await page.screenshot({ path: join(shots, 'timeline.png'), fullPage: true });
  await page.click('#view-timeline table.eps tbody tr');
  await page.waitForFunction(() => /^599 of 698/.test(document.querySelector('#count').textContent));
  await page.click('#tabs button[data-view="timeline"]');
  await bars[bars.length - 1].click();
  await page.waitForFunction(() => /^time:\d/.test(document.querySelector('#q').value) && /^\d+ of 698/.test(document.querySelector('#count').textContent));
  await page.click('#tabs button[data-view="timeline"]');
  await page.click('#view-timeline ul.insights li.ins-errors a');
  await page.waitForFunction(() => /^time:36\d/.test(document.querySelector('#q').value));
  await page.fill('#q', '');
});

await step('no network requests and no errors', async () => {
  assert.deepEqual(network, []);
  assert.deepEqual(errors, []);
});

await browser.close();
console.log(`\n${passed} checks passed`);
