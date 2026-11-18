// End-to-end tests for the toolkit features: settings and rules, safer sharing,
// body tools, copy-as formats, timeline, sequence diagrams and NetLog.
// Usage: node test/toolkit.mjs [screenshot-dir]
import { createRequire } from 'node:module';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';

const { chromium } = createRequire(import.meta.url)('playwright');
const here = dirname(fileURLToPath(import.meta.url));
const appUrl = pathToFileURL(join(here, '..', 'har-analyzer.html')).href;
const sample = f => join(here, '..', 'sample', f);
const shots = process.argv[2];
if (shots) mkdirSync(shots, { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1400, height: 1000 } });
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

await step('no network requests and no errors', async () => {
  assert.deepEqual(network, []);
  assert.deepEqual(errors, []);
});

await browser.close();
console.log(`\n${passed} checks passed`);
