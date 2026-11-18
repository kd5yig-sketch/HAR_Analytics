// End-to-end test of the Diagnose and Compare tabs.
// Usage: node test/diagnose.mjs [screenshot-dir]
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
page.on('request', r => { if (!/^(file|data|blob):/.test(r.url())) network.push(r.url()); });
let passed = 0;
const step = async (name, fn) => { await fn(); passed++; console.log('  ✓ ' + name); };

await page.goto(appUrl);
await page.setInputFiles('#file', sample('diagnostics.har'));
await page.waitForSelector('#view-overview:not(.hidden)');
await page.click('#tabs button[data-view="diag"]');

// Main cause expected per category, matched on the card's data-cause and (optionally) URL fragment.
const EXPECT = {
  cors: [['cors_method', '/v1/cart/items'], ['cors_wildcard_credentials', '/v1/prices'], ['cors_origin_mismatch', '/v1/catalog'], ['cors_multi_acao', '/v1/reviews'], ['cors_pna', '192.168.1.20'], ['cors_no_acao', '/v1/recommendations']],
  network: [['net_CERT_DATE_INVALID', 'legacy.example-partner.com'], ['net_CERT_AUTHORITY_INVALID', 'internal.example-corp.net'], ['net_BLOCKED_BY_CLIENT', 'analytics.example-tracker.com'], ['net_QUIC_PROTOCOL_ERROR', 'video.example-media.com'], ['net_outage', null]],
  server: [['server_nginx_reverse_proxy_', '/api/checkout'], ['server_aws_load_balancer_alb_elb_', '/v1/report'], ['server_cloudflare_edge', 'search.example-shop.com'], ['server_envoy_service_mesh', '/v1/inventory'], ['server_application', '/v1/orders/12345'], ['timeout_cluster', null]],
  ratelimit: [['rate_limited', '/v1/search'], ['retry_storm', '/v1/stock']],
  hidden: [['graphql_errors', '/graphql'], ['body_failure', '/api/payments'], ['html_not_json', '/api/v2/wishlist'], ['js_undefined_url', '/undefined/'], ['req_json_wrong_type', '/api/newsletter'], ['http_422', '/api/address'], ['bad_json', '/api/catalog/full'], ['grpc_permission_denied', '/grpc/']],
  redirect: [['loop_scheme', 'shop2.example-shop.com'], ['downgrade', '/account'], ['post_redirect', '/checkout/submit']],
  realtime: [['ws_idle', 'live.example-shop.com'], ['ws_200', 'chat.example-shop.com'], ['reconnect_loop', 'chat.example-shop.com'], ['sse_compressed', '/events/stream']],
  hang: [['pending', '/api/recommendations/slow'], ['very_slow', '/api/reports/annual'], ['slow_download', 'catalog.pdf']],
  cache: [['cdn_setcookie', 'static.example-shop.com'], ['stale_assets', 'app.js'], ['html_cached', 'www.example-shop.com/'], ['cached_cookie', '/api/me']],
  perf: [['doc_ttfb', 'www.example-shop.com/'], ['render_blocking', null], ['h1_queue', 'images.example-shop.com'], ['no_reuse', 'fonts.example-shop.com']],
  security: [['secret_in_url', 'access_token'], ['secret_in_url', 'password='], ['cleartext_creds', 'legacy.example-shop.com'], ['cookie_none_insecure', null], ['cookie_no_httponly', null], ['csp_violation', '/csp-report'], ['stack_trace', null]],
};

await step('diagnoses every scenario in every category with the right main cause', async () => {
  const cards = await page.$$eval('#view-diag .dsec .acard', cs => cs.map(c => ({ cat: c.dataset.cat, cause: c.dataset.cause, text: c.textContent })));
  for (const [cat, list] of Object.entries(EXPECT)) for (const [cause, frag] of list) {
    const hit = cards.find(c => c.cat === cat && c.cause === cause && (!frag || c.text.includes(frag)));
    assert.ok(hit, `${cat}: no card with main cause ${cause}${frag ? ' mentioning ' + frag : ''}. Got: ` + cards.filter(c => c.cat === cat).map(c => c.cause).join(', '));
  }
});

await step('explains the specifics, not just the category', async () => {
  const text = await page.textContent('#view-diag');
  const has = re => assert.ok(re.test(text), 'Diagnose view is missing ' + re);
  has(/does not allow the request header authorization/); has(/The \* wildcard never covers Authorization/);
  has(/probably cached for a page on another origin/);
  has(/target did not respond before the load balancer’s idle timeout/);
  has(/2 requests failed after ~60\.\d s/); has(/60 s: nginx proxy_read_timeout, AWS ALB\/ELB idle timeout/);
  has(/Cloudflare: the origin took longer than 100 s/);
  has(/The application crashed: java\.lang\.NullPointerException/);
  has(/retried after 2 s, before Retry-After \(30 s\)/);
  has(/Cannot query field "discountCode"/); has(/GRAPHQL_VALIDATION_FAILED/);
  has(/The body is JSON but was sent as Content-Type: text\/plain/);
  has(/Field error: zip: must be 5 digits/);
  has(/truncated \(44 B of 178 KB\)/);
  has(/redirects flip between http and https/);
  has(/An idle timeout closed the WebSocket/);
  has(/Requests to unrelated hosts .* failed at the same time/);
  has(/Responses set cookies \(\d+ of 5\)/);
  has(/Other visitors may receive this user’s cookie \(shop_session\)/);
  has(/blocked https:\/\/cdn\.example-widgets\.com\/widget\.js/);
  has(/openssl s_client -connect legacy\.example-partner\.com:443/);
});

await step('keeps harmless items out of the problem list', async () => {
  const normals = await page.$$eval('#view-diag details.normals .acard', cs => cs.map(c => c.dataset.cause));
  assert.ok(normals.includes('net_ABORTED'), 'cancelled request should be a note');
  assert.ok(normals.includes('graphql_apq'), 'persisted-query miss followed by a retry should be a note');
  const main = await page.$$eval('#view-diag .dsec > .acard', cs => cs.map(c => c.dataset.cause));
  assert.ok(!main.includes('net_ABORTED') && !main.includes('graphql_apq'));
  const dupDowngrades = (await page.$$eval('#view-diag .dsec > .acard[data-cause="downgrade"]', cs => cs.length));
  assert.equal(dupDowngrades, 1, 'redirect-loop hops must not be reported as separate downgrades');
  if (shots) await page.screenshot({ path: join(shots, 'diag-view.png'), fullPage: false });
});

await step('integrates with findings, filters, the overview and request details', async () => {
  const badge = +(await page.textContent('#b-diag'));
  assert.ok(badge >= 50, 'Diagnose badge should count problems, got ' + badge);
  await page.click('#tabs button[data-view="findings"]');
  for (const code of ['cors', 'diag_hidden', 'diag_ratelimit', 'diag_redirect', 'diag_realtime', 'diag_hang', 'diag_security', 'diag_cache']) assert.ok(await page.$('#fg-' + code), 'missing findings group ' + code);
  assert.match(await page.textContent('#fg-failed'), /The server certificate has expired.*\(CERT_DATE_INVALID\)/);
  assert.match(await page.textContent('#fg-server_error'), /from nginx \(reverse proxy\)/);
  await page.click('#tabs button[data-view="overview"]');
  assert.match(await page.textContent('#view-overview'), /Diagnosis[\s\S]*Hidden failures & API errors/);
  await page.click('#tabs button[data-view="requests"]');
  await page.fill('#q', 'diag:cors');
  await page.waitForFunction(() => /^\d+ of 121/.test(document.querySelector('#count').textContent));
  await page.fill('#q', 'graphql');
  await page.waitForFunction(() => document.querySelectorAll('#rows .row').length === 3);
  await page.click('#rows .row');
  await page.click('#detail .dtabs button[data-tab="diag"]');
  assert.match(await page.textContent('#detail .dbody'), /GRAPHQL_VALIDATION_FAILED/);
  for (const tab of ['headers', 'payload', 'response', 'timing', 'cookies', 'diag', 'issues']) {
    await page.click(`#detail .dtabs button[data-tab="${tab}"]`);
    const txt = (await page.textContent('#detail')).replace(/"undefined"/g, '');
    assert.ok(!/\[object |\bundefined\b|\bNaN\b/.test(txt), 'bad text in ' + tab + ': ' + (txt.match(/.{0,40}(\[object |\bundefined\b|\bNaN\b).{0,40}/) || [''])[0]);
  }
  await page.fill('#q', '');
});

await step('diagnosis report is complete and contains no secrets', async () => {
  await page.click('#tabs button[data-view="diag"]');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#diag-dl')]);
  const md = readFileSync(await dl.path(), 'utf8');
  assert.match(md, /^# Diagnosis report/); assert.match(md, /## CORS/); assert.match(md, /## Security hygiene/);
  for (const s of ['hunter2-sample', 'sess-abc123def456', 'sess-other-user-999', 'eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl', 'abc12345', 'tok-xyz789']) assert.ok(!md.includes(s), 'secret in report: ' + s);
  const view = await page.textContent('#view-diag');
  const clean = view.replace(/"undefined"/g, '').replace(/\/undefined\//g, '/');
  const bad = clean.match(/.{0,50}(\[object |\bNaN\b|: undefined|\(undefined\)|undefined (ms|s|KB|MB|B)\b|= undefined).{0,50}/);
  assert.equal(bad, null, 'bad text in Diagnose view: ' + (bad && bad[0]));
});

await step('Compare: ranks the differences that explain the failure', async () => {
  await page.setInputFiles('#file', sample('compare-working.har'));
  await page.waitForFunction(() => document.querySelector('#fileinfo').textContent.startsWith('compare-working.har'));
  await page.click('#btn-compare');
  await page.setInputFiles('#file2', sample('compare-broken.har'));
  await page.waitForSelector('#view-compare:not(.hidden) ol.explain');
  const items = await page.$$eval('ol.explain li', l => l.map(x => x.textContent));
  assert.match(items[0], /Works in A \(200\) but fails in B \(401\): GET api\.example\.com\/api\/orders/);
  assert.match(items[0], /Request Authorization Bearer … → \(none\)/);
  const all = items.join('\n');
  assert.match(all, /GET api\.example\.com\/api\/orders\/:n/, 'IDs in paths should be matched as placeholders');
  assert.match(all, /Fails in B and was not requested in A: GET api\.example\.com\/api\/feature-flags \(500\)/);
  assert.match(all, /Requested in A but never in B: POST api\.example\.com\/api\/token/);
  assert.match(all, /resolved to different servers: A 203\.0\.113\.10 vs B 198\.51\.100\.99/);
  assert.match(all, /Browser \(User-Agent\) differs/);
  assert.match(all, /Slower in B: GET api\.example\.com\/api\/config \(\d+ ms → 2\.60 s\)/);
  if (shots) await page.screenshot({ path: join(shots, 'compare-view.png'), fullPage: true });
});

await step('Compare: swap and clear', async () => {
  await page.click('#cmp-swap');
  await page.waitForFunction(() => document.querySelector('#fileinfo').textContent.startsWith('compare-broken.har'));
  await page.waitForSelector('#view-compare:not(.hidden) ol.explain');
  assert.match(await page.textContent('ol.explain'), /Fails in A but works in B: GET api\.example\.com\/api\/orders/);
  await page.click('#view-compare button:has-text("Clear")');
  await page.waitForSelector('#cmp-open');
});

await step('phone width, dark theme, no network, no errors', async () => {
  await page.click('#btn-theme');
  await page.setInputFiles('#file', sample('diagnostics.har'));
  await page.waitForFunction(() => document.querySelector('#fileinfo').textContent.startsWith('diagnostics.har'));
  await page.click('#tabs button[data-view="diag"]');
  await page.setViewportSize({ width: 390, height: 900 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false, 'horizontal scroll at phone width');
  if (shots) await page.screenshot({ path: join(shots, 'diag-mobile-dark.png') });
  assert.equal(await page.evaluate(() => D.error), '');
  assert.deepEqual(network, []);
  assert.deepEqual(errors, []);
});

await browser.close();
console.log(`\n${passed} checks passed`);
