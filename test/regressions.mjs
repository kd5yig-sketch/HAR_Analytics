// Regression tests for false positives found on real Chromium captures (github.com, pypi.org, npm,
// a TLS-inspecting proxy). Runs the core analysis under Node. Usage: node test/regressions.mjs
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { coreSource } from '../tools/build.mjs';

const ctx = vm.createContext({ console, TextEncoder, TextDecoder, URL, URLSearchParams, CompressionStream, DecompressionStream, Blob, Response, atob, btoa, crypto: globalThis.crypto });
vm.runInContext(coreSource() + '\n;globalThis.K = { get S() { return S; }, D, A, normalize, analyze, analyzeAuth, runDiagnostics, piiInText, htmlDecode, certFacts, netlogToHar };', ctx);
const K = ctx.K;

const T0 = Date.parse('2026-11-18T10:00:00Z');
const H = o => Object.entries(o || {}).map(([name, value]) => ({ name, value }));
function entry(o) {
  return {
    startedDateTime: new Date(T0 + (o.at || 0)).toISOString(), time: o.time ?? 40, pageref: o.page || 'p1', _resourceType: o.rt || 'fetch',
    request: { method: o.method || 'GET', url: o.url, httpVersion: 'HTTP/1.1', headers: H(o.req), queryString: [], cookies: [], headersSize: -1, bodySize: -1, ...(o.post ? { postData: o.post } : {}) },
    response: { status: o.status ?? 200, statusText: o.statusText || '', httpVersion: o.status === 0 ? '' : (o.proto || 'HTTP/1.1'), headers: H(o.res), cookies: [], content: { size: (o.body || '').length, mimeType: o.mime || 'application/json', text: o.body || '' }, redirectURL: '', headersSize: -1, bodySize: -1, ...(o.fail ? { _failureText: o.fail } : {}) },
    cache: {}, timings: { blocked: o.blocked ?? 1, dns: -1, connect: -1, ssl: -1, send: 1, wait: 30, receive: 5 },
  };
}
async function run(entries) {
  const har = { log: { version: '1.2', creator: { name: 'test' }, pages: [{ id: 'p1', startedDateTime: new Date(T0).toISOString(), title: 't', pageTimings: {} }], entries } };
  const n = K.normalize(har);
  Object.assign(K.S, { fileName: 't.har', har, pages: n.pages, entries: n.entries, base: n.base, netlog: null });
  K.analyze(); await K.analyzeAuth(); K.runDiagnostics();
  return { diag: K.D.events.filter(v => !v.normal), auth: K.A.events.filter(v => !v.normal) };
}
const ids = evs => Array.from(evs.flatMap(v => v.causes.map(c => c.id)));
let passed = 0;
const step = async (name, fn) => { await fn(); passed++; console.log('  ✓ ' + name); };
const page = (url, at) => entry({ url, at, rt: 'document', mime: 'text/html', body: '<html><title>x</title></html>' });

await step('the same asset failing on each page load is not a retry storm', async () => {
  const E = [];
  for (let k = 0; k < 6; k++) { E.push(page('https://site.example/p' + k, k * 3000)); E.push(entry({ url: 'https://api.site.example/v1/config', at: k * 3000 + 100, status: 0, fail: 'net::ERR_CONNECTION_RESET' })); }
  assert.ok(!ids((await run(E)).diag).includes('retry_storm'));
  const F = [page('https://site.example/', 0)];
  for (let k = 0; k < 5; k++) F.push(entry({ url: 'https://api.site.example/v1/config', at: 100 + k * 150, status: 503 }));
  assert.ok(ids((await run(F)).diag).includes('retry_storm'), 'a real retry storm inside one page load is still found');
  const G = [page('https://site.example/', 0)];
  for (let k = 0; k < 5; k++) G.push(entry({ url: 'https://cdn.site.example/app.css', rt: 'stylesheet', mime: 'text/css', at: 100 + k * 150, status: 0, fail: 'net::ERR_TUNNEL_CONNECTION_FAILED' }));
  assert.ok(!ids((await run(G)).diag).includes('retry_storm'), 'static assets re-fetched by the browser');
});

await step('personal data: no hits on hashes, SVG paths, git remotes, placeholders or retina images', async () => {
  for (const t of ['https://github.githubassets.com/assets/62515-31408097eb7d17aa.js', 'M373.876 71.5861C388.853 71.5861 400 60.2448 400 46.1893', 'git@github.com:microsoft/playwright.git', '"heading":"you@domain.com"', 'logo@2x.png', 'noreply@github.com'])
    assert.deepEqual([...K.piiInText(t)].map(x => x.kind), [], t);
  const found = [...K.piiInText('Call +1 415 555 0134, card 4111 1111 1111 1111. Mail alex@example.com')].map(x => x.kind).sort();
  assert.deepEqual(found, ['card', 'email', 'phone']);
});

await step('a rejected sign-in form is explained (CSRF token, wrong password, empty password)', async () => {
  const form = (fields, status, res, body) => entry({ method: 'POST', url: 'https://site.example/session', rt: 'document', status, mime: 'text/html', body: body || '<html><head><title>Oh no &middot; Site</title></head></html>', req: { cookie: 'sess=abc' }, res, post: { mimeType: 'application/x-www-form-urlencoded', text: new URLSearchParams(fields).toString() } });
  let r = await run([page('https://site.example/login', 0), form({ authenticity_token: 'abc', login: 'pat', password: 'x' }, 422)]);
  assert.equal(r.auth.length, 1); assert.equal(r.auth[0].headline, 'Sign-in form for "pat" rejected with HTTP 422'); assert.equal(r.auth[0].causes[0].id, 'csrf');
  r = await run([form({ login: 'pat', password: 'x' }, 200, {}, '<html><title>Sign in</title><p>Incorrect username or password.</p><input type="password" name="password"></html>')]);
  assert.deepEqual(ids(r.auth).slice(0, 1), ['form_bad_password']);
  r = await run([form({ email: 'pat@example.com', password: '' }, 400)]);
  assert.ok(ids(r.auth).includes('form_empty_password')); assert.ok(!r.auth[0].headline.includes('@'), 'email user names stay out of the headline');
  assert.equal(K.htmlDecode('Oh no &middot; GitHub &#8253; &#x2014; &amp;'), 'Oh no · GitHub ‽ — &');
});

await step('a Privacy Pass challenge is not an authentication failure or a leaked token', async () => {
  const r = await run([page('https://pypi.example/', 0), entry({ method: 'POST', url: 'https://pypi.example/_fs-ch-1T1/pat?token=abcdefghijklmnop', status: 401, res: { 'www-authenticate': 'PrivateToken challenge=AAIA, token-key=AAA' } })]);
  assert.equal(r.auth.length, 0); assert.ok(!ids(r.diag).includes('secret_in_url'));
});

await step('edge cookies (Cloudflare bot management, load balancer affinity) on cached responses are expected', async () => {
  const cached = c => entry({ url: 'https://registry.example/pkg/latest', res: { age: '198', 'cache-control': 'public, max-age=300', 'cf-cache-status': 'HIT', 'set-cookie': c } });
  assert.ok(!ids((await run([cached('__cf_bm=abc; path=/; HttpOnly')])).diag).includes('cached_cookie'));
  assert.ok(!ids((await run([cached('[318 bytes were stripped]')])).diag).includes('cached_cookie'));
  assert.ok(ids((await run([cached('session=abc; path=/')])).diag).includes('cached_cookie'), 'an app session cookie is still flagged');
});

await step('repeated identical API failures are one finding; failed requests are not "queued on HTTP/1.1"', async () => {
  let r = await run([entry({ url: 'https://site.example/fastly/logo', status: 404, mime: 'text/html', body: '<html></html>' }), entry({ at: 900, url: 'https://site.example/fastly/logo', status: 404, mime: 'text/html', body: '<html></html>' })]);
  const nf = r.diag.filter(v => v.causes.some(c => c.id === 'api_not_found'));
  assert.equal(nf.length, 1); assert.match(nf[0].headline, /\(2 requests\)$/);
  const E = []; for (let k = 0; k < 20; k++) E.push(entry({ url: 'https://assets.example/a' + k + '.js', rt: 'script', at: k, status: 0, fail: 'net::ERR_TUNNEL_CONNECTION_FAILED', blocked: 400 }));
  r = await run(E); assert.ok(!ids(r.diag).includes('h1_queue'));
});

await step('NetLogs: a private CA signing many unrelated sites is a TLS-inspection proxy', async () => {
  const leaf = (cn, issuer) => ({ cn, subject: 'CN=' + cn, sans: [cn], issuer: 'CN=' + issuer, issuerCn: issuer, notBefore: T0 - 864e5, notAfter: T0 + 864e5 * 30, selfSigned: false });
  const cert = cn => ({ leaf: leaf(cn, 'Egress Gateway Issuing CA'), chain: [], knownRoot: false, flags: ['AUTHORITY_INVALID'] });
  K.S.netlog = { certs: [cert('pypi.org'), cert('registry.npmjs.org')] };
  assert.equal(K.certFacts(cert('pypi.org'), 'pypi.org', T0).causes[0].id, 'tls_inspection');
  K.S.netlog = { certs: [cert('intranet.corp.example')] };
  assert.equal(K.certFacts(cert('intranet.corp.example'), 'intranet.corp.example', T0).causes[0].id, 'cert_private_ca', 'one internal site is a private CA, not inspection');
  K.S.netlog = null;
});

await step('NetLogs: cache-only lookups and cache-internal errors are not failed requests', async () => {
  const types = ['REQUEST_ALIVE', 'URL_REQUEST_START_JOB', 'HTTP_CACHE_OPEN_OR_CREATE_ENTRY', 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS'];
  const constants = { logEventTypes: Object.fromEntries(types.map((t, i) => [t, i])), logSourceType: { URL_REQUEST: 1 }, logEventPhase: { PHASE_BEGIN: 1, PHASE_END: 2, PHASE_NONE: 0 }, netError: { ERR_FAILED: -2, ERR_CACHE_MISS: -400 }, timeTickOffset: String(T0), logCaptureMode: 'Default' };
  const ev = (src, type, phase, t, params) => ({ source: { id: src, type: 1, start_time: String(t) }, type: types.indexOf(type), phase, time: String(t), params });
  const events = [
    ev(1, 'REQUEST_ALIVE', 1, 0), ev(1, 'URL_REQUEST_START_JOB', 1, 1, { url: 'https://site.example/font.woff2', method: 'GET' }), ev(1, 'HTTP_CACHE_OPEN_OR_CREATE_ENTRY', 2, 2, { net_error: -2 }), ev(1, 'URL_REQUEST_START_JOB', 2, 3, { net_error: -400 }), ev(1, 'REQUEST_ALIVE', 2, 4, { net_error: -400 }),
    ev(2, 'REQUEST_ALIVE', 1, 5), ev(2, 'URL_REQUEST_START_JOB', 1, 6, { url: 'https://site.example/font.woff2', method: 'GET' }), ev(2, 'HTTP_CACHE_OPEN_OR_CREATE_ENTRY', 2, 7, { net_error: -2 }), ev(2, 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS', 0, 20, { headers: ['HTTP/1.1 200 OK', 'content-type: font/woff2'] }), ev(2, 'REQUEST_ALIVE', 2, 30),
  ];
  const { har } = K.netlogToHar({ constants, events });
  assert.equal(har.log.entries.length, 1);
  assert.equal(har.log.entries[0].response.status, 200); assert.equal(har.log.entries[0].response._error || '', '');
});

console.log(`\n${passed} checks passed`);
