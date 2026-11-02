// Generates sample/sample.har: a synthetic capture that exercises every finding the analyzer reports.
// Usage: node test/make-sample.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const t0 = Date.parse('2026-11-02T15:00:00.000Z');
const PAGE = 'https://www.shop.example.com/home';
const ORIGIN = 'https://www.shop.example.com';
const PNG_1PX = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

const H = obj => Object.entries(obj).map(([name, value]) => ({ name, value: String(value) }));
const entries = [];

function add(o) {
  const t = { blocked: 2, dns: -1, connect: -1, ssl: -1, send: 0.3, wait: 40, receive: 5, ...o.timings };
  const time = ['blocked', 'dns', 'connect', 'send', 'wait', 'receive'].reduce((a, k) => a + Math.max(0, t[k]), 0);
  const u = new URL(o.url);
  const body = o.body ?? '';
  const size = o.size ?? body.length;
  entries.push({
    pageref: 'page_1',
    startedDateTime: new Date(t0 + o.at).toISOString(),
    time,
    _resourceType: o.type,
    request: {
      method: o.method || 'GET', url: o.url, httpVersion: 'h2',
      headers: H({ ':authority': u.host, accept: '*/*', 'user-agent': 'Mozilla/5.0 (sample)', ...(o.reqHeaders || {}) }),
      queryString: [...u.searchParams].map(([name, value]) => ({ name, value })),
      cookies: o.reqCookies || [],
      headersSize: -1, bodySize: o.postData ? o.postData.text.length : 0,
      ...(o.postData ? { postData: o.postData } : {}),
    },
    response: {
      status: o.status ?? 200, statusText: o.statusText ?? 'OK', httpVersion: o.status === 0 ? '' : 'h2',
      headers: H(o.status === 0 ? {} : { date: 'Mon, 02 Nov 2026 15:00:00 GMT', ...(o.mime ? { 'content-type': o.mime } : {}), ...(o.resHeaders || {}) }),
      cookies: o.resCookies || [],
      content: { size, mimeType: o.mime || '', ...(o.b64 ? { text: o.b64, encoding: 'base64' } : body ? { text: body } : {}) },
      redirectURL: o.redirect || '', headersSize: -1, bodySize: o.transfer ?? size, _transferSize: o.status === 0 ? 0 : (o.transfer ?? size) + 250,
      ...(o.error ? { _error: o.error } : {}),
    },
    cache: {}, timings: t, serverIPAddress: o.status === 0 ? '' : (o.ip || '203.0.113.10'), connection: String(o.conn || 1000),
  });
}

// 1. Redirect chain: apex -> www -> /home
add({ at: 0, url: 'http://shop.example.com/', type: 'document', status: 301, statusText: 'Moved Permanently', redirect: 'https://shop.example.com/', resHeaders: { location: 'https://shop.example.com/' }, timings: { dns: 35, connect: 40, wait: 30 } });
add({ at: 120, url: 'https://shop.example.com/', type: 'document', status: 301, statusText: 'Moved Permanently', redirect: 'https://www.shop.example.com/', resHeaders: { location: 'https://www.shop.example.com/' }, timings: { dns: 2, connect: 90, ssl: 60, wait: 35 } });
add({ at: 260, url: 'https://www.shop.example.com/', type: 'document', status: 302, statusText: 'Found', resHeaders: { location: '/home' }, timings: { dns: 20, connect: 80, ssl: 55, wait: 40 } });
add({ at: 400, url: PAGE, type: 'document', mime: 'text/html', body: '<!doctype html><html><head><title>Example Shop</title></head><body><h1>Welcome</h1></body></html>', resHeaders: { 'content-encoding': 'br', 'cache-control': 'no-cache' }, timings: { wait: 180, receive: 20 } });

// 2. Uncompressed stylesheet without caching headers
add({ at: 640, url: ORIGIN + '/static/app.css', type: 'stylesheet', mime: 'text/css', size: 48211, transfer: 48211, body: 'body{font-family:sans-serif}\n'.repeat(1700), timings: { wait: 60, receive: 90 } });
// 3. Large but compressed and cached JS bundle
add({ at: 650, url: ORIGIN + '/static/vendor.4f2a.js', type: 'script', mime: 'application/javascript', size: 1650000, transfer: 410000, resHeaders: { 'content-encoding': 'br', 'cache-control': 'public, max-age=31536000, immutable' }, timings: { wait: 70, receive: 480 } });
// 4. Mixed content image (with body so the image preview works)
add({ at: 700, url: 'http://cdn.example.net/img/logo.png', type: 'image', mime: 'image/png', b64: PNG_1PX, size: 68, resHeaders: { 'cache-control': 'max-age=86400' }, ip: '198.51.100.7', timings: { dns: 45, connect: 38, wait: 25 } });
// 5. Font with slow DNS and slow TLS
add({ at: 720, url: 'https://fonts.example-cdn.com/inter-var.woff2', type: 'font', mime: 'font/woff2', size: 98000, resHeaders: { 'cache-control': 'max-age=31536000', 'access-control-allow-origin': '*' }, reqHeaders: { origin: ORIGIN }, ip: '198.51.100.20', timings: { dns: 340, connect: 1420, ssl: 820, wait: 60, receive: 70 } });
// 6. Login POST: JSON body with password; insecure cookie; token in response
add({
  at: 900, url: ORIGIN + '/api/login', method: 'POST', type: 'fetch', mime: 'application/json',
  reqHeaders: { 'content-type': 'application/json', origin: ORIGIN },
  postData: { mimeType: 'application/json', text: JSON.stringify({ username: 'alex@example.com', password: 'hunter2' }) },
  body: JSON.stringify({ ok: true, user: { id: 42, name: 'Alex' }, access_token: 'eyJhbGciOiJIUzI1NiJ9.sample.signature', expires_in: 3600 }),
  resHeaders: { 'set-cookie': 'session=s3cr3tSessionValue; Path=/; HttpOnly; SameSite=Lax', 'cache-control': 'no-store' },
  resCookies: [{ name: 'session', value: 's3cr3tSessionValue', path: '/', httpOnly: true, secure: false }],
  timings: { wait: 220 },
});
const AUTH = { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.sample.signature', cookie: 'session=s3cr3tSessionValue' };
const COOKIES = [{ name: 'session', value: 's3cr3tSessionValue' }];
// 7. 401 Unauthorized
add({ at: 1150, url: ORIGIN + '/api/account/settings', type: 'fetch', status: 401, statusText: 'Unauthorized', mime: 'application/json', body: '{"error":"token_expired","message":"The access token expired"}', resHeaders: { 'www-authenticate': 'Bearer error="invalid_token"' }, timings: { wait: 35 } });
// 8. 500 with slow TTFB and slow total
add({ at: 1200, url: ORIGIN + '/api/orders?page=1&limit=50', type: 'fetch', status: 500, statusText: 'Internal Server Error', mime: 'application/json', reqHeaders: AUTH, reqCookies: COOKIES, body: '{"error":"internal","trace_id":"9f1c2b7e"}', timings: { wait: 3480, receive: 4 } });
// 9. 504 from the gateway
add({ at: 1250, url: ORIGIN + '/api/recommendations', type: 'fetch', status: 504, statusText: 'Gateway Timeout', mime: 'text/html', reqHeaders: AUTH, body: '<html><body><h1>504 Gateway Time-out</h1></body></html>', timings: { wait: 1520 } });
// 10. Failed CORS preflight
add({ at: 1300, url: 'https://api.partner.example/v1/inventory', method: 'OPTIONS', type: 'preflight', status: 403, statusText: 'Forbidden', reqHeaders: { origin: ORIGIN, 'access-control-request-method': 'PUT', 'access-control-request-headers': 'authorization,content-type' }, ip: '192.0.2.44', timings: { dns: 30, connect: 70, ssl: 50, wait: 45 } });
// 11. Cross-origin response missing Access-Control-Allow-Origin
add({ at: 1320, url: 'https://api.partner.example/v1/stores?api_key=AKIA-SAMPLE-KEY-123', type: 'fetch', mime: 'application/json', reqHeaders: { origin: ORIGIN }, body: '[{"id":1,"city":"Austin"}]', resHeaders: { 'content-encoding': 'gzip' }, ip: '192.0.2.44', timings: { wait: 95 } });
// 12. DNS failure: no response at all
add({ at: 1350, url: 'https://metrics.tracker-example.org/collect.js', type: 'script', status: 0, statusText: '', error: 'net::ERR_NAME_NOT_RESOLVED', timings: { dns: 410, wait: 0, receive: 0, send: 0 } });
// 13. Connection refused
add({ at: 1360, url: 'https://ws.shop.example.com:8443/live', type: 'fetch', status: 0, statusText: '', error: 'net::ERR_CONNECTION_REFUSED', timings: { dns: 12, connect: 3, wait: 0, receive: 0, send: 0 } });
// 14. Duplicate config fetches, the third one queued behind others
for (const [i, at] of [1400, 1460, 1520].entries()) {
  add({ at, url: ORIGIN + '/api/config', type: 'xhr', mime: 'application/json', body: '{"features":{"newCheckout":true},"region":"us"}', resHeaders: { 'content-encoding': 'gzip', 'cache-control': 'no-cache' }, timings: { blocked: i === 2 ? 880 : 3, wait: 50 } });
}
// 15. Missing favicon
add({ at: 1600, url: ORIGIN + '/favicon.ico', type: 'other', status: 404, statusText: 'Not Found', mime: 'text/html', body: '<h1>Not Found</h1>', timings: { wait: 22 } });
// 16. A batch of healthy product images
for (let i = 1; i <= 12; i++) {
  add({ at: 900 + i * 25, url: `https://img.example-cdn.com/products/${1000 + i}.webp?w=400`, type: 'image', mime: 'image/webp', size: 18000 + i * 900, resHeaders: { 'cache-control': 'public, max-age=604800' }, ip: '198.51.100.30', conn: 2000, timings: { wait: 30 + (i % 4) * 15, receive: 12 + i } });
}
// 17. Uncached script
add({ at: 1700, url: ORIGIN + '/static/analytics-loader.js', type: 'script', mime: 'text/javascript', size: 1800, body: '/* loader */'.padEnd(1800, ' '), resHeaders: { 'content-encoding': 'gzip' }, timings: { wait: 40 } });

entries.sort((a, b) => Date.parse(a.startedDateTime) - Date.parse(b.startedDateTime));

const har = {
  log: {
    version: '1.2',
    creator: { name: 'HAR Analyzer sample generator', version: '1.0' },
    pages: [{ startedDateTime: new Date(t0).toISOString(), id: 'page_1', title: PAGE, pageTimings: { onContentLoad: 1180, onLoad: 2350 } }],
    entries,
  },
};
const out = join(here, '..', 'sample', 'sample.har');
writeFileSync(out, JSON.stringify(har, null, 2) + '\n');
console.log(`wrote ${entries.length} entries to ${out}`);
