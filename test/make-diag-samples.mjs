// Generates the diagnostics samples:
//   sample/diagnostics.har      one or more examples of every problem the Diagnose tab explains
//   sample/compare-working.har  a capture where things work...
//   sample/compare-broken.har   ...and the same flow failing, for the Compare tab
// All hosts are example domains and all secrets are fake. Usage: node test/make-diag-samples.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const t0 = Date.parse('2026-11-02T16:00:00.000Z');
const form = o => new URLSearchParams(o).toString();

function builder(page, creator = 'HAR Analytics diagnostics sample generator') {
  const entries = [];
  let nextConn = 1000;
  function add(o) {
    const t = { blocked: 1, dns: -1, connect: -1, ssl: -1, send: 0.2, wait: 40, receive: 3, ...(o.timings || {}) };
    const time = o.time ?? ['blocked', 'dns', 'connect', 'send', 'wait', 'receive'].reduce((a, k) => a + Math.max(0, t[k]), 0);
    const u = new URL(o.url), status = o.status ?? 200, pending = o.pending;
    const body = o.json !== undefined ? JSON.stringify(o.json) : (o.body ?? '');
    const mime = o.mime || (o.json !== undefined ? 'application/json' : '');
    const resHeaders = status === 0 ? [] : [['date', new Date(t0 + o.at + time).toUTCString()], ...(mime ? [['content-type', mime]] : []), ...(o.loc ? [['location', o.loc]] : []), ...(o.res || [])];
    const reqHeaders = [['user-agent', o.ua || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36'], ['accept', o.accept || '*/*'], ['accept-language', o.lang || 'en-US,en;q=0.9'], ...(o.req || [])];
    let postData;
    if (o.form) postData = { mimeType: 'application/x-www-form-urlencoded', text: form(o.form) };
    if (o.postJson) postData = { mimeType: o.postType || 'application/json', text: JSON.stringify(o.postJson) };
    if (o.postText != null) postData = { mimeType: o.postType || 'text/plain', text: o.postText };
    if (postData && !reqHeaders.some(h => h[0] === 'content-type')) reqHeaders.push(['content-type', postData.mimeType]);
    const size = o.size ?? body.length;
    const e = {
      startedDateTime: new Date(t0 + o.at).toISOString(), time: pending ? 0 : time, _resourceType: o.type || 'fetch', pageref: 'page_1',
      request: { method: o.method || (postData ? 'POST' : 'GET'), url: o.url, httpVersion: o.http || 'h2', headers: reqHeaders.map(([name, value]) => ({ name, value })), queryString: [...u.searchParams].map(([name, value]) => ({ name, value })), cookies: [], headersSize: -1, bodySize: postData ? postData.text.length : 0, ...(postData ? { postData } : {}) },
      response: { status, statusText: o.statusText ?? (status === 200 ? 'OK' : ''), httpVersion: status === 0 ? '' : (o.http || 'h2'), headers: resHeaders.map(([name, value]) => ({ name, value })), cookies: [], content: { size, mimeType: mime, ...(body ? { text: body } : {}) }, redirectURL: o.loc || '', headersSize: -1, bodySize: o.transfer ?? size, _transferSize: status === 0 ? 0 : (o.transfer ?? size) + 300, ...(o.error ? { _error: o.error } : {}), ...(o.sw ? { _fetchedViaServiceWorker: true } : {}) },
      cache: {}, timings: pending ? { blocked: 1, dns: -1, connect: -1, ssl: -1, send: 0, wait: -1, receive: -1 } : t, serverIPAddress: status === 0 ? '' : (o.ip || '203.0.113.20'), connection: String(o.conn || nextConn++),
      ...(o.initiator ? { _initiator: o.initiator } : {}), ...(o.priority ? { _priority: o.priority } : {}), ...(o.ws ? { _webSocketMessages: o.ws } : {}),
    };
    entries.push(e);
    return e;
  }
  function save(file, pageTimings = { onContentLoad: 2600, onLoad: 4100 }) {
    entries.sort((a, b) => Date.parse(a.startedDateTime) - Date.parse(b.startedDateTime));
    const har = { log: { version: '1.2', creator: { name: creator, version: '1.0' }, pages: [{ startedDateTime: new Date(t0).toISOString(), id: 'page_1', title: page, pageTimings }], entries } };
    writeFileSync(join(here, '..', 'sample', file), JSON.stringify(har, null, 2) + '\n');
    console.log(`wrote ${entries.length} entries to sample/${file}`);
  }
  return { add, save };
}

/* =================== diagnostics.har =================== */
{
  const WWW = 'https://www.example-shop.com', API = 'https://api.example-shop.net', ST = 'https://static.example-shop.com', IMG = 'https://images.example-shop.com';
  const ORIGIN = [['origin', WWW]], CORS = [['sec-fetch-mode', 'cors'], ['sec-fetch-site', 'cross-site'], ['origin', WWW]];
  const { add, save } = builder(WWW + '/');
  const PARSER = { type: 'parser', url: WWW + '/' };

  // Page: slow TTFB, cacheable HTML, missing security headers, version disclosure
  add({ at: 0, type: 'document', url: WWW + '/', mime: 'text/html', body: '<!doctype html><html><head><title>Example Shop</title></head><body></body></html>', timings: { dns: 20, connect: 30, ssl: 25, wait: 2100, receive: 30 }, res: [['cache-control', 'public, max-age=3600'], ['server', 'nginx/1.18.0'], ['x-powered-by', 'PHP/7.4.3'], ['set-cookie', 'shop_session=sess-abc123def456; Path=/; Secure; SameSite=Lax'], ['set-cookie', 'auth_token=tok-xyz789; Path=/; SameSite=None']], req: [['sec-fetch-mode', 'navigate']] });
  // Render-blocking CSS/JS and a 5-level initiator chain
  add({ at: 2250, type: 'stylesheet', url: ST + '/css/site.css', mime: 'text/css', size: 90000, initiator: PARSER, priority: 'VeryHigh', timings: { wait: 900, receive: 1400 }, res: [['cache-control', 'public, max-age=86400'], ['x-cache', 'MISS']] });
  add({ at: 2260, type: 'script', url: ST + '/js/app.js', mime: 'application/javascript', size: 240000, initiator: PARSER, priority: 'High', timings: { wait: 700, receive: 1900 }, res: [['cache-control', 'public, max-age=31536000, immutable'], ['x-cache', 'MISS'], ['set-cookie', 'cdn_id=1; Path=/']] });
  add({ at: 4900, type: 'script', url: ST + '/js/loader.7c1e9a2b.js', mime: 'application/javascript', size: 30000, initiator: { type: 'script', stack: { callFrames: [{ url: ST + '/js/app.js', lineNumber: 10 }] } }, timings: { wait: 120 }, res: [['cache-control', 'public, max-age=300'], ['x-cache', 'MISS'], ['set-cookie', 'cdn_id=1; Path=/']] });
  add({ at: 5100, type: 'script', url: ST + '/js/widgets.9d8e7f6a.js', mime: 'application/javascript', size: 50000, initiator: { type: 'script', stack: { callFrames: [{ url: ST + '/js/loader.7c1e9a2b.js', lineNumber: 3 }] } }, timings: { wait: 150 }, res: [['cache-control', 'public, max-age=300'], ['x-cache', 'MISS'], ['set-cookie', 'cdn_id=1; Path=/']] });
  add({ at: 5350, url: ST + '/data/widgets.json', json: { widgets: [] }, initiator: { type: 'script', stack: { callFrames: [{ url: ST + '/js/widgets.9d8e7f6a.js', lineNumber: 7 }] } }, res: [['cache-control', 'private, no-store'], ['x-cache', 'BYPASS']] });
  add({ at: 5500, type: 'stylesheet', url: ST + '/css/theme.5a4b3c2d.css', mime: 'text/css', size: 12000, timings: { wait: 60 }, res: [['cache-control', 'public, max-age=600'], ['x-cache', 'MISS']] });
  // HTTP/1.1 image host with queueing, two big images, revalidations, a service-worker response
  for (let i = 0; i < 12; i++) add({ at: 2400 + i * 10, type: 'image', http: 'http/1.1', url: IMG + `/p/${100 + i}.webp`, mime: 'image/webp', size: i < 2 ? 420000 + i * 1000 : 30000, timings: { blocked: i < 6 ? 2 : 300 + i * 40, wait: 80, receive: 60 }, res: [['cache-control', 'public, max-age=86400']] });
  for (let i = 0; i < 10; i++) add({ at: 2500 + i * 7, type: 'image', url: IMG + `/icons/${i}.svg`, status: 304, statusText: 'Not Modified', http: 'http/1.1', timings: { blocked: 200, wait: 30 } });
  add({ at: 3000, url: WWW + '/api/menu', json: { items: [] }, sw: true });
  // Fonts host over HTTP/2 that keeps opening new connections
  for (let i = 0; i < 5; i++) add({ at: 2600 + i * 20, type: 'font', url: `https://fonts.example-shop.com/f${i}.woff2`, mime: 'font/woff2', size: 20000, req: CORS, res: [['access-control-allow-origin', '*'], ['cache-control', 'public, max-age=31536000']], timings: { dns: 5, connect: 40, ssl: 30, wait: 30 } });

  // ---- CORS ----
  add({ at: 6000, method: 'OPTIONS', type: 'preflight', url: API + '/v1/cart/items', req: [...CORS, ['access-control-request-method', 'PUT'], ['access-control-request-headers', 'authorization, content-type, x-request-id']], status: 204, statusText: 'No Content', res: [['access-control-allow-origin', WWW], ['access-control-allow-methods', 'GET, POST'], ['access-control-allow-headers', 'content-type, *']] });
  add({ at: 6100, url: API + '/v1/prices', req: [...CORS, ['cookie', 'shop_session=sess-abc123def456']], json: { prices: [] }, res: [['access-control-allow-origin', '*']] });
  add({ at: 6200, url: 'https://cdn-api.example-shop.net/v1/catalog', req: CORS, json: { items: [] }, res: [['access-control-allow-origin', 'https://staging.example-shop.com'], ['age', '3200'], ['x-cache', 'Hit from cloudfront'], ['cache-control', 'public, max-age=86400']] });
  add({ at: 6300, url: API + '/v1/reviews', req: CORS, json: { reviews: [] }, res: [['access-control-allow-origin', WWW], ['access-control-allow-origin', WWW], ['vary', 'Origin']] });
  add({ at: 6400, method: 'OPTIONS', type: 'preflight', http: 'http/1.1', url: 'http://192.168.1.20:8080/status', req: [...CORS, ['access-control-request-method', 'GET'], ['access-control-request-private-network', 'true']], status: 204, statusText: 'No Content', res: [['access-control-allow-origin', WWW]] });
  add({ at: 6500, url: API + '/v1/recommendations', req: CORS, status: 500, statusText: 'Internal Server Error', json: { error: 'internal' } });

  // ---- Network & TLS ----
  add({ at: 7000, type: 'script', url: 'https://legacy.example-partner.com/widget.js', status: 0, error: 'net::ERR_CERT_DATE_INVALID' });
  add({ at: 7050, url: 'https://internal.example-corp.net/api/flags', status: 0, error: 'net::ERR_CERT_AUTHORITY_INVALID' });
  add({ at: 7100, type: 'script', url: 'https://analytics.example-tracker.com/a.js', status: 0, error: 'net::ERR_BLOCKED_BY_CLIENT' });
  add({ at: 7150, type: 'image', url: 'https://analytics.example-tracker.com/pixel.gif?e=view', status: 0, error: 'net::ERR_BLOCKED_BY_CLIENT' });
  add({ at: 7200, type: 'image', url: IMG + '/p/cancelled.webp', status: 0, error: 'net::ERR_ABORTED' });
  add({ at: 7250, type: 'media', url: 'https://video.example-media.com/intro.m3u8', status: 0, error: 'net::ERR_QUIC_PROTOCOL_ERROR' });
  // A network outage: four unrelated hosts fail together
  add({ at: 120000, url: API + '/v1/heartbeat', status: 0, error: 'net::ERR_INTERNET_DISCONNECTED' });
  add({ at: 120400, type: 'image', url: 'https://cdn.example-ads.com/banner.png', status: 0, error: 'net::ERR_NAME_NOT_RESOLVED' });
  add({ at: 121000, url: 'https://chat.example-support.com/poll', status: 0, error: 'net::ERR_INTERNET_DISCONNECTED' });
  add({ at: 122500, url: WWW + '/api/session/ping', status: 0, error: 'net::ERR_NETWORK_CHANGED' });

  // ---- Server & gateway errors ----
  add({ at: 8000, url: WWW + '/api/checkout', postJson: { cart: 1 }, status: 502, statusText: 'Bad Gateway', mime: 'text/html', body: '<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx</center></body></html>', res: [['server', 'nginx']] });
  add({ at: 8100, url: API + '/v1/report', req: ORIGIN, status: 504, statusText: 'Gateway Timeout', mime: 'text/html', body: '<html><head><title>504 Gateway Time-out</title></head><body><center><h1>504 Gateway Time-out</h1></center></body></html>', res: [['server', 'awselb/2.0'], ['access-control-allow-origin', WWW], ['vary', 'Origin']], time: 60080, timings: { wait: 60075 } });
  add({ at: 8200, url: API + '/v1/export', req: ORIGIN, status: 504, statusText: 'Gateway Timeout', mime: 'text/html', body: '<html><head><title>504 Gateway Time-out</title></head><body><center><h1>504 Gateway Time-out</h1></center></body></html>', res: [['server', 'awselb/2.0'], ['access-control-allow-origin', WWW], ['vary', 'Origin']], time: 60010, timings: { wait: 60005 } });
  add({ at: 8300, type: 'document', url: 'https://search.example-shop.com/search?q=lamp', status: 524, statusText: '', mime: 'text/html', body: '<!DOCTYPE html><html><head><title>search.example-shop.com | 524: A timeout occurred</title></head><body>Error code 524</body></html>', res: [['server', 'cloudflare'], ['cf-ray', '8d2f1a2b3c4d5e6f-DFW']], time: 100150, timings: { wait: 100140 } });
  add({ at: 8400, url: API + '/v1/orders/12345', req: ORIGIN, status: 500, statusText: 'Internal Server Error', json: { timestamp: '2026-11-02T16:00:08Z', status: 500, error: 'Internal Server Error', trace: 'java.lang.NullPointerException: Cannot invoke "com.example.shop.Order.getCustomer()" because "order" is null\n\tat com.example.shop.OrderService.load(OrderService.java:88)\n\tat com.example.shop.OrderController.get(OrderController.java:41)' }, res: [['access-control-allow-origin', WWW], ['vary', 'Origin']] });
  add({ at: 8500, url: API + '/v1/inventory', req: ORIGIN, status: 503, statusText: 'Service Unavailable', mime: 'text/plain', body: 'upstream connect error or disconnect/reset before headers. reset reason: connection failure', res: [['server', 'envoy'], ['access-control-allow-origin', WWW], ['vary', 'Origin']] });

  // ---- Rate limiting & retries ----
  add({ at: 9000, url: API + '/v1/search?q=lamp', req: ORIGIN, status: 429, statusText: 'Too Many Requests', json: { message: 'Rate limit exceeded' }, res: [['retry-after', '30'], ['x-ratelimit-limit', '100'], ['x-ratelimit-remaining', '0'], ['x-ratelimit-reset', '1793635230'], ['access-control-allow-origin', WWW], ['vary', 'Origin']] });
  add({ at: 11000, url: API + '/v1/search?q=lamp', req: ORIGIN, status: 429, statusText: 'Too Many Requests', json: { message: 'Rate limit exceeded' }, res: [['retry-after', '28'], ['access-control-allow-origin', WWW], ['vary', 'Origin']] });
  for (let i = 0; i < 5; i++) add({ at: 12000 + i * 1000, url: API + '/v1/stock', req: ORIGIN, status: 503, statusText: 'Service Unavailable', json: { error: 'unavailable' }, res: [['access-control-allow-origin', WWW], ['vary', 'Origin']] });
  for (let i = 0; i < 22; i++) add({ at: 20000 + i * 1000, url: WWW + '/api/notifications/count', json: { count: 0 } });

  // ---- Hidden failures & API errors ----
  add({ at: 50000, url: WWW + '/graphql', postJson: { operationName: 'GetCart', query: 'query GetCart { cart { id discountCode } }' }, json: { data: null, errors: [{ message: 'Cannot query field "discountCode" on type "Cart".', extensions: { code: 'GRAPHQL_VALIDATION_FAILED' } }] } });
  add({ at: 50200, url: WWW + '/graphql', postJson: { operationName: 'GetUser', extensions: { persistedQuery: { version: 1, sha256Hash: 'ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38' } } }, json: { errors: [{ message: 'PersistedQueryNotFound', extensions: { code: 'PERSISTED_QUERY_NOT_FOUND' } }] } });
  add({ at: 50300, url: WWW + '/graphql', postJson: { operationName: 'GetUser', query: 'query GetUser { me { id } }', extensions: { persistedQuery: { version: 1, sha256Hash: 'ecf4' } } }, json: { data: { me: { id: 1 } } } });
  add({ at: 50400, url: WWW + '/api/payments', postJson: { amount: 42 }, json: { success: false, message: 'Payment declined: card expired' } });
  add({ at: 50500, url: WWW + '/api/v2/wishlist', accept: 'application/json, text/plain, */*', mime: 'text/html', body: '<!doctype html><html><head><title>Example Shop</title></head><body><div id="root"></div></body></html>' });
  add({ at: 50600, url: WWW + '/api/products/undefined/reviews', status: 404, statusText: 'Not Found', json: { error: 'not_found', message: 'Product not found' } });
  add({ at: 50700, url: WWW + '/api/newsletter', postText: JSON.stringify({ email: 'alex@example.com' }), postType: 'text/plain;charset=UTF-8', status: 415, statusText: 'Unsupported Media Type', json: { message: 'Unsupported Media Type' } });
  add({ at: 50800, url: WWW + '/api/address', postJson: { zip: 'abc' }, status: 422, statusText: 'Unprocessable Entity', json: { message: 'Validation failed', errors: [{ field: 'zip', message: 'must be 5 digits' }, { field: 'street', message: 'is required' }] } });
  add({ at: 50900, url: WWW + '/api/catalog/full', mime: 'application/json', body: '{"items":[{"id":1,"name":"Lamp"},{"id":2,"na', size: 44, res: [['content-length', '182233']] });
  add({ at: 51000, url: WWW + '/grpc/shop.Cart/Get', postText: 'AAAAAA==', postType: 'application/grpc-web+proto', mime: 'application/grpc-web+proto', res: [['grpc-status', '7'], ['grpc-message', 'caller%20lacks%20cart.read']] });

  // ---- Redirects ----
  const LOOP = 'shop2.example-shop.com';
  for (let i = 0; i < 6; i++) { const https = i % 2 === 1; add({ at: 52000 + i * 80, type: 'document', url: (https ? 'https://' : 'http://') + LOOP + '/', status: 301, statusText: 'Moved Permanently', loc: (https ? 'http://' : 'https://') + LOOP + '/', http: 'http/1.1', res: [['server', 'nginx']] }); }
  add({ at: 53000, type: 'document', url: WWW + '/account', status: 302, statusText: 'Found', loc: 'http://www.example-shop.com/account/' });
  add({ at: 53100, type: 'document', http: 'http/1.1', url: 'http://www.example-shop.com/account/', mime: 'text/html', body: '<title>Account</title>' });
  add({ at: 53500, type: 'document', url: WWW + '/checkout/submit', form: { order: '77' }, status: 301, statusText: 'Moved Permanently', loc: WWW + '/checkout/submit/' });
  add({ at: 53600, type: 'document', url: WWW + '/checkout/submit/', status: 405, statusText: 'Method Not Allowed', mime: 'text/html', body: '<title>405</title>', res: [['allow', 'POST']] });

  // ---- WebSockets & streaming ----
  add({ at: 54000, type: 'websocket', url: 'wss://live.example-shop.com/socket', status: 101, statusText: 'Switching Protocols', time: 61200, http: 'http/1.1', ws: [{ type: 'send', time: (t0 + 54100) / 1000, opcode: 1, data: '{"sub":"prices"}' }, { type: 'receive', time: (t0 + 54200) / 1000, opcode: 1, data: '{"ok":true}' }] });
  for (let i = 0; i < 3; i++) add({ at: 55000 + i * 3000, type: 'websocket', url: 'wss://chat.example-shop.com/ws', status: 200, http: 'http/1.1', mime: 'text/html', body: '<title>Chat</title>', req: [['upgrade', 'websocket'], ['connection', 'Upgrade'], ['origin', WWW]] });
  add({ at: 60000, url: WWW + '/events/stream', accept: 'text/event-stream', mime: 'text/event-stream', body: 'data: {"hello":1}\n\n', time: 15000, timings: { wait: 50, receive: 14900 }, res: [['server', 'nginx'], ['content-encoding', 'gzip']] });

  // ---- Hangs ----
  add({ at: 70000, url: WWW + '/api/recommendations/slow', pending: true, status: 0 });
  add({ at: 70500, url: WWW + '/api/reports/annual', json: { ok: true }, time: 42000, timings: { wait: 41500, receive: 400 } });
  add({ at: 71000, type: 'other', url: WWW + '/downloads/catalog.pdf', mime: 'application/pdf', size: 1500000, timings: { wait: 200, receive: 25000 } });

  // ---- Caching ----
  add({ at: 72000, url: WWW + '/api/me', json: { id: 1 }, res: [['x-cache', 'HIT'], ['age', '120'], ['cache-control', 'public, max-age=300'], ['set-cookie', 'shop_session=sess-other-user-999; Path=/; Secure; HttpOnly']] });

  // ---- Security ----
  add({ at: 73000, url: API + '/v1/export?format=csv&access_token=eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl', req: ORIGIN, json: { ok: true }, res: [['access-control-allow-origin', WWW], ['vary', 'Origin']] });
  add({ at: 73100, type: 'document', url: WWW + '/legacy/login?user=alex&password=hunter2-sample', mime: 'text/html', body: '<title>Login</title>' });
  add({ at: 73200, url: WWW + '/api/subscribe?email=alex%40example.com', json: { ok: true } });
  add({ at: 73300, type: 'document', http: 'http/1.1', url: 'http://legacy.example-shop.com/login', form: { user: 'alex', password: 'hunter2-sample' }, req: [['cookie', 'legacy_sid=abc12345']], mime: 'text/html', body: '<title>Welcome</title>' });
  add({ at: 73400, url: WWW + '/csp-report', postJson: { 'csp-report': { 'document-uri': WWW + '/', 'violated-directive': 'script-src-elem', 'effective-directive': 'script-src-elem', 'blocked-uri': 'https://cdn.example-widgets.com/widget.js', 'original-policy': "script-src 'self' https://static.example-shop.com" } }, postType: 'application/csp-report', status: 204, statusText: 'No Content' });
  add({ at: 74000, url: WWW + '/api/last', json: { ok: true } });
  save('diagnostics.har');
}

/* =================== compare-working.har / compare-broken.har =================== */
for (const broken of [false, true]) {
  const APP = 'https://app.example.com', API = 'https://api.example.com';
  const { add, save } = builder(APP + '/', 'HAR Analytics compare sample generator');
  const ua = broken ? 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:132.0) Gecko/20100101 Firefox/132.0' : undefined;
  const apiIp = broken ? '198.51.100.99' : '203.0.113.10';
  const TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln';
  add({ at: 0, ua, type: 'document', url: APP + '/', mime: 'text/html', body: '<title>App</title>' });
  add({ at: 300, ua, type: 'script', url: APP + '/static/app.3f9a1c2b.js', mime: 'application/javascript', size: 120000, res: [['cache-control', 'public, max-age=31536000, immutable']] });
  add({ at: 600, ua, url: API + '/api/config', ip: apiIp, req: [['origin', APP]], json: { env: 'prod' }, timings: { wait: broken ? 2600 : 90 }, res: [['access-control-allow-origin', APP]] });
  if (!broken) add({ at: 900, url: API + '/api/token', ip: apiIp, req: [['origin', APP]], form: { grant_type: 'client_credentials', client_id: 'web' }, json: { access_token: TOKEN, expires_in: 3600 }, res: [['access-control-allow-origin', APP]] });
  const auth = broken ? [] : [['authorization', 'Bearer ' + TOKEN]];
  add({ at: broken ? 3400 : 1200, ua, url: API + '/api/orders', ip: apiIp, req: [['origin', APP], ...auth], ...(broken ? { status: 401, statusText: 'Unauthorized', json: { error: 'missing token' }, res: [['access-control-allow-origin', APP], ['www-authenticate', 'Bearer']] } : { json: { orders: [42] }, res: [['access-control-allow-origin', APP]] }) });
  add({ at: broken ? 3500 : 1300, ua, url: API + `/api/orders/${broken ? 57 : 42}`, ip: apiIp, req: [['origin', APP], ...auth], ...(broken ? { status: 401, statusText: 'Unauthorized', json: { error: 'missing token' }, res: [['access-control-allow-origin', APP]] } : { json: { id: 42 }, res: [['access-control-allow-origin', APP]] }) });
  if (broken) add({ at: 3600, ua, url: API + '/api/feature-flags', ip: apiIp, req: [['origin', APP]], status: 500, statusText: 'Internal Server Error', json: { error: 'flags service down' }, res: [['access-control-allow-origin', APP]] });
  save(broken ? 'compare-broken.har' : 'compare-working.har', { onContentLoad: 400, onLoad: broken ? 3700 : 1400 });
}
