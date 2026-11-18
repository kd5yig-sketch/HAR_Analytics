const pos = n => (typeof n === 'number' && n > 0 ? n : 0);
function fmtBytes(n) {
  if (n == null || n < 0 || isNaN(n)) return '—';
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
}
function fmtMs(ms) {
  if (ms == null || ms < 0 || isNaN(ms)) return '—';
  if (ms === 0) return '0 ms';
  if (ms < 1) return ms.toFixed(2) + ' ms';
  if (ms < 1000) return Math.round(ms) + ' ms';
  return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + ' s';
}
function hdr(list, name) {
  if (!Array.isArray(list)) return '';
  name = name.toLowerCase();
  const f = list.find(x => x && String(x.name).toLowerCase() === name);
  return f ? String(f.value ?? '') : '';
}
function hdrAll(list, name) {
  if (!Array.isArray(list)) return [];
  name = name.toLowerCase();
  return list.filter(x => x && String(x.name).toLowerCase() === name).map(x => String(x.value ?? ''));
}
/* ---------- state ---------- */
const S = {
  fileName: '', har: null, pages: [], entries: [], findings: [], filtered: [],
  sort: { key: 'start', dir: 1 }, types: new Set(), selected: null, view: 'overview', dtab: 'headers'
};

/* ---------- classification ---------- */
const TYPE_LABEL = { doc: 'Document', xhr: 'XHR / Fetch', js: 'Script', css: 'Stylesheet', img: 'Image', font: 'Font', media: 'Media', ws: 'WebSocket', other: 'Other' };
const RT_MAP = { document: 'doc', script: 'js', stylesheet: 'css', image: 'img', font: 'font', xhr: 'xhr', fetch: 'xhr', preflight: 'xhr', eventsource: 'xhr', media: 'media', websocket: 'ws' };
function classify(e, mime, u) {
  const rt = String(e._resourceType || '').toLowerCase();
  if (RT_MAP[rt]) return RT_MAP[rt];
  if (rt) return 'other';
  const m = mime.toLowerCase();
  if (m.includes('html')) return 'doc';
  if (m.includes('javascript') || m.includes('ecmascript')) return 'js';
  if (m.includes('css')) return 'css';
  if (m.startsWith('image/')) return 'img';
  if (m.startsWith('font/') || m.includes('woff') || m.includes('opentype') || m.includes('truetype')) return 'font';
  if (m.startsWith('audio/') || m.startsWith('video/')) return 'media';
  if (m.includes('json') || m.includes('xml') || m.includes('grpc') || m.includes('protobuf')) return 'xhr';
  const ext = u ? (u.pathname.match(/\.([a-z0-9]+)$/i) || [])[1] : '';
  if (ext) {
    const x = ext.toLowerCase();
    if (/^(js|mjs)$/.test(x)) return 'js';
    if (x === 'css') return 'css';
    if (/^(png|jpe?g|gif|webp|avif|svg|ico|bmp)$/.test(x)) return 'img';
    if (/^(woff2?|ttf|otf|eot)$/.test(x)) return 'font';
    if (/^(mp4|webm|mp3|m4a|ogg|wav|m3u8|ts)$/.test(x)) return 'media';
    if (/^(html?)$/.test(x)) return 'doc';
  }
  if (u && /^wss?:$/.test(u.protocol)) return 'ws';
  return 'other';
}
const isFailed = e => e.status === 0;
function statusClass(e) {
  if (isFailed(e) || e.status >= 500) return 'err';
  if (e.status >= 400) return 'warn';
  return 'ok';
}
const isTextMime = m => /^text\/|json|javascript|ecmascript|xml|svg|x-www-form-urlencoded|graphql/i.test(m);

/* ---------- loading & normalising ---------- */
function normalize(har) {
  const log = har && har.log;
  if (!log || !Array.isArray(log.entries)) throw new Error('This file does not look like a HAR: it has no "log.entries" list.');
  const pages = Array.isArray(log.pages) ? log.pages : [];
  const starts = log.entries.map(e => Date.parse(e && e.startedDateTime));
  let base = Infinity;
  for (const t of starts) if (!isNaN(t) && t < base) base = t;
  if (base === Infinity) base = 0;
  const entries = log.entries.map((e, i) => {
    e = e || {};
    const req = e.request || {}, res = e.response || {}, content = res.content || {};
    const url = String(req.url || '');
    let u = null; try { u = new URL(url); } catch (_) { /* not a URL */ }
    const t = e.timings || {};
    const timings = { blocked: pos(t.blocked), dns: pos(t.dns), connect: pos(t.connect), ssl: pos(t.ssl), send: pos(t.send), wait: pos(t.wait), receive: pos(t.receive) };
    // Per the HAR spec, ssl time is included in connect time.
    timings.tcp = Math.max(0, timings.connect - timings.ssl);
    const phaseSum = timings.blocked + timings.dns + timings.connect + timings.send + timings.wait + timings.receive;
    const mime = String(content.mimeType || hdr(res.headers, 'content-type') || '').split(';')[0].trim();
    const transfer = typeof res._transferSize === 'number' && res._transferSize >= 0 ? res._transferSize : pos(res.headersSize) + pos(res.bodySize);
    return {
      i: i + 1, raw: e, method: String(req.method || 'GET').toUpperCase(), url, u,
      host: u ? u.host : '', path: u ? (u.pathname + u.search) : url,
      status: typeof res.status === 'number' ? res.status : (parseInt(res.status, 10) || 0),
      statusText: String(res.statusText || ''), error: String(res._error || e._error || ''),
      mime, type: classify(e, mime, u), transfer, contentSize: pos(content.size),
      time: typeof e.time === 'number' && e.time >= 0 ? e.time : phaseSum,
      start: isNaN(starts[i]) ? 0 : starts[i] - base, timings,
      httpVersion: String(res.httpVersion || req.httpVersion || ''), serverIP: String(e.serverIPAddress || ''),
      connection: String(e.connection || ''), pageref: String(e.pageref || ''),
      fromCache: e._fromCache ? String(e._fromCache) : (e.cache && (e.cache.beforeRequest || e.cache.afterRequest) && res.status !== 304 && transfer === 0 ? 'cache' : ''),
      findings: [], redirectTo: null, redirectFrom: null, _hay: null
    };
  });
  return { pages, entries, base };
}

/* ---------- analysis ---------- */
const RULES = {
  failed: { sev: 'error', title: 'Request failed (no HTTP response)', help: 'The browser never received a response. Usual causes: DNS failure, connection refused/reset/timed out, TLS or certificate error, the request was blocked (CORS, CSP, mixed content, an extension or firewall), or it was cancelled by navigation. The error text, when the browser recorded one, says which.' },
  preflight: { sev: 'error', title: 'CORS preflight failed', help: 'An OPTIONS preflight did not return a 2xx status, so the browser blocks the real cross-origin request. The server (or a proxy/WAF in front of it) must answer OPTIONS with 2xx and the right Access-Control-Allow-* headers.' },
  server_error: { sev: 'error', title: 'Server error (5xx)', help: '500: unhandled error in the app. 502/504: a gateway, load balancer or proxy could not reach (or timed out waiting for) the upstream server. 503: overloaded or in maintenance. Check server logs at the time shown.' },
  client_error: { sev: 'warn', title: 'Client error (4xx)', help: '400/422: the server rejected the request data. 404: wrong URL or missing resource. 405: wrong method. 413: payload too large. 429: rate limited.' },
  cors: { sev: 'error', title: 'CORS failure', help: 'The browser will not let the page use this cross-origin response (missing or wrong Access-Control-Allow-* headers, a failed preflight, or credentials with a wildcard origin). The Diagnose tab names the exact header that is wrong.' },
  mixed: { sev: 'warn', title: 'Mixed content (HTTP request from an HTTPS page)', help: 'Browsers block or warn about insecure HTTP subresources on HTTPS pages. Load these over HTTPS.' },
  redirect_chain: { sev: 'warn', title: 'Redirect chain (2 or more redirects)', help: 'Each redirect costs a full round trip, and loops or long chains often point at misconfigured http→https, www/non-www or login redirects. Link directly to the final URL.' },
  insecure_cookie: { sev: 'warn', title: 'Cookie set without the Secure flag over HTTPS', help: 'Cookies without Secure can be sent over plain HTTP. Cookies with SameSite=None are rejected by browsers unless they are also Secure.' },
  slow_ttfb: { sev: 'warn', title: 'Slow server response (waiting > 1 s)', help: '“Waiting” (time to first byte) is mostly time the server spent producing the response, plus one network round trip. Look at server-side processing, database queries or upstream calls.' },
  slow_total: { sev: 'warn', title: 'Slow request (> 3 s total)', help: 'The whole request took more than 3 seconds. See its Timing tab to find which phase dominated.' },
  slow_dns: { sev: 'info', title: 'Slow DNS lookup (> 200 ms)', help: 'Resolving the host name was slow. Check the DNS resolver, or use dns-prefetch / preconnect hints.' },
  slow_connect: { sev: 'info', title: 'Slow TCP connect (> 500 ms)', help: 'Establishing the TCP connection was slow: high latency, packet loss, or an overloaded server/load balancer.' },
  slow_tls: { sev: 'info', title: 'Slow TLS handshake (> 500 ms)', help: 'The TLS handshake was slow. Check latency, certificate chain size, OCSP stapling and TLS 1.3 / session resumption support.' },
  queued: { sev: 'info', title: 'Queued / stalled before sending (> 500 ms)', help: 'The request waited before it could be sent. With HTTP/1.1 browsers open about 6 connections per host, so many parallel requests queue up. HTTP/2 or fewer requests help.' },
  large: { sev: 'info', title: 'Large response (> 1 MB)', help: 'Large responses slow down loading on slower links. Consider compression, pagination, smaller images or lazy loading.' },
  uncompressed: { sev: 'info', title: 'Text response sent without compression', help: 'A text-based response over 2 KB had no Content-Encoding. Enabling gzip or brotli usually shrinks these by 60–80%.' },
  no_cache: { sev: 'info', title: 'Static asset without caching headers', help: 'No Cache-Control or Expires header, so browsers must guess how long to cache it. Set an explicit Cache-Control.' },
  duplicate: { sev: 'info', title: 'Same URL requested more than once', help: 'The same GET URL was downloaded more than once (not from cache). This may be wasted work or a sign of retry loops.' },
};
Object.assign(RULES, {
  diag_rules: { sev: 'warn', title: 'Your rule matched', help: 'A custom rule from Settings matched this request. See the Diagnose tab, section Your rules.' },
  diag_hidden: { sev: 'error', title: 'Hidden failure or API error', help: 'An API failed in a way that is easy to miss (GraphQL, JSON-RPC or gRPC errors inside a 200, HTML instead of JSON, malformed JSON, "undefined" in a URL) or returned a client error such as validation, 404 or 415. See the Diagnose tab.' },
  diag_ratelimit: { sev: 'error', title: 'Rate limiting or retry storm', help: 'The server throttled the client (429 / Retry-After), or the client retried a failing request without backing off. See the Diagnose tab.' },
  diag_redirect: { sev: 'error', title: 'Redirect problem', help: 'A redirect loop, an HTTPS-to-HTTP downgrade, or a POST that lost its body on a redirect. See the Diagnose tab.' },
  diag_realtime: { sev: 'error', title: 'WebSocket or streaming problem', help: 'A WebSocket or Server-Sent Events connection failed, was closed by an idle timeout, kept reconnecting, or may be buffered. See the Diagnose tab.' },
  diag_hang: { sev: 'warn', title: 'Hang or incomplete request', help: 'Requests that never finished, took very long, or downloaded very slowly. See the Diagnose tab.' },
  diag_security: { sev: 'warn', title: 'Security hygiene', help: 'Secrets in URLs, credentials over HTTP, cookies without protections, CSP violations or exposed stack traces. See the Diagnose tab.' },
  diag_cache: { sev: 'warn', title: 'Caching / CDN problem', help: 'Assets not cached by the CDN, HTML cached too long, stale-asset risks, or a response with Set-Cookie served from a shared cache. See the Diagnose tab.' },
});
RULES.auth = { sev: 'error', title: 'Authentication / authorization failure', help: 'Credentials were missing or rejected, or a sign-in flow failed. The Authentication tab shows the method used and the most likely cause for each failure.' };
RULES.auth_recovered = { sev: 'warn', title: 'Authentication failure (succeeded later)', help: 'The request failed authentication, but the same request succeeded later, for example after a token refresh or sign-in.' };
const SEV_ORDER = { error: 0, warn: 1, info: 2 };

function pageUrlFor(e) {
  const p = S.pages.find(p => p.id === e.pageref);
  if (p && /^https?:\/\//i.test(p.title || '')) return p.title;
  const I = idx(), doc = e.pageref ? I.docByPage.get(e.pageref) : I.byTime.find(x => x.type === 'doc');
  return doc ? doc.url : '';
}

function analyze() {
  RULES.slow_ttfb.title = 'Slow server response (waiting > ' + fmtMs(SETTINGS.ttfbMs) + ')';
  RULES.slow_total.title = 'Slow request (> ' + fmtMs(SETTINGS.slowMs) + ' total)';
  RULES.slow_total.help = 'The whole request took more than ' + fmtMs(SETTINGS.slowMs) + '. See its Timing tab to find which phase dominated.';
  const F = [];
  const add = (e, code, detail) => { const f = { code, sev: RULES[code].sev, e, detail: detail || '' }; e.findings.push(f); F.push(f); };
  const byUrl = new Map();
  for (const e of S.entries) { if (!byUrl.has(e.url)) byUrl.set(e.url, []); byUrl.get(e.url).push(e); }

  // Redirect links
  for (const e of S.entries) {
    if (e.status < 300 || e.status >= 400) continue;
    const res = e.raw.response || {};
    const loc = hdr(res.headers, 'location') || res.redirectURL;
    if (!loc) continue;
    let abs; try { abs = new URL(loc, e.url).href; } catch (_) { continue; }
    e.redirectTarget = abs;
    const next = (byUrl.get(abs) || []).find(x => x !== e && x.start >= e.start && !x.redirectFrom);
    if (next) { e.redirectTo = next; next.redirectFrom = e; }
  }

  const dupSeen = new Map();
  for (const e of S.entries) {
    const req = e.raw.request || {}, res = e.raw.response || {};
    const t = e.timings;
    const pageUrl = pageUrlFor(e);

    if (e.method === 'OPTIONS' && hdr(req.headers, 'access-control-request-method') && (e.status === 0 || e.status >= 300)) {
      add(e, 'preflight', e.status ? 'HTTP ' + e.status : (e.error || 'no response'));
    } else if (isFailed(e)) {
      add(e, 'failed', e.error || 'no status recorded');
    } else if (e.status >= 500) {
      add(e, 'server_error', e.status + ' ' + e.statusText);
    } else if (e.status >= 400 && !AUTH_STATUS.has(e.status)) {
      add(e, 'client_error', e.status + ' ' + e.statusText);
    }

    // Top-level navigations (e.g. an http→https redirect) are not mixed content.
    if (e.type !== 'doc' && pageUrl.startsWith('https:') && e.u && e.u.protocol === 'http:') add(e, 'mixed', 'page is ' + pageUrl);

    if (!e.redirectFrom && e.redirectTo) {
      const chain = [e]; let c = e;
      while (c.redirectTo && chain.length < 30) { c = c.redirectTo; if (chain.includes(c)) break; chain.push(c); }
      const hops = chain.filter(x => x.status >= 300 && x.status < 400).length;
      if (hops >= 2) add(e, 'redirect_chain', hops + ' redirects → ' + chain[chain.length - 1].url);
    }

    if (e.u && e.u.protocol === 'https:') {
      for (const sc of hdrAll(res.headers, 'set-cookie')) {
        for (const line of sc.split('\n')) {
          if (line.trim() && !/;\s*secure\b/i.test(line)) add(e, 'insecure_cookie', line.split('=')[0].trim() + (/samesite\s*=\s*none/i.test(line) ? ' (SameSite=None)' : ''));
        }
      }
    }

    if (t.wait > SETTINGS.ttfbMs) add(e, 'slow_ttfb', fmtMs(t.wait) + ' waiting');
    if (e.time > SETTINGS.slowMs) add(e, 'slow_total', fmtMs(e.time));
    if (t.dns > 200) add(e, 'slow_dns', fmtMs(t.dns));
    if (t.tcp > 500) add(e, 'slow_connect', fmtMs(t.tcp));
    if (t.ssl > 500) add(e, 'slow_tls', fmtMs(t.ssl));
    if (t.blocked > 500) add(e, 'queued', fmtMs(t.blocked));
    if (e.contentSize > 1048576) add(e, 'large', fmtBytes(e.contentSize));

    const ok200 = e.status === 200 && !e.fromCache;
    if (ok200 && isTextMime(e.mime) && e.contentSize > 2048 && !hdr(res.headers, 'content-encoding') && (e.transfer === 0 || e.transfer >= e.contentSize * 0.9)) {
      add(e, 'uncompressed', fmtBytes(e.contentSize) + ' ' + e.mime);
    }
    if (ok200 && ['js', 'css', 'img', 'font'].includes(e.type) && Array.isArray(res.headers) && res.headers.length && !hdr(res.headers, 'cache-control') && !hdr(res.headers, 'expires')) {
      add(e, 'no_cache', TYPE_LABEL[e.type]);
    }
    if (e.method === 'GET' && ok200 && e.u) {
      const n = (dupSeen.get(e.url) || 0) + 1; dupSeen.set(e.url, n);
      if (n > 1) add(e, 'duplicate', 'request #' + n + ' for this URL');
    }
  }
  F.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  S.findings = SETTINGS.ignoreHosts.length ? F.filter(f => !isIgnoredHost(f.e.host)) : F;
  if (SETTINGS.ignoreHosts.length) for (const e of S.entries) if (isIgnoredHost(e.host)) e.findings = [];
}
function worstSev(e) {
  let w = null;
  for (const f of e.findings) if (w == null || SEV_ORDER[f.sev] < SEV_ORDER[w]) w = f.sev;
  return w;
}

/* ---------- findings view ---------- */
function groupFindings() {
  const m = new Map();
  for (const f of S.findings) { if (!m.has(f.code)) m.set(f.code, { code: f.code, sev: f.sev, items: [] }); m.get(f.code).items.push(f); }
  return [...m.values()].sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || b.items.length - a.items.length);
}
/* ---------- detail pane ---------- */
function bodyText(content) {
  if (!content || content.text == null) return null;
  if (content.encoding === 'base64') {
    try {
      const bin = atob(content.text);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    } catch (_) { return null; }
  }
  return String(content.text);
}
function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
function toCurl(e) {
  const r = e.raw.request || {};
  const parts = ['curl ' + shq(e.url)];
  if (e.method !== 'GET' && !(e.method === 'POST' && r.postData)) parts.push('-X ' + e.method);
  for (const x of (r.headers || [])) {
    const n = String(x.name);
    if (n.startsWith(':') || /^(content-length|host|connection|accept-encoding)$/i.test(n)) continue;
    parts.push('-H ' + shq(n + ': ' + x.value));
  }
  if (r.postData && r.postData.text != null) parts.push('--data-raw ' + shq(r.postData.text));
  else if (r.postData && Array.isArray(r.postData.params)) for (const p of r.postData.params) parts.push('--data-urlencode ' + shq(p.name + '=' + (p.value || '')));
  parts.push('--compressed');
  return parts.join(' \\\n  ');
}
/* ---------- export ---------- */
const SENSITIVE_HEADER = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-refresh-token|x-id-token|x-csrf-token|x-xsrf-token|csrf-token|x-amz-security-token|x-goog-api-key|ocp-apim-subscription-key|x-functions-key|private-token|x-session-id|x-ms-token-aad-access-token)$/i;
const SENSITIVE_NAME = /(token|secret|passw|pwd|auth|session|sessid|sig|signature|credential|apikey|api_key|api-key|ticket|assertion|saml|jwt|bearer)/i;
const SENSITIVE_EXACT = /^(code|key|state|nonce|otp|pin|sid|ssn)$/i;
const RED = '[REDACTED]';
const isSensitiveName = n => SENSITIVE_NAME.test(n) || SENSITIVE_EXACT.test(n);
function redactUrl(url) {
  try {
    const u = new URL(url); let changed = false;
    for (const k of [...new Set(u.searchParams.keys())]) if (isSensitiveName(k)) { u.searchParams.set(k, RED); changed = true; }
    if (u.username || u.password) { u.username = ''; u.password = ''; changed = true; }
    if (u.hash && /(access_token|id_token|token)=/i.test(u.hash)) { u.hash = '#' + RED; changed = true; }
    return changed ? u.href : url;
  } catch (_) { return url; }
}
function redactJson(v) {
  if (Array.isArray(v)) return v.map(redactJson);
  if (v && typeof v === 'object') { const o = {}; for (const [k, x] of Object.entries(v)) o[k] = isSensitiveName(k) && (typeof x !== 'object' || x === null) ? RED : redactJson(x); return o; }
  return v;
}
function redactBodyText(text, mime) {
  if (text == null) return text;
  try { if (/json/i.test(mime || '') || /^\s*[\[{]/.test(text)) return JSON.stringify(redactJson(JSON.parse(text))); } catch (_) { /* not JSON */ }
  if (/x-www-form-urlencoded/i.test(mime || '')) {
    try { const p = new URLSearchParams(text); for (const k of [...new Set(p.keys())]) if (isSensitiveName(k)) p.set(k, RED); return p.toString(); } catch (_) { /* leave */ }
  }
  return text;
}
function buildRedacted(opts) {
  const pats = SETTINGS.redactPatterns.map(p => new RegExp(p, 'g'));
  const har = pats.length ? JSON.parse(JSON.stringify(S.har), (k, v) => typeof v === 'string' ? pats.reduce((s, re) => s.replace(re, RED), v) : v) : JSON.parse(JSON.stringify(S.har));
  const fixHeaders = list => (list || []).map(x => {
    const n = String(x.name);
    if (SENSITIVE_HEADER.test(n) || (opts.params && isSensitiveName(n) && !/^(accept|content|cache|access-control)/i.test(n))) return { ...x, value: RED };
    if (opts.params && /^(referer|location|origin|content-location)$/i.test(n)) return { ...x, value: redactUrl(String(x.value)) };
    return x;
  });
  const fixCookies = list => (list || []).map(c => ({ ...c, value: RED }));
  for (const p of (har.log.pages || [])) if (opts.params && p.title) p.title = redactUrl(p.title);
  for (const e of har.log.entries || []) {
    const req = e.request || {}, res = e.response || {};
    req.headers = fixHeaders(req.headers); res.headers = fixHeaders(res.headers);
    req.cookies = fixCookies(req.cookies); res.cookies = fixCookies(res.cookies);
    if (opts.params) {
      if (req.url) req.url = redactUrl(req.url);
      if (res.redirectURL) res.redirectURL = redactUrl(res.redirectURL);
      req.queryString = (req.queryString || []).map(q => isSensitiveName(q.name) ? { ...q, value: RED } : q);
    }
    if (req.postData) {
      if (opts.reqBody) { req.postData = { mimeType: req.postData.mimeType || '', text: '', comment: 'removed by HAR Analyzer' }; }
      else if (opts.params) {
        if (req.postData.text != null) req.postData.text = redactBodyText(String(req.postData.text), req.postData.mimeType);
        if (Array.isArray(req.postData.params)) req.postData.params = req.postData.params.map(p => isSensitiveName(p.name) ? { ...p, value: RED } : p);
      }
    }
    if (res.content) {
      if (opts.resBody) { delete res.content.text; delete res.content.encoding; res.content.comment = 'removed by HAR Analyzer'; }
      else if (opts.params && res.content.text != null && res.content.encoding !== 'base64') res.content.text = redactBodyText(String(res.content.text), res.content.mimeType);
    }
    if (opts.resBody && e._webSocketMessages) delete e._webSocketMessages;
  }
  har.log.comment = ((har.log.comment ? har.log.comment + ' ' : '') + 'Redacted with HAR Analyzer on ' + new Date().toISOString() + '.').trim();
  return har;
}
function csvCell(v) { v = v == null ? '' : String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }

/* ---------- lookup indexes (built once per loaded file) ---------- */
// Several checks need "requests to the same URL / host near this one". Scanning
// S.entries for every request is quadratic, which is too slow for large HARs.
const IDX = { of: null };
function idx() {
  if (IDX.of === S.entries) return IDX;
  const byTime = [...S.entries].sort((a, b) => a.start - b.start);
  const byUrl = new Map(), byHost = new Map(), okHosts = new Set(), okStarts = [], docByPage = new Map();
  for (const e of byTime) {
    const k = String(e.url).split(/[?#]/)[0];
    if (!byUrl.has(k)) byUrl.set(k, []); byUrl.get(k).push(e);
    if (!byHost.has(e.host)) byHost.set(e.host, []); byHost.get(e.host).push(e);
    if (e.status > 0) { okHosts.add(e.host); okStarts.push(e.start); }
    if (e.type === 'doc' && !docByPage.has(e.pageref)) docByPage.set(e.pageref, e);
  }
  Object.assign(IDX, { of: S.entries, byTime, byUrl, byHost, okHosts, okStarts, docByPage });
  return IDX;
}
const sameUrl = e => idx().byUrl.get(String(e.url).split(/[?#]/)[0]) || [];
// Index of the first element whose key >= v in an array sorted by key.
function lowerBound(arr, v, key) { let lo = 0, hi = arr.length; while (lo < hi) { const mid = (lo + hi) >> 1; if ((key ? key(arr[mid]) : arr[mid]) < v) lo = mid + 1; else hi = mid; } return lo; }
