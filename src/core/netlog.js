/* ======================================================================
   Chrome NetLog (chrome://net-export) support
   Converts a NetLog into HAR-style entries (so every analysis works on it)
   and extracts what a HAR does not have: DNS lookups, proxy decisions,
   connection attempts, TLS details and the certificates Chrome saw, with
   every problem Chrome's verifier found.
   ====================================================================== */
const isNetLog = o => !!(o && typeof o === 'object' && o.constants && Array.isArray(o.events));
function parseNetLogText(text) {
  try { return JSON.parse(text); } catch (err) {
    // net-export files are cut short when Chrome crashes or logging is not stopped: repair the ending.
    let t = text.trimEnd().replace(/,\s*$/, '');
    for (const tail of [']}', '\n]}', '}]}']) { try { const o = JSON.parse(t + tail); o._truncated = true; return o; } catch (_) { /* try the next ending */ } }
    const k = t.lastIndexOf('},');
    if (k > 0) { try { const o = JSON.parse(t.slice(0, k + 1) + ']}'); o._truncated = true; return o; } catch (_) { /* give up */ } }
    throw err;
  }
}

/* ---------- X.509 certificates (minimal DER reader) ---------- */
function derRead(b, p) {
  const tag = b[p]; let len = b[p + 1], hl = 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[p + 2 + i]; hl = 2 + n; }
  return { tag, start: p + hl, end: p + hl + len, next: p + hl + len };
}
function derKids(b, node) { const out = []; let p = node.start; while (p < node.end) { const k = derRead(b, p); out.push(k); p = k.next; } return out; }
function derOid(b, n) { const v = b.subarray(n.start, n.end), out = [Math.floor(v[0] / 40), v[0] % 40]; let x = 0; for (let i = 1; i < v.length; i++) { x = x * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { out.push(x); x = 0; } } return out.join('.'); }
const derStr = (b, n) => new TextDecoder('utf-8').decode(b.subarray(n.start, n.end));
function derTime(b, n) {
  const s = derStr(b, n);
  const m = n.tag === 0x17 ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s) : /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s);
  if (!m) return NaN;
  const y = n.tag === 0x17 ? (+m[1] < 50 ? 2000 + +m[1] : 1900 + +m[1]) : +m[1];
  return Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
}
const OID_NAMES = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST' };
function derName(b, n) {
  const parts = [];
  for (const rdn of derKids(b, n)) for (const atv of derKids(b, rdn)) { const [o, v] = derKids(b, atv); const k = OID_NAMES[derOid(b, o)]; if (k) parts.push([k, derStr(b, v)]); }
  return parts;
}
function parseCertPem(pem) {
  try {
    const b = b64ToBytes(String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
    const cert = derRead(b, 0), [tbs] = derKids(b, cert), f = derKids(b, tbs);
    let i = f[0].tag === 0xa0 ? 1 : 0;
    const issuer = derName(b, f[i + 2]), [nb, na] = derKids(b, f[i + 3]), subject = derName(b, f[i + 4]);
    const sans = [];
    const ext = f.find(x => x.tag === 0xa3);
    if (ext) for (const e of derKids(b, derKids(b, ext)[0])) {
      const k = derKids(b, e);
      if (derOid(b, k[0]) !== '2.5.29.17') continue;
      const seq = derRead(b, k[k.length - 1].start);
      for (const g of derKids(b, seq)) { if (g.tag === 0x82) sans.push(derStr(b, g)); else if (g.tag === 0x87) sans.push([...b.subarray(g.start, g.end)].join(g.end - g.start === 4 ? '.' : ':')); }
    }
    const cn = (subject.find(x => x[0] === 'CN') || [])[1] || '', icn = (issuer.find(x => x[0] === 'CN') || [])[1] || '';
    return { subject: subject.map(x => x.join('=')).join(', '), cn, issuer: issuer.map(x => x.join('=')).join(', '), issuerCn: icn, notBefore: derTime(b, nb), notAfter: derTime(b, na), sans, selfSigned: JSON.stringify(subject) === JSON.stringify(issuer) };
  } catch (_) { return null; }
}
function certCoversHost(cert, host) {
  host = String(host || '').toLowerCase().replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  const names = cert.sans.length ? cert.sans : [cert.cn];
  return names.some(n => { n = String(n).toLowerCase(); return n === host || (n.startsWith('*.') && host.endsWith(n.slice(1)) && host.split('.').length === n.split('.').length); });
}
const TLS_CIPHERS = { 4865: 'TLS_AES_128_GCM_SHA256', 4866: 'TLS_AES_256_GCM_SHA384', 4867: 'TLS_CHACHA20_POLY1305_SHA256', 49195: 'ECDHE_ECDSA_AES_128_GCM_SHA256', 49196: 'ECDHE_ECDSA_AES_256_GCM_SHA384', 49199: 'ECDHE_RSA_AES_128_GCM_SHA256', 49200: 'ECDHE_RSA_AES_256_GCM_SHA384', 52392: 'ECDHE_RSA_CHACHA20_POLY1305', 52393: 'ECDHE_ECDSA_CHACHA20_POLY1305', 47: 'RSA_AES_128_CBC_SHA (legacy)', 53: 'RSA_AES_256_CBC_SHA (legacy)' };

/* ---------- NetLog → HAR entries + transport details ---------- */
function netlogToHar(log) {
  const C = log.constants || {}, inv = o => Object.fromEntries(Object.entries(o || {}).map(([k, v]) => [v, k]));
  const T = inv(C.logEventTypes), SRC = inv(C.logSourceType), ERR = inv(C.netError), CS = C.certStatusFlag || {};
  const PH = C.logEventPhase || { PHASE_BEGIN: 1, PHASE_END: 2, PHASE_NONE: 0 };
  const off = Number(C.timeTickOffset) || 0, abs = t => off + Number(t);
  const errName = n => (ERR[n] ? 'net::' + ERR[n] : 'net error ' + n);
  const bySrc = new Map(), edges = new Map();
  const link = (a, b) => { if (!edges.has(a)) edges.set(a, new Set()); if (!edges.has(b)) edges.set(b, new Set()); edges.get(a).add(b); edges.get(b).add(a); };
  for (const e of log.events) {
    if (!e || !e.source) continue;
    const id = e.source.id;
    if (!bySrc.has(id)) bySrc.set(id, { id, type: SRC[e.source.type] || String(e.source.type), events: [] });
    bySrc.get(id).events.push(e);
    const dep = e.params && e.params.source_dependency;
    if (dep && dep.id != null) link(id, dep.id);
  }
  const typeOf = id => (bySrc.get(id) || {}).type;
  const flags = st => Object.entries(CS).filter(([k, v]) => v && (st & v) === v && !/^(IS_EV|REV_CHECKING_ENABLED|SHA1_SIGNATURE_PRESENT|CT_COMPLIANCE_FAILED|IS_QWAC)$/.test(k)).map(([k]) => k);

  // Sockets: connect attempts, TLS, certificate verification
  const sockets = new Map();
  for (const s of bySrc.values()) {
    if (s.type !== 'SOCKET') continue;
    const k = { id: s.id, attempts: [], connect: null, tls: null, remote: '', local: '', inUse: 0, bytesIn: 0, bytesOut: 0 };
    let cs = null, ss = null;
    for (const e of s.events) {
      const n = T[e.type], p = e.params || {};
      if (n === 'TCP_CONNECT' && e.phase === PH.PHASE_BEGIN) { cs = abs(e.time); k.addresses = p.address_list || []; }
      if (n === 'TCP_CONNECT' && e.phase === PH.PHASE_END) { k.connect = { start: cs, end: abs(e.time), error: p.net_error ? errName(p.net_error) : '' }; if (p.remote_address) k.remote = p.remote_address; if (p.local_address) k.local = p.local_address; if (p.net_error) for (const a of (k.addresses || [])) k.attempts.push({ address: a, error: errName(p.net_error), at: abs(e.time) }); }
      if (n === 'TCP_CONNECT_ATTEMPT' && e.phase === PH.PHASE_BEGIN) k.attempts.push({ address: p.address, at: abs(e.time) });
      if (n === 'TCP_CONNECT_ATTEMPT' && e.phase === PH.PHASE_END && k.attempts.length && (p.net_error || p.os_error)) k.attempts[k.attempts.length - 1].error = p.net_error ? errName(p.net_error) : 'OS error ' + p.os_error;
      if (n === 'SSL_CONNECT' && e.phase === PH.PHASE_BEGIN) ss = abs(e.time);
      if (n === 'SSL_CONNECT' && e.phase === PH.PHASE_END) k.tls = { start: ss, end: abs(e.time), error: p.net_error ? errName(p.net_error) : '', version: p.version || '', cipher: p.cipher_suite != null ? (TLS_CIPHERS[p.cipher_suite] || '0x' + Number(p.cipher_suite).toString(16)) : '', alpn: p.next_proto || '', resumed: !!p.is_resumed };
      if (n === 'SOCKET_IN_USE' && e.phase === PH.PHASE_BEGIN) k.inUse++;
      if (n === 'SOCKET_BYTES_RECEIVED' && p.byte_count) k.bytesIn += p.byte_count;
      if (n === 'SOCKET_BYTES_SENT' && p.byte_count) k.bytesOut += p.byte_count;
    }
    sockets.set(s.id, k);
  }
  const certJobs = new Map();
  for (const s of bySrc.values()) {
    if (s.type !== 'CERT_VERIFIER_JOB') continue;
    const b = s.events.find(e => T[e.type] === 'CERT_VERIFIER_JOB' && e.phase === PH.PHASE_BEGIN), en = s.events.find(e => T[e.type] === 'CERT_VERIFIER_JOB' && e.phase === PH.PHASE_END);
    const pems = (b && b.params && (b.params.certificates || (b.params.certificate && b.params.certificate.certificates))) || [];
    const chain = pems.map(parseCertPem).filter(Boolean);
    const p = (en && en.params) || {};
    certJobs.set(s.id, { id: s.id, host: (b && b.params && b.params.host) || '', chain, leaf: chain[0] || null, status: p.cert_status || 0, flags: flags(p.cert_status || 0), error: p.net_error ? errName(p.net_error) : '', knownRoot: p.is_issued_by_known_root });
  }
  // DNS lookups (host resolver jobs carry the outcome)
  const dns = [];
  for (const s of bySrc.values()) for (const e of s.events) {
    const n = T[e.type];
    if ((n === 'HOST_RESOLVER_MANAGER_JOB' || n === 'HOST_RESOLVER_IMPL_JOB') && e.phase === PH.PHASE_BEGIN && e.params && e.params.host) {
      const end = s.events.find(x => x.type === e.type && x.phase === PH.PHASE_END && Number(x.time) >= Number(e.time));
      const ep = (end && end.params) || {};
      const addrs = ep.results ? JSON.stringify(ep.results).match(/\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\]/gi) || [] : ep.address_list || [];
      dns.push({ host: String(e.params.host).replace(/^[a-z]+:\/\//i, '').replace(/:\d+$/, ''), start: abs(e.time), ms: end ? Number(end.time) - Number(e.time) : NaN, error: ep.net_error ? errName(ep.net_error) : '', addresses: [...new Set(addrs)], types: e.params.dns_query_types || [] });
    }
  }
  // Proxy decisions and PAC script errors
  const pacErrors = [];
  for (const s of bySrc.values()) for (const e of s.events) {
    const n = T[e.type];
    if ((n === 'PAC_JAVASCRIPT_ERROR' || n === 'PAC_JAVASCRIPT_ALERT') && e.params) pacErrors.push({ kind: n === 'PAC_JAVASCRIPT_ERROR' ? 'error' : 'alert', message: e.params.message || '', line: e.params.line_number, at: abs(e.time) });
  }
  // Walk from a request to its stream jobs, sockets and certificate jobs (never into another request).
  const reach = rid => {
    const seen = new Set([rid]), q = [[rid, 0]], out = { sockets: [], certs: [], proxy: '' };
    while (q.length) {
      const [id, d] = q.shift();
      const ty = typeOf(id);
      if (ty === 'SOCKET' && sockets.has(id)) out.sockets.push(sockets.get(id));
      if (ty === 'CERT_VERIFIER_JOB' && certJobs.has(id)) out.certs.push(certJobs.get(id));
      if (ty === 'HTTP_STREAM_JOB_CONTROLLER' && !out.proxy) for (const e of bySrc.get(id).events) { const n = T[e.type]; if (n === 'PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST' && e.params) out.proxy = e.params.proxy_info || out.proxy; if (n === 'HTTP_STREAM_JOB_CONTROLLER_PROXY_SERVER_RESOLVED' && e.params && !out.proxy) out.proxy = e.params.proxy_chain || ''; }
      if (d >= 7) continue;
      for (const n of edges.get(id) || []) { if (seen.has(n)) continue; seen.add(n); if (typeOf(n) === 'URL_REQUEST') continue; q.push([n, d + 1]); }
    }
    return out;
  };
  const splitHeaders = list => {
    if (!list) return { status: 0, statusText: '', version: '', headers: [] };
    const arr = Array.isArray(list) ? list : Object.entries(list).map(([k, v]) => k + ': ' + v);
    let status = 0, statusText = '', version = '';
    const headers = [];
    for (const line of arr) {
      const m = /^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)$/.exec(line);
      if (m) { version = m[1]; status = +m[2]; statusText = m[3]; continue; }
      const i = String(line).indexOf(':', String(line).startsWith(':') ? 1 : 0);
      if (i < 0) continue;
      const name = line.slice(0, i).trim(), value = line.slice(i + 1).trim();
      if (name === ':status') { status = +value; version = 'h2'; }
      headers.push({ name, value });
    }
    return { status, statusText, version, headers };
  };
  const entries = [], details = [];
  for (const s of bySrc.values()) {
    if (s.type !== 'URL_REQUEST') continue;
    const hops = [];
    let cur = null, lastEnd = NaN, alive = null;
    for (const e of s.events) {
      const n = T[e.type], p = e.params || {}, t = abs(e.time);
      if (n === 'REQUEST_ALIVE' && e.phase === PH.PHASE_BEGIN) alive = t;
      if (n === 'URL_REQUEST_START_JOB' && e.phase === PH.PHASE_BEGIN && p.url) { if (cur) cur.end = t; cur = { url: p.url, method: p.method || 'GET', start: hops.length ? t : (alive || t), reqHeaders: null, resHeaders: null, bytes: 0, error: '', proto: 'http/1.1', initiator: p.initiator || '' }; hops.push(cur); continue; }
      if (!cur) continue;
      if (/^HTTP_TRANSACTION_(HTTP2_|QUIC_|)SEND_REQUEST_HEADERS$/.test(n)) { cur.reqHeaders = p.headers; if (/HTTP2/.test(n)) cur.proto = 'h2'; if (/QUIC/.test(n)) cur.proto = 'h3'; }
      if (n === 'HTTP_TRANSACTION_SEND_REQUEST' && e.phase === PH.PHASE_BEGIN) cur.sendStart = t;
      if (n === 'HTTP_TRANSACTION_SEND_REQUEST' && e.phase === PH.PHASE_END) cur.sendEnd = t;
      if (n === 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS') cur.resHeaders = p.headers;
      if (n === 'HTTP_TRANSACTION_READ_HEADERS' && e.phase === PH.PHASE_END) cur.headersEnd = t;
      if ((n === 'URL_REQUEST_JOB_FILTERED_BYTES_READ') && p.byte_count) cur.bytes += p.byte_count;
      if ((n === 'URL_REQUEST_REDIRECT_JOB' || n === 'URL_REQUEST_REDIRECTED') && (p.location || p.url)) cur.location = p.location || p.url;
      if (p.net_error && e.phase !== PH.PHASE_BEGIN && !cur.error && !/^(HTTP_CACHE_|DISK_CACHE_|ENTRY_)/.test(n)) cur.error = errName(p.net_error); // cache-internal errors are not request failures
      if (n === 'REQUEST_ALIVE' && e.phase === PH.PHASE_END) lastEnd = t;
    }
    if (!hops.length) continue;
    if (hops.length === 1 && hops[0].error === 'net::ERR_CACHE_MISS' && !hops[0].resHeaders) continue; // a cache-only lookup (preload / back-forward / speculative), not a network request
    if (isFinite(lastEnd)) hops[hops.length - 1].end = lastEnd;
    const r = reach(s.id);
    const cert = r.certs.find(c => c.leaf) || null;
    hops.forEach((hp, k) => {
      const end = isFinite(hp.end) ? hp.end : (hp.headersEnd || hp.start);
      const res = splitHeaders(hp.resHeaders), req = splitHeaders(hp.reqHeaders);
      let u = null; try { u = new URL(hp.url); } catch (_) { /* not a URL */ }
      const host = u ? u.hostname : '';
      const sock = r.sockets.find(x => x.connect && !x.connect.error && x.connect.start >= hp.start - 5 && x.connect.start <= end) || null;
      const used = sock || r.sockets.find(x => x.connect && !x.connect.error) || r.sockets[0] || null;
      const lookup = dns.filter(d => d.host === host && d.start >= hp.start - 5 && d.start <= end).pop() || null;
      const dnsMs = lookup && isFinite(lookup.ms) ? lookup.ms : -1;
      const tcpMs = sock && sock.connect ? sock.connect.end - sock.connect.start : -1;
      const sslMs = sock && sock.tls && sock.tls.end ? sock.tls.end - sock.tls.start : -1;
      const send = hp.sendStart && hp.sendEnd ? hp.sendEnd - hp.sendStart : 0;
      const wait = hp.sendEnd && hp.headersEnd ? hp.headersEnd - hp.sendEnd : 0;
      const receive = hp.headersEnd ? Math.max(0, end - hp.headersEnd) : 0;
      const connect = tcpMs >= 0 ? tcpMs + Math.max(0, sslMs) : -1;
      const total = Math.max(0, end - hp.start);
      const blocked = Math.max(0, total - Math.max(0, dnsMs) - Math.max(0, connect) - send - wait - receive);
      const mime = (res.headers.find(x => /^content-type$/i.test(x.name)) || {}).value || '';
      const loc = (res.headers.find(x => /^location$/i.test(x.name)) || {}).value || hp.location || (hops[k + 1] ? hops[k + 1].url : '');
      const hopError = hp.error || (k === hops.length - 1 ? '' : '');
      const info = { source: s.id, proxy: r.proxy, cert, sockets: r.sockets.map(x => ({ id: x.id, remote: x.remote, attempts: x.attempts, tls: x.tls, connectError: x.connect && x.connect.error })), dns: lookup };
      const remote = used && used.remote ? used.remote.replace(/:\d+$/, '').replace(/^\[|\]$/g, '') : '';
      entries.push({
        startedDateTime: new Date(hp.start).toISOString(), time: total,
        request: { method: hp.method, url: hp.url, httpVersion: res.version || hp.proto, headers: req.headers, queryString: u ? [...u.searchParams].map(([name, value]) => ({ name, value })) : [], cookies: [], headersSize: -1, bodySize: -1 },
        response: { status: res.status, statusText: res.statusText, httpVersion: res.version || (res.status ? hp.proto : ''), headers: res.headers, cookies: [], content: { size: hp.bytes, mimeType: mime.split(';')[0] }, redirectURL: res.status >= 300 && res.status < 400 ? loc : '', headersSize: -1, bodySize: hp.bytes, _transferSize: hp.bytes, ...(hopError && !res.status ? { _error: hopError } : {}) },
        cache: {}, timings: { blocked, dns: dnsMs, connect, ssl: sslMs, send, wait, receive },
        serverIPAddress: remote, connection: used ? String(used.id) : '', _netlog: info,
      });
      details.push({ entryIndex: entries.length - 1, url: hp.url, error: hopError, ...info });
    });
  }
  entries.sort((a, b) => Date.parse(a.startedDateTime) - Date.parse(b.startedDateTime));
  // IPv6 fallback: a connect to an IPv6 address failed and the same host:port then worked over IPv4.
  const v6 = [];
  const all = [...sockets.values()];
  for (const sk of all) for (const a of sk.attempts) {
    if (!a.error || !/^\[/.test(a.address || '')) continue;
    const port = (a.address.match(/:(\d+)$/) || [])[1];
    const ok = all.find(o => o.connect && !o.connect.error && o.remote && !/^\[/.test(o.remote) && o.remote.endsWith(':' + port) && Math.abs(o.connect.start - a.at) < 3000);
    if (ok) v6.push({ v6: a.address, error: a.error, v4: ok.remote, at: a.at });
  }
  const certs = [...certJobs.values()].filter(c => c.leaf);
  const startT = entries.length ? Date.parse(entries[0].startedDateTime) : off;
  return {
    har: { log: { version: '1.2', creator: { name: 'Chrome NetLog', version: (C.clientInfo && (C.clientInfo.version || C.clientInfo.cl)) || '' }, pages: [], entries, comment: 'Converted from a Chrome NetLog by HAR Analytics. NetLogs do not contain request or response bodies.' } },
    info: { truncated: !!log._truncated, captureMode: C.logCaptureMode || '', events: log.events.length, sources: bySrc.size, client: C.clientInfo || {}, start: startT, dns, pacErrors, certs, ipv6Fallbacks: v6, sockets: all, details, flagNames: Object.keys(CS) },
  };
}

/* ---------- NetLog-only diagnoses ---------- */
const CERT_FLAG_TEXT = { AUTHORITY_INVALID: 'not issued by a trusted authority', COMMON_NAME_INVALID: 'issued for a different host name', DATE_INVALID: 'expired or not valid yet', REVOKED: 'revoked', INVALID: 'invalid', WEAK_SIGNATURE_ALGORITHM: 'signed with a weak algorithm', NAME_CONSTRAINT_VIOLATION: 'violates a name constraint', CERTIFICATE_TRANSPARENCY_REQUIRED: 'missing Certificate Transparency', KNOWN_INTERCEPTION_BLOCKED: 'a known interception certificate', NON_UNIQUE_NAME: 'for a non-unique (internal) name', PINNED_KEY_MISSING: 'missing a pinned key', SYMANTEC_LEGACY: 'from the distrusted legacy Symantec PKI', VALIDITY_TOO_LONG: 'valid for too long', NO_REVOCATION_MECHANISM: 'without a revocation mechanism', UNABLE_TO_CHECK_REVOCATION: 'impossible to check for revocation' };
// Sites whose certificate came from the same non-public issuer as this one (a TLS-inspection proxy signs them all).
function inspectionSites(cert) {
  if (cert.knownRoot !== false || !cert.leaf || !S.netlog) return [];
  const sites = new Set();
  for (const c of S.netlog.certs || []) if (c.leaf && c.knownRoot === false && c.leaf.issuer === cert.leaf.issuer && !c.leaf.selfSigned) { const n = c.leaf.sans[0] || c.leaf.cn; if (n && !/^(localhost|[\d.]+)$/.test(n)) sites.add(siteOf(n.replace(/^\*\./, ''))); }
  return [...sites];
}
function certFacts(cert, host, when) {
  const L = cert.leaf, facts = [], causes = [];
  let inspected = [];
  if (!L) return { facts, causes };
  facts.push('Certificate: ' + (L.cn || L.subject) + (L.sans.length ? ' (names: ' + L.sans.slice(0, 8).join(', ') + (L.sans.length > 8 ? ', …' : '') + ')' : ''));
  facts.push('Issued by: ' + (L.issuerCn || L.issuer) + (L.selfSigned ? ' (self-signed)' : '') + (cert.knownRoot === false ? ', not a publicly trusted root' : ''));
  facts.push('Valid: ' + fmtDate(L.notBefore) + ' → ' + fmtDate(L.notAfter));
  if (cert.flags.length) facts.push('Chrome’s verdict (all problems found): ' + cert.flags.map(f => CERT_FLAG_TEXT[f] || f).join('; '));
  if (isFinite(L.notAfter) && L.notAfter < when) causes.push(C('high', 'cert_expired', 'The certificate expired ' + fmtDelta(when - L.notAfter) + ' before this request', 'It was valid until ' + fmtDate(L.notAfter) + '.', ['Renew and install the certificate on ' + host + '.']));
  if (isFinite(L.notBefore) && L.notBefore > when) causes.push(C('high', 'cert_not_yet', 'The certificate is not valid yet (from ' + fmtDate(L.notBefore) + ')', 'Either it was installed too early or this computer’s clock is behind.', ['Check the client clock.']));
  if (host && !certCoversHost(L, host)) causes.push(C('high', 'cert_wrong_host', 'The certificate is for ' + (L.sans[0] || L.cn) + ', not ' + host, 'Names in the certificate: ' + (L.sans.join(', ') || L.cn) + '.', ['Install a certificate whose names include ' + host + ', or use a host name that is on the certificate.']));
  if (L.selfSigned) causes.push(C('high', 'cert_self_signed', 'The certificate is self-signed', 'Browsers only trust self-signed certificates that were installed as trusted roots on this device.', ['Use a certificate from a trusted CA, or install this one as a trusted root (development only).']));
  else if ((inspected = inspectionSites(cert)).length >= 2) causes.push(C('high', 'tls_inspection', 'A TLS-inspection proxy is replacing certificates (' + (L.issuerCn || L.issuer) + ')', 'The same private CA issued the certificates Chrome received for ' + inspected.length + ' unrelated sites (' + inspected.slice(0, 4).join(', ') + (inspected.length > 4 ? ', …' : '') + '). Real sites use their own public CAs, so a proxy or security product on the network path (Zscaler, Netskope, a firewall, antivirus) is decrypting the traffic and re-signing it with its own root, which this device does not trust.', ['Install the inspection proxy’s root certificate on this device (ask IT for it), or have IT exempt these sites from inspection.', 'Apps with their own trust store (Node, Java, Python, Git) need the root added separately (NODE_EXTRA_CA_CERTS, the Java keystore, REQUESTS_CA_BUNDLE, http.sslCAInfo).']));
  else if (cert.knownRoot === false && cert.flags.includes('AUTHORITY_INVALID')) causes.push(C('likely', 'cert_private_ca', 'The certificate chain ends at a private or missing CA (' + (L.issuerCn || L.issuer) + ')', 'A corporate CA or TLS-inspection proxy root that is not installed on this device, or a server that does not send its intermediate certificate.', ['Install the issuing CA on the device, or configure the server to send the full chain.']));
  return { facts, causes };
}
function diagNetlog() {
  const N = S.netlog;
  if (!N) return;
  // Enrich failed TLS requests with the certificate facts
  const seen = new Set();
  for (const e of S.entries) {
    const nl = e.raw._netlog || (e.netlogLink && e.netlogLink._netlog);
    if (!nl || !nl.cert || !/CERT|SSL/.test(e.error || '') || seen.has(e.host)) continue;
    seen.add(e.host);
    const { facts, causes } = certFacts(nl.cert, e.u ? e.u.hostname : e.host, entryTime(e));
    const ev = (e.diag || []).find(v => v.cat === 'network');
    if (ev) { ev.causes.unshift(...causes); ev.causes.sort((a, b) => CONF_ORDER[a.conf] - CONF_ORDER[b.conf]); ev.evidence.push(...facts); ev.netlog = true; }
    else dAdd('network', 'error', e, 'TLS certificate problem — ' + e.host, causes.length ? causes : [C('likely', 'cert_problem', 'Chrome rejected the certificate', nl.cert.flags.join(', '), [])], facts);
  }
  const v6 = new Map(); for (const f of N.ipv6Fallbacks) { const ip = f.v6.replace(/:\d+$/, ''); if (!v6.has(ip)) v6.set(ip, { ...f, n: 0 }); v6.get(ip).n++; }
  for (const f of [...v6.values()].slice(0, 5)) dAdd('network', 'info', null, 'IPv6 connections to ' + f.v6.replace(/:\d+$/, '') + ' failed ' + f.n + ' time' + (f.n > 1 ? 's' : '') + '; Chrome fell back to IPv4', [C('possible', 'ipv6_fallback', 'Connections over IPv6 fail on this network or server', f.v6 + ' failed with ' + f.error + '; ' + f.v4 + ' over IPv4 worked. Each fallback adds delay. Typical causes: the server or a load balancer does not listen on IPv6 although DNS has an AAAA record, or the network’s IPv6 route is broken.', ['Fix IPv6 on the server / network, or remove the AAAA record.'])], [], []);
  for (const d of N.dns.filter(d => d.error)) if (!S.entries.some(e => e.host === d.host && e.error)) dAdd('network', 'error', null, 'DNS lookup failed for ' + d.host + ' (seen only in the NetLog)', [C('high', 'netlog_dns', 'DNS could not resolve ' + d.host, d.error + ' after ' + fmtMs(d.ms) + '.', ['Check the name and the DNS server / VPN.'])], [], []);
  const slow = N.dns.filter(d => !d.error && d.ms > 500);
  if (slow.length) dAdd('network', 'warn', null, slow.length + ' slow DNS lookup' + (slow.length > 1 ? 's' : '') + ' (over 500 ms)', [C('likely', 'netlog_slow_dns', 'DNS resolution is slow', 'Slowest: ' + slow.sort((a, b) => b.ms - a.ms).slice(0, 5).map(d => d.host + ' ' + fmtMs(d.ms)).join(', ') + '.', ['Check the DNS server or VPN DNS settings.'])], [], []);
  for (const p of N.pacErrors.filter(p => p.kind === 'error').slice(0, 3)) dAdd('network', 'error', null, 'The proxy auto-config (PAC) script has an error', [C('high', 'pac_error', 'PAC script error: ' + p.message, 'Line ' + (p.line ?? '?') + '. When the PAC script fails, Chrome may use the wrong proxy or none.', ['Fix the PAC file and reload proxy settings.'])], [], []);
}
// Match NetLog requests to an open HAR's entries (same method + URL, nearest start time).
function attachNetlog(info, netEntries) {
  const byKey = new Map();
  for (const ne of netEntries) { const k = ne.request.method + ' ' + ne.request.url; if (!byKey.has(k)) byKey.set(k, []); byKey.get(k).push(ne); }
  let matched = 0;
  for (const e of S.entries) {
    const list = byKey.get(e.method + ' ' + e.url); if (!list || !list.length) continue;
    const t = entryTime(e);
    let best = 0; for (let k = 1; k < list.length; k++) if (Math.abs(Date.parse(list[k].startedDateTime) - t) < Math.abs(Date.parse(list[best].startedDateTime) - t)) best = k;
    if (Math.abs(Date.parse(list[best].startedDateTime) - t) > 120000) continue;
    e.netlogLink = list.splice(best, 1)[0]; matched++;
  }
  return matched;
}
