const AUTH_STATUS = new Set([401, 403, 407, 419, 440, 495, 496, 498, 511]);
const A = { events: [], tokens: new Map(), flows: [], notes: [], hosts: new Map(), jar: [], skew: new Map(), secrets: new Set(), sanitized: false, error: '' };
const CONF_ORDER = { high: 0, likely: 1, possible: 2 };
const CONF_LABEL = { high: 'Strong evidence', likely: 'Likely', possible: 'Possible' };
const LOGIN_RE = /\/(log-?in|sign-?in|signon|sso|authorize|authenticate|oauth2?|saml2?|session\/new|adfs\/ls|idp|cas\/login)(\/|\?|#|$|\.)/i;
const API_KEY_HEADERS = /^(x-api-key|api-key|apikey|x-apikey|x-functions-key|ocp-apim-subscription-key|x-goog-api-key|private-token|x-auth-token|x-access-token|x-app-key|x-client-secret)$/i;
const SESSION_COOKIE = /(sess|^sid$|_sid$|auth|token|jwt|login|remember|^jsessionid$|^phpsessid$|^connect\.sid$|^fedauth|^rtfa$|^estsauth|^__host-|^__secure-|^idsrv|^\.aspnetcore\.(cookies|identity)|^\.aspxauth|okta)/i;

/* ---------- decoding helpers ---------- */
function b64ToBytes(s) {
  s = String(s).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s); const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}
const utf8 = b => new TextDecoder('utf-8').decode(b);
function tryB64Text(s) { try { return utf8(b64ToBytes(s)); } catch (_) { return null; } }
function parseJwt(tok) {
  if (typeof tok !== 'string') return null;
  const p = tok.trim().split('.');
  if (p.length === 5) {
    try { const header = JSON.parse(utf8(b64ToBytes(p[0]))); return header && header.enc ? { header, payload: null, encrypted: true } : null; } catch (_) { return null; }
  }
  if (p.length !== 3 || p[0].length < 10) return null;
  try {
    const header = JSON.parse(utf8(b64ToBytes(p[0])));
    const payload = JSON.parse(utf8(b64ToBytes(p[1])));
    if (!header || typeof header !== 'object' || !header.alg) return null;
    return { header, payload: payload && typeof payload === 'object' ? payload : {}, sigLen: p[2].length };
  } catch (_) { return null; }
}
function shortHash(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0; return h.toString(16).padStart(8, '0'); }
const fp = tok => '#' + shortHash(String(tok)).slice(0, 6) + ' (' + String(tok).length + ' chars)';
const maskId = s => { s = String(s || ''); return s.length > 8 ? s.slice(0, 4) + '…' + s.slice(-4) : s; };
const isRedacted = v => /^\[?(redacted|removed|filtered|hidden|masked|\*{3,}|x{4,})\]?$/i.test(String(v).trim()) || /\[REDACTED\]/.test(String(v));
const entryTime = e => (S.base || 0) + e.start;
const fmtDate = ms => isFinite(ms) ? new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '—';
function fmtDelta(ms) {
  const a = Math.abs(ms);
  if (a < 1000) return Math.round(a) + ' ms';
  if (a < 60000) return Math.round(a / 1000) + ' s';
  if (a < 7200000) return Math.round(a / 60000) + ' min';
  if (a < 172800000) return (a / 3600000).toFixed(1).replace(/\.0$/, '') + ' h';
  return Math.round(a / 86400000) + ' days';
}
function siteOf(host) {
  host = String(host || '').toLowerCase();
  if (/^[\d.]+$|:/.test(host)) return host;
  const p = host.split('.');
  if (p.length <= 2) return host;
  if (p[p.length - 1].length === 2 && /^(co|com|org|net|gov|ac|edu|ne|or)$/.test(p[p.length - 2])) return p.slice(-3).join('.');
  return p.slice(-2).join('.');
}
function absUrl(loc, base) { try { return new URL(loc, base).href; } catch (_) { return String(loc); } }
const noQuery = u => String(u || '').split(/[?#]/)[0];
function urlParamsAll(url) {
  const out = {};
  try {
    const u = new URL(url);
    for (const [k, v] of u.searchParams) out[k] = v;
    if (u.hash.length > 1) for (const [k, v] of new URLSearchParams(u.hash.slice(1))) out[k] = v;
  } catch (_) { /* not a URL */ }
  return out;
}
function secret(v) { if (v != null) { v = String(v); if (v.length >= 4 && !isRedacted(v)) A.secrets.add(v); } return v; }
const SECRET_FIELD = /^(password|passwd|pwd|pass|secret|client_secret|code|code_verifier|refresh_token|access_token|id_token|client_assertion|assertion|samlresponse|samlrequest|otp|token|api_key|apikey|key|sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token)$/i;

/* ---------- WWW-Authenticate / Authorization parsing ---------- */
function parseChallenges(str) {
  const out = []; let s = String(str || '');
  while (true) {
    s = s.replace(/^[\s,]+/, ''); if (!s) break;
    const m = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+/.exec(s); if (!m) break;
    const ch = { scheme: m[0], params: {}, token: '' }; out.push(ch); s = s.slice(m[0].length);
    const t68 = /^\s+([A-Za-z0-9\-._~+/]+=*)\s*(?=,|$)/.exec(s);
    if (t68) { ch.token = t68[1]; s = s.slice(t68[0].length); continue; }
    while (true) {
      const pm = /^[\s,]*([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*=\s*("((?:[^"\\]|\\.)*)"|([^,\s]*))/.exec(s);
      if (!pm) break;
      ch.params[pm[1].toLowerCase()] = pm[3] != null ? pm[3].replace(/\\(.)/g, '$1') : pm[4];
      s = s.slice(pm[0].length);
    }
  }
  return out;
}
function challengeText(c) {
  const bits = [c.scheme];
  for (const k of ['realm', 'error', 'error_description', 'scope', 'algorithm', 'stale', 'qop']) if (c.params[k] != null) bits.push(k + '="' + c.params[k] + '"');
  if (c.token) { const n = /^(ntlm|negotiate)$/i.test(c.scheme) ? parseNegotiate(c.token) : null; bits.push(n ? '(' + (n.ntlm ? 'NTLM type ' + n.ntlm.type : n.mech) + ' token' + (n.negState ? ', ' + n.negState : '') + ')' : '(token)'); }
  return bits.join(' ');
}

/* ---------- NTLM / Kerberos (SPNEGO) ---------- */
function parseNtlm(bytes) {
  const sig = 'NTLMSSP\0';
  if (bytes.length < 12) return null;
  for (let i = 0; i < 8; i++) if (bytes[i] !== sig.charCodeAt(i)) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out = { type: dv.getUint32(8, true) };
  const buf = off => {
    if (off + 8 > bytes.length) return null;
    const len = dv.getUint16(off, true), o = dv.getUint32(off + 4, true);
    return o + len <= bytes.length ? bytes.subarray(o, o + len) : null;
  };
  const u16 = b => { if (!b || !b.length) return ''; const a = new Uint16Array(b.slice(0, b.length & ~1).buffer); let s = ''; for (const c of a) s += String.fromCharCode(c); return s; };
  const oem = b => { if (!b) return ''; let s = ''; for (const c of b) s += String.fromCharCode(c); return s; };
  if (out.type === 1 && bytes.length >= 16) out.flags = dv.getUint32(12, true);
  if (out.type === 2 && bytes.length >= 32) { out.flags = dv.getUint32(20, true); const t = buf(12); out.target = (out.flags & 1) ? u16(t) : oem(t); }
  if (out.type === 3 && bytes.length >= 52) {
    out.flags = bytes.length >= 64 ? dv.getUint32(60, true) : 0;
    const dec = (out.flags & 1) || !out.flags ? u16 : oem;
    const nt = buf(20); out.ntLen = nt ? nt.length : 0;
    out.domain = dec(buf(28)); out.user = dec(buf(36)); out.workstation = dec(buf(44));
    out.version = out.ntLen === 24 ? 'NTLMv1' : out.ntLen > 24 ? 'NTLMv2' : out.ntLen === 0 ? 'anonymous' : 'unknown';
  }
  return out;
}
function indexOfSeq(b, seq) {
  outer: for (let i = 0; i + seq.length <= b.length; i++) { for (let j = 0; j < seq.length; j++) if (b[i + j] !== seq[j]) continue outer; return i; }
  return -1;
}
const OID_KRB5 = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02], OID_MSKRB5 = [0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];
const OID_NTLMSSP = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a], NTLM_SIG = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00];
function parseNegotiate(tok) {
  let b; try { b = b64ToBytes(tok); } catch (_) { return { mech: 'unreadable' }; }
  const at = indexOfSeq(b, NTLM_SIG);
  const out = { mech: 'unknown' };
  if (at >= 0) { out.mech = 'NTLM'; out.ntlm = parseNtlm(b.subarray(at)); }
  else if (indexOfSeq(b, OID_KRB5) >= 0 || indexOfSeq(b, OID_MSKRB5) >= 0) out.mech = 'Kerberos';
  else if (indexOfSeq(b, OID_NTLMSSP) >= 0) out.mech = 'NTLM';
  if (b[0] === 0xa1) { const i = indexOfSeq(b, [0xa0, 0x03, 0x0a, 0x01]); if (i >= 0 && i < 12) out.negState = ['accept-completed', 'accept-incomplete', 'reject', 'request-mic'][b[i + 4]] || ''; }
  return out;
}

/* ---------- tokens ---------- */
function registerToken(tok, jwt, e, how, kind) {
  secret(tok);
  const k = shortHash(tok) + ':' + tok.length;
  let t = A.tokens.get(k);
  if (!t) { t = { key: k, fp: fp(tok), jwt, kinds: new Set(), uses: [], issued: [] }; A.tokens.set(k, t); }
  if (kind) t.kinds.add(kind);
  (how === 'issued' ? t.issued : t.uses).push(e);
  return t;
}
const tokenOf = tok => A.tokens.get(shortHash(String(tok)) + ':' + String(tok).length);
function harvestResponseTokens(e) {
  const res = e.raw.response || {};
  if (e.status >= 200 && e.status < 300 && /json/i.test(e.mime)) {
    let j = null; try { j = JSON.parse(bodyText(res.content || {}) || ''); } catch (_) { /* not JSON */ }
    if (j && typeof j === 'object' && (typeof j.access_token === 'string' || typeof j.id_token === 'string')) {
      e.tokenResponse = { scope: j.scope, expires_in: j.expires_in, token_type: j.token_type, has: [] };
      for (const [f, kind] of [['access_token', 'access'], ['id_token', 'id'], ['refresh_token', 'refresh']]) {
        if (typeof j[f] === 'string') { registerToken(j[f], parseJwt(j[f]), e, 'issued', kind); e.tokenResponse.has.push(f); }
      }
    }
  }
  const loc = hdr(res.headers, 'location');
  if (loc && /[#?&](access_token|id_token)=/.test(loc)) {
    const p = urlParamsAll(absUrl(loc, e.url));
    for (const [f, kind] of [['access_token', 'access'], ['id_token', 'id']]) if (p[f]) registerToken(p[f], parseJwt(p[f]), e, 'issued', kind);
  }
}
function scopesOf(p) {
  const s = new Set();
  if (!p) return s;
  for (const x of [].concat(p.scp || p.scope || []).join(' ').split(/\s+/)) if (x) s.add(x);
  for (const r of [].concat(p.roles || [])) s.add(String(r));
  return s;
}

/* ---------- credentials on a request ---------- */
function requestCookies(e) {
  const req = e.raw.request || {}; const m = new Map();
  for (const c of (req.cookies || [])) if (c && c.name) m.set(c.name, String(c.value ?? ''));
  for (const v of hdrAll(req.headers, 'cookie')) for (const part of v.split(';')) { const i = part.indexOf('='); const n = (i < 0 ? part : part.slice(0, i)).trim(); if (n && !m.has(n)) m.set(n, i < 0 ? '' : part.slice(i + 1).trim()); }
  return m;
}
function bearerCred(tok, where, e) {
  tok = String(tok || '').trim();
  const jwt = parseJwt(tok);
  if (jwt) registerToken(tok, jwt, e, 'use'); else secret(tok);
  return { method: jwt ? (jwt.encrypted ? 'Bearer token (encrypted JWT)' : 'Bearer token (JWT)') : 'Bearer token (opaque)', label: (jwt ? 'Bearer JWT' : 'Bearer token') + ' in ' + where + ' ' + fp(tok), token: tok, jwt, where };
}
function describeAuthorization(v, e, hname) {
  v = String(v).trim();
  if (isRedacted(v)) return { method: 'Unknown (redacted)', label: hname + ' header present but redacted', redacted: true, header: hname, scheme: '' };
  secret(v);
  const sp = v.indexOf(' ');
  const scheme = sp < 0 ? v : v.slice(0, sp), rest = sp < 0 ? '' : v.slice(sp + 1).trim(), s = scheme.toLowerCase();
  const c = { scheme, header: hname };
  secret(rest);
  if (s === 'basic') {
    const txt = tryB64Text(rest), i = txt ? txt.indexOf(':') : -1;
    if (i >= 0) secret(txt.slice(i + 1));
    return { ...c, method: 'HTTP Basic', user: i >= 0 ? txt.slice(0, i) : null, pwLen: i >= 0 ? txt.length - i - 1 : null, label: 'HTTP Basic' + (i >= 0 ? ' as "' + txt.slice(0, i) + '"' : ' (undecodable)') };
  }
  if (s === 'bearer' || s === 'dpop') return { ...bearerCred(rest, hname + ' header', e), ...c, dpop: s === 'dpop' };
  if (s === 'digest') {
    const p = (parseChallenges('Digest ' + rest)[0] || {}).params || {};
    return { ...c, method: 'HTTP Digest', user: p.username, params: p, label: 'HTTP Digest as "' + (p.username || '?') + '"' + (p.algorithm ? ' (' + p.algorithm + ')' : '') };
  }
  if (s === 'ntlm' || s === 'negotiate') {
    const n = parseNegotiate(rest);
    const method = n.mech === 'Kerberos' ? 'Kerberos (Negotiate)' : n.mech === 'NTLM' ? (s === 'negotiate' ? 'NTLM (inside Negotiate)' : 'NTLM') : 'Negotiate';
    let label = method;
    if (n.ntlm) label += ' type ' + n.ntlm.type + (n.ntlm.type === 1 ? ' (negotiate)' : n.ntlm.type === 3 ? ' (authenticate) for ' + (n.ntlm.domain ? n.ntlm.domain + '\\' : '') + (n.ntlm.user || '(anonymous)') + ', ' + n.ntlm.version : '');
    else if (n.mech === 'Kerberos') label += ' ticket';
    return { ...c, method, neg: n, label };
  }
  if (s === 'aws4-hmac-sha256') {
    const m = /Credential=([^/,\s]+)\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request/.exec(rest);
    return { ...c, method: 'AWS Signature v4', aws: m ? { key: m[1], date: m[2], region: m[3], service: m[4] } : {}, label: 'AWS SigV4' + (m ? ' (key ' + maskId(m[1]) + ', ' + m[3] + ', ' + m[4] + ')' : '') };
  }
  if (s === 'sharedkey' || s === 'sharedkeylite') return { ...c, method: 'Azure Storage Shared Key', label: 'Azure Storage ' + scheme + ' (account ' + rest.split(':')[0] + ')' };
  if (s === 'oauth') {
    const p = (parseChallenges('OAuth ' + rest)[0] || {}).params || {};
    return { ...c, method: 'OAuth 1.0a', params: p, label: 'OAuth 1.0a (consumer ' + (p.oauth_consumer_key || '?') + (p.oauth_signature_method ? ', ' + p.oauth_signature_method : '') + ')' };
  }
  if (s === 'hawk') return { ...c, method: 'Hawk', label: 'Hawk' };
  if (s === 'ssws') return { ...c, method: 'API token (Okta SSWS)', label: 'Okta SSWS API token ' + fp(rest) };
  if (/^(token|apikey|api-key|key|api_key)$/.test(s)) return { ...c, method: 'API token', label: 'API token (' + scheme + ' scheme) ' + fp(rest) };
  if (!rest && parseJwt(scheme)) return { ...bearerCred(scheme, hname + ' header without a scheme', e), header: hname, scheme: '', noScheme: true };
  return { ...c, method: 'Custom (' + scheme + ')', label: 'Custom Authorization scheme "' + scheme + '"' };
}
function amzDate(s) { const m = /^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/.exec(s || ''); return m ? Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : NaN; }
function credentialsOf(e) {
  const req = e.raw.request || {}, H = req.headers || [], creds = [];
  for (const v of hdrAll(H, 'authorization')) creds.push(describeAuthorization(v, e, 'Authorization'));
  for (const v of hdrAll(H, 'proxy-authorization')) creds.push({ ...describeAuthorization(v, e, 'Proxy-Authorization'), proxy: true });
  for (const x of H) if (API_KEY_HEADERS.test(x.name)) { secret(x.value); creds.push({ method: 'API key', label: 'API key in ' + x.name + ' header ' + (isRedacted(x.value) ? '(redacted)' : fp(x.value)), where: x.name }); }
  if (e.u) {
    const q = e.u.searchParams;
    for (const [k, v] of q) if (SECRET_FIELD.test(k)) secret(v);
    if (q.get('X-Amz-Credential') || q.get('X-Amz-Signature')) {
      const cred = (q.get('X-Amz-Credential') || '').split('/'), signed = amzDate(q.get('X-Amz-Date')), exp = +q.get('X-Amz-Expires');
      creds.push({ method: 'AWS presigned URL', label: 'AWS SigV4 presigned URL (key ' + maskId(cred[0]) + (cred[2] ? ', ' + cred[2] : '') + (cred[3] ? ', ' + cred[3] : '') + ')', presign: { signed, seconds: exp, expires: isNaN(signed) || !exp ? NaN : signed + exp * 1000, temp: !!q.get('X-Amz-Security-Token') } });
    } else if (q.get('sig') && (q.get('se') || q.get('sv'))) {
      creds.push({ method: 'Azure SAS token', label: 'Azure shared access signature (permissions ' + (q.get('sp') || '?') + (q.get('se') ? ', expires ' + q.get('se') : '') + ')', sas: { start: Date.parse(q.get('st') || ''), expiry: Date.parse(q.get('se') || ''), perms: q.get('sp') || '' } });
    } else if (q.get('access_token')) creds.push(bearerCred(q.get('access_token'), 'access_token query parameter', e));
    else for (const k of ['api_key', 'apikey', 'api-key', 'key']) if (q.get(k)) { creds.push({ method: 'API key', label: 'API key in "' + k + '" query parameter ' + fp(q.get(k)), where: '?' + k }); break; }
  }
  const cookies = requestCookies(e);
  for (const v of cookies.values()) secret(v);
  const sess = [...cookies.keys()].filter(n => SESSION_COOKIE.test(n));
  if (sess.length) {
    const c = { method: 'Session cookie', label: 'Session cookie' + (sess.length > 1 ? 's' : '') + ' ' + sess.join(', '), cookies: sess };
    for (const n of sess) { const j = parseJwt(cookies.get(n)); if (j) { registerToken(cookies.get(n), j, e, 'use', 'cookie'); c.jwt = c.jwt || j; c.token = c.token || cookies.get(n); } }
    creds.push(c);
  }
  return creds;
}
function bodyParams(e) {
  const pd = (e.raw.request || {}).postData; if (!pd) return null;
  const dec = v => { v = v == null ? '' : String(v); if (/%[0-9a-f]{2}/i.test(v)) { try { return decodeURIComponent(v.replace(/\+/g, ' ')); } catch (_) { return v; } } return v; };
  const out = {};
  if (Array.isArray(pd.params) && pd.params.length) { for (const p of pd.params) out[p.name] = dec(p.value); return out; }
  const t = pd.text == null ? '' : String(pd.text);
  if (/json/i.test(pd.mimeType || '') || /^\s*\{/.test(t)) { try { const j = JSON.parse(t); if (j && typeof j === 'object') return j; } catch (_) { /* not JSON */ } }
  if (/x-www-form-urlencoded/i.test(pd.mimeType || '') || /^[\w.%-]+=/.test(t)) { try { for (const [k, v] of new URLSearchParams(t)) out[k] = v; return out; } catch (_) { /* not a form */ } }
  return null;
}

/* ---------- cookies set by responses ---------- */
function parseSetCookie(line, e) {
  const [nv, ...attrs] = line.split(';'); const i = nv.indexOf('=');
  const c = { name: nv.slice(0, i).trim(), value: nv.slice(i + 1).trim(), e, at: entryTime(e), host: e.u ? e.u.hostname.toLowerCase() : '' };
  for (const a of attrs) {
    const j = a.indexOf('='), key = (j < 0 ? a : a.slice(0, j)).trim().toLowerCase(), val = j < 0 ? '' : a.slice(j + 1).trim();
    if (key === 'domain') c.domain = val.replace(/^\./, '').toLowerCase();
    else if (key === 'path') c.path = val;
    else if (key === 'expires') c.expires = Date.parse(val);
    else if (key === 'max-age') c.maxAge = +val;
    else if (key === 'secure') c.secure = true;
    else if (key === 'httponly') c.httpOnly = true;
    else if (key === 'samesite') c.sameSite = val.toLowerCase();
    else if (key === 'partitioned') c.partitioned = true;
  }
  return c;
}
function setCookiesOf(e) {
  const res = e.raw.response || {}, out = [];
  for (const v of hdrAll(res.headers, 'set-cookie')) for (const line of v.split('\n')) if (line.includes('=')) out.push(parseSetCookie(line, e));
  if (!out.length) for (const c of (res.cookies || [])) if (c && c.name) out.push({ name: c.name, value: String(c.value ?? ''), e, at: entryTime(e), host: e.u ? e.u.hostname.toLowerCase() : '', domain: c.domain ? String(c.domain).replace(/^\./, '').toLowerCase() : undefined, path: c.path, expires: c.expires ? Date.parse(c.expires) : undefined, secure: !!c.secure, httpOnly: !!c.httpOnly, sameSite: c.sameSite ? String(c.sameSite).toLowerCase() : undefined });
  for (const c of out) secret(c.value);
  return out;
}
const cookieApplies = (c, e) => { if (!e.u) return false; const h = e.u.hostname.toLowerCase(); return c.domain ? h === c.domain || h.endsWith('.' + c.domain) : h === c.host; };
function setCookieSummary(c) {
  return [c.domain ? 'Domain=' + c.domain : 'host-only', 'Path=' + (c.path || '/'), c.secure ? 'Secure' : 'not Secure', c.httpOnly ? 'HttpOnly' : '', 'SameSite=' + (c.sameSite ? c.sameSite[0].toUpperCase() + c.sameSite.slice(1) : 'unspecified'), isFinite(c.maxAge) ? 'Max-Age=' + c.maxAge : '', isFinite(c.expires) ? 'Expires ' + fmtDate(c.expires) : ''].filter(Boolean).join('; ');
}
function cookieWhyNotSent(c, e) {
  const t = entryTime(e), H = (e.raw.request || {}).headers || [], u = e.u;
  if (c.value === '' || c.maxAge <= 0 || (isFinite(c.expires) && c.expires <= c.at)) return { id: 'deleted', conf: 'high', short: 'it had been deleted', text: 'That response deleted it (empty value or an expiry in the past), which is what servers do on sign-out or when they reset the session.', fixes: ['Find out why #' + c.e.i + ' cleared the cookie (sign-out, session reset, a failed check).'] };
  if ((isFinite(c.expires) && c.expires <= t) || (c.maxAge > 0 && c.at + c.maxAge * 1000 <= t)) return { id: 'expired', conf: 'high', short: 'it had expired', text: 'Its lifetime ended before this request was made.', fixes: ['Lengthen the cookie lifetime, or refresh the session before it expires.'] };
  if (c.path && !u.pathname.startsWith(c.path)) return { id: 'path', conf: 'high', short: 'its Path does not cover this URL', text: 'Path=' + c.path + ' does not match ' + u.pathname + '.', fixes: ['Set the cookie with Path=/ (or a path that covers the API).'] };
  if (c.secure && u.protocol !== 'https:') return { id: 'secure', conf: 'high', short: 'it is Secure but this request used HTTP', text: 'Secure cookies are only sent over HTTPS.', fixes: ['Use HTTPS for this request.'] };
  if (c.sameSite === 'none' && !c.secure) return { id: 'samesite_insecure', conf: 'high', short: 'browsers rejected it (SameSite=None without Secure)', text: 'Browsers refuse to store a SameSite=None cookie that is not also Secure, so it never existed in the browser.', fixes: ['Set the cookie with SameSite=None; Secure.'] };
  const sfs = hdr(H, 'sec-fetch-site').toLowerCase(), mode = hdr(H, 'sec-fetch-mode').toLowerCase();
  let cross = false;
  if (sfs) cross = sfs === 'cross-site';
  else { const o = hdr(H, 'origin') || hdr(H, 'referer'); if (o && o !== 'null') { try { cross = siteOf(new URL(o).hostname) !== siteOf(u.hostname); } catch (_) { /* bad URL */ } } }
  const nav = mode === 'navigate' || (!mode && e.type === 'doc');
  if (cross) {
    if (c.sameSite === 'strict') return { id: 'samesite', conf: 'high', short: 'SameSite=Strict blocks it on cross-site requests', text: 'This request came from another site, and Strict cookies are never sent cross-site.', fixes: ['Use SameSite=Lax (for top-level navigations) or SameSite=None; Secure if the cookie must be sent from other sites.'] };
    if ((!c.sameSite || c.sameSite === 'lax') && !(nav && e.method === 'GET')) return { id: 'samesite', conf: 'high', short: 'SameSite=' + (c.sameSite ? 'Lax' : 'unspecified (treated as Lax)') + ' blocks it on this cross-site ' + (nav ? e.method + ' navigation' : 'request'), text: 'This request came from another site (' + (hdr(H, 'origin') || hdr(H, 'referer') || 'Sec-Fetch-Site: cross-site') + '). Lax cookies are only sent on cross-site top-level GET navigations, not on cross-site fetch/XHR, iframes, images or POSTs.' + (c.sameSite ? '' : ' The cookie has no SameSite attribute, and browsers treat that as Lax.'), fixes: ['If this cookie must be sent from other sites, set it with SameSite=None; Secure (and, for embedded use, consider Partitioned).', 'Or serve the API from the same site as the page.'] };
    if (c.sameSite === 'none') return { id: 'third_party', conf: 'likely', short: 'third-party cookie blocking', text: 'It is SameSite=None; Secure, so only the browser’s third-party cookie protection (Safari ITP, Firefox, Chrome settings or tracking protection) would block it on this cross-site request.', fixes: ['Use Partitioned cookies (CHIPS), the Storage Access API, or a same-site API host; or send the credential in a header instead.'] };
  }
  const origin = hdr(H, 'origin');
  if (!nav && origin && origin !== 'null' && origin !== u.origin) return { id: 'credentials_mode', conf: 'likely', short: 'cross-origin request without credentials mode', text: 'This is a cross-origin fetch/XHR from ' + origin + '. Browsers only attach cookies to those when the code sets credentials: "include" (fetch) or withCredentials = true (XHR), and the response must then allow it with Access-Control-Allow-Credentials: true and a specific Access-Control-Allow-Origin (not *).', fixes: ['Set credentials: "include" / withCredentials = true on the request, and Access-Control-Allow-Credentials: true on the server.'] };
  return { id: 'unknown', conf: 'possible', short: 'no rule in the HAR explains why', text: 'It applies to this URL and was not expired or deleted in this capture. It may have been blocked by the browser (third-party cookie settings, an extension), cleared outside the capture, or set in a different browser profile or container.', fixes: ['Check the browser’s cookie storage and any “blocked cookies” warnings in DevTools for this request.'] };
}

/* ---------- server messages ---------- */
function collectErr(j, out, depth) {
  if (!j || typeof j !== 'object' || depth > 3) return;
  if (Array.isArray(j)) { if (j.length) collectErr(j[0], out, depth + 1); return; }
  const s = k => (typeof j[k] === 'string' || typeof j[k] === 'number') ? String(j[k]) : null;
  if (!out.error && typeof j.error === 'string') out.error = j.error;
  if (!out.description) out.description = s('error_description') || s('errorSummary') || s('message') || s('detail') || s('error_message') || s('msg') || s('reason') || s('title');
  if (!out.code) { const c = s('code') || s('errorCode') || s('error_code') || s('status'); if (c && !/^\d{3}$/.test(c)) out.code = c; }
  if (j.error && typeof j.error === 'object') collectErr(j.error, out, depth + 1);
  if (Array.isArray(j.errors)) collectErr(j.errors, out, depth + 1);
}
function errorInfo(e) {
  const out = {}, text = bodyText((e.raw.response || {}).content || {});
  if (!text) return out;
  const t = text.slice(0, 200000); out.text = t;
  if (/json/i.test(e.mime) || /^\s*[[{]/.test(t)) { try { collectErr(JSON.parse(t), out, 0); } catch (_) { /* not JSON */ } }
  if (/xml/i.test(e.mime) || /^\s*<\?xml|<Error>/i.test(t)) {
    const code = /<Code>([^<]+)<\/Code>/i.exec(t), msg = /<Message>([^<]+)<\/Message>/i.exec(t), ad = /<AuthenticationErrorDetail>([^<]+)</i.exec(t);
    if (code && !out.code) out.code = code[1].trim();
    if (msg && !out.description) out.description = msg[1].trim();
    if (ad) out.detail = ad[1].trim();
  }
  if (/html/i.test(e.mime) || /^\s*<(!doctype|html)/i.test(t)) {
    const title = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(t); if (title) out.title = title[1].trim();
    out.loginForm = /<input[^>]+type\s*=\s*["']?password/i.test(t);
    out.html = true;
  }
  if (!out.description && !out.title && !out.code && !out.error && t.length < 300 && !/[<{]/.test(t)) out.description = t.trim();
  return out;
}
const msgOf = err => [err.error, err.description, err.code && err.code !== err.error ? err.code : null, err.detail, err.title].filter(Boolean).join(' — ');

/* ---------- knowledge tables ---------- */
const BEARER_ERR = {
  invalid_token: 'The access token is expired, revoked, malformed, or not valid for this API (wrong issuer, audience or signing key).',
  insufficient_scope: 'The token is valid but lacks a required scope or permission.',
  invalid_request: 'The request is malformed: a required parameter is missing, or the token was sent more than once or in an unsupported place.',
};
const OAUTH_ERR = {
  invalid_grant: { t: 'Grant rejected (invalid_grant)', d: 'The authorization code, refresh token or user credentials are invalid, expired, revoked, already used, or were issued to another client. Identity providers also return this for a PKCE code_verifier or redirect_uri mismatch.' },
  invalid_client: { t: 'Client authentication failed (invalid_client)', d: 'Unknown client_id, a wrong or expired client secret or certificate, or the client authenticated with a method the identity provider does not allow for it.' },
  unauthorized_client: { t: 'Client not allowed to use this grant (unauthorized_client)', d: 'The application is not configured or permitted for this grant type or response type.' },
  unsupported_grant_type: { t: 'Unsupported grant type', d: 'The authorization server does not support the grant_type that was sent.' },
  unsupported_response_type: { t: 'Unsupported response type', d: 'The authorization server, or this client’s configuration, does not allow this response_type.' },
  invalid_scope: { t: 'Invalid scope (invalid_scope)', d: 'A requested scope is unknown, malformed, or not allowed for this client.' },
  invalid_request: { t: 'Invalid request (invalid_request)', d: 'A required parameter is missing or invalid, often redirect_uri, code_verifier or client_id.' },
  access_denied: { t: 'Access denied (access_denied)', d: 'The user declined consent, or a policy (Conditional Access, app assignment, group restriction) denied the sign-in.' },
  server_error: { t: 'Identity provider error (server_error)', d: 'The identity provider hit an internal error.' },
  temporarily_unavailable: { t: 'Identity provider unavailable', d: 'The identity provider is overloaded or in maintenance.' },
  login_required: { t: 'Login required (login_required)', d: 'Silent sign-in (prompt=none) failed because the user has no session at the identity provider. In an iframe this usually means the browser blocked the identity provider’s third-party cookies.' },
  interaction_required: { t: 'Interaction required (interaction_required)', d: 'Silent sign-in failed because the user must interact: MFA, consent, or a policy prompt.' },
  consent_required: { t: 'Consent required (consent_required)', d: 'The user, or an administrator, has not consented to the requested permissions.' },
  account_selection_required: { t: 'Account selection required', d: 'Several accounts are signed in and the user must pick one.' },
  invalid_dpop_proof: { t: 'Invalid DPoP proof', d: 'The DPoP proof was missing, malformed, or did not match this request.' },
  authorization_pending: { t: 'Authorization pending', d: 'Device flow: the user has not finished signing in yet. This is normal while polling.' },
  slow_down: { t: 'Polling too fast (slow_down)', d: 'Device flow: the client must poll less often.' },
  expired_token: { t: 'Device code expired', d: 'Device flow: the user did not finish signing in in time.' },
};
const AADSTS = {
  50126: 'Wrong username or password.', 50076: 'Multi-factor authentication is required by policy.', 50079: 'The user must register for multi-factor authentication.', 50074: 'Strong authentication (MFA) is required.',
  700016: 'Application (client_id) not found in this tenant: wrong tenant or client_id, or the app has not been consented there.', 50011: 'The redirect URI in the request does not match any configured for the app.',
  7000215: 'Invalid client secret. Often the secret’s ID was used instead of its value.', 7000222: 'The client secret has expired; create a new one.', 70008: 'The authorization code or refresh token has expired.',
  54005: 'The authorization code was already redeemed (codes are single-use).', 50173: 'The grant expired because the user changed their password or it was revoked.', 50133: 'The session is invalid because the password changed.',
  65001: 'The user or an administrator has not consented to the app’s permissions.', 90072: 'The account does not exist in this tenant (guest not invited, or wrong tenant).', 53003: 'Blocked by a Conditional Access policy.',
  50105: 'The user is not assigned to the application, and assignment is required.', 700082: 'The refresh token expired due to inactivity.', 9002326: 'Cross-origin token redemption is only allowed for apps registered as a Single-Page Application (SPA).',
  50058: 'Silent sign-in failed: there is no user session at Microsoft Entra ID (third-party cookies blocked?).', 500011: 'The resource (API) was not found in the tenant: wrong scope/resource URI, or the API has not been consented.',
  700024: 'The client assertion is not within its valid time range (expired assertion or clock skew).', 50034: 'The user account does not exist in this directory.', 50053: 'The account is locked, or sign-in was blocked from a suspicious IP.',
  50057: 'The user account is disabled.', 50055: 'The password has expired.', 50020: 'The user from an external identity provider does not exist in this tenant.', 700054: 'response_type id_token is not enabled for the application.',
  50148: 'The PKCE code_verifier does not match the code_challenge.', 501481: 'The PKCE code_verifier does not match the code_challenge.', 7000218: 'The request must contain client_assertion or client_secret: the app is registered as a confidential client but a public-client flow was used.',
  50196: 'Request loop detected: the client signed in too many times in a short period.', 240002: 'An id_token cannot be used as an authorization grant.',
};
const SAML_STATUS = {
  Requester: 'The identity provider says the service provider’s request was wrong (bad or unsigned AuthnRequest, unknown service provider).',
  Responder: 'The identity provider could not process the request (an error or a policy on the identity provider’s side).',
  VersionMismatch: 'SAML version mismatch.', AuthnFailed: 'The user could not be authenticated (wrong credentials, failed MFA).',
  InvalidNameIDPolicy: 'The identity provider cannot supply the NameID format the service provider asked for.',
  NoAuthnContext: 'The identity provider cannot satisfy the requested authentication context (for example a specific MFA level or PasswordProtectedTransport).',
  NoPassive: 'Passive (silent) sign-in failed because the user has no session at the identity provider.',
  RequestDenied: 'The identity provider refused the request (policy, or the user is not assigned to the application).',
  RequestUnsupported: 'The identity provider does not support this request.', UnknownPrincipal: 'The user is unknown to the identity provider.',
  NoAvailableIDP: 'No identity provider is available for this request.', NoSupportedIDP: 'None of the identity providers supports this request.',
};
const CLOUD_CODES = {
  SignatureDoesNotMatch: ['high', 'The request signature does not match (AWS / S3-compatible)', 'The server calculated a different signature: wrong secret key, a header or query parameter changed after signing (proxy, URL re-encoding), or the wrong region or service in the signature.'],
  InvalidAccessKeyId: ['high', 'Unknown access key ID', 'The access key does not exist in this account, was deleted, or belongs to another environment.'],
  ExpiredToken: ['high', 'Temporary credentials expired', 'The session token (STS / assumed role) has expired. Refresh the temporary credentials.'],
  InvalidToken: ['high', 'Invalid session token', 'The security token is malformed or invalid.'],
  TokenRefreshRequired: ['high', 'The session token must be refreshed', 'Refresh the temporary credentials.'],
  RequestTimeTooSkewed: ['high', 'Client clock is more than 15 minutes off', 'AWS rejects signatures whose timestamp differs from server time by more than 15 minutes. Fix the client clock (NTP).'],
  RequestExpired: ['high', 'The signed request has expired', 'The signed request or presigned URL is past its expiry time.'],
  AccessDenied: ['likely', 'Access denied by policy', 'The credentials are valid, but an IAM, bucket, KMS or organization policy does not allow this action on this resource.'],
  AllAccessDisabled: ['high', 'All access to this resource is disabled', ''],
  AuthenticationFailed: ['high', 'Azure Storage authentication failed', 'The Shared Key or SAS signature is invalid, expired, or not valid yet.'],
  AuthorizationFailure: ['likely', 'Azure: not authorized (often network rules)', 'The storage account’s firewall or virtual-network rules, or a disabled access method, blocked the request.'],
  AuthorizationPermissionMismatch: ['high', 'Azure role (RBAC) permission missing', 'The identity is signed in but lacks a data role such as Storage Blob Data Reader or Contributor.'],
  AuthorizationResourceTypeMismatch: ['high', 'The SAS is not valid for this resource type', 'The SAS srt/sr parameter does not include this resource type.'],
  AuthorizationServiceMismatch: ['high', 'The SAS is not valid for this service', 'The SAS ss parameter does not include this service.'],
  KeyBasedAuthenticationNotPermitted: ['high', 'Shared Key authorization is disabled on the storage account', 'Use Microsoft Entra ID (OAuth) instead.'],
  InvalidAuthenticationInfo: ['high', 'Invalid authentication information (Azure)', 'The authentication header or token is malformed.'],
};
const KEYWORDS = [
  [/expired?\b/i, 'msg_expired', 'The server’s message says the credentials or session expired', ['jwt_expired', 'jwt_expired_skew', 'bearer_expired', 'presign_expired', 'sas_expired', 'session_invalid']],
  [/signature/i, 'msg_signature', 'The server’s message mentions an invalid signature (token signed by a different key, issuer or environment)', ['cloud_SignatureDoesNotMatch']],
  [/audience|\baud\b/i, 'msg_audience', 'The server’s message mentions the token audience', ['jwt_audience', 'id_token_as_access']],
  [/issuer|\biss\b/i, 'msg_issuer', 'The server’s message mentions the token issuer (a token from another tenant or environment?)', []],
  [/revoked/i, 'msg_revoked', 'The server’s message says the credentials were revoked', []],
  [/(invalid|incorrect|wrong|bad)\W+(user ?(name)?|password|credentials?|login)/i, 'msg_bad_password', 'The server’s message says the username or password is wrong', ['basic_rejected']],
  [/locked/i, 'msg_locked', 'The server’s message says the account is locked', []],
  [/disabled|deactivated|suspended/i, 'msg_disabled', 'The server’s message says the account is disabled', []],
  [/\bmfa\b|multi-?factor|\b2fa\b|two-?factor|\botp\b/i, 'msg_mfa', 'The server’s message mentions multi-factor authentication', []],
  [/api.?key/i, 'msg_api_key', 'The server’s message says the API key is invalid', ['api_key_rejected']],
  [/(missing|no|required|without).{0,20}(token|authori[sz]ation|credentials?|api.?key)/i, 'msg_missing', 'The server’s message says credentials are missing', ['header_dropped_redirect', 'header_missing', 'no_credentials', 'sanitized', 'cookie_samesite', 'cookie_credentials_mode', 'cookie_deleted', 'cookie_expired', 'cookie_path', 'cookie_secure', 'cookie_unknown']],
];
function wafVendor(e, err) {
  const H = (e.raw.response || {}).headers || [], body = (err.text || '').slice(0, 20000), server = hdr(H, 'server');
  if (hdr(H, 'cf-ray') && /cloudflare/i.test(server) && /attention required|you have been blocked|cf-error|ray id|access denied/i.test(body)) return 'Cloudflare';
  if (hdr(H, 'x-amzn-waf-action')) return 'AWS WAF';
  if (/request blocked[\s\S]*cloudfront|generated by cloudfront/i.test(body)) return 'Amazon CloudFront / AWS WAF';
  if (/incapsula incident|_Incapsula_Resource/i.test(body) || hdr(H, 'x-iinfo')) return 'Imperva';
  if (/AkamaiGHost/i.test(server) || /errors\.edgesuite\.net/i.test(body) || /access denied[\s\S]{0,400}reference #/i.test(body)) return 'Akamai';
  if (hdr(H, 'x-azure-ref') && /the request is blocked/i.test(body)) return 'Azure Front Door';
  if (/sucuri/i.test(server) || /sucuri website firewall/i.test(body)) return 'Sucuri';
  if (/mod_?security|web application firewall|requested url was rejected[\s\S]{0,200}support id/i.test(body)) return 'a web application firewall';
  return null;
}

/* ---------- clock skew ---------- */
function computeSkew() {
  const per = new Map();
  for (const e of S.entries) {
    const d = Date.parse(hdr((e.raw.response || {}).headers, 'date'));
    if (isNaN(d) || !e.host || e.status === 0) continue;
    if (!per.has(e.host)) per.set(e.host, []);
    per.get(e.host).push(d - (entryTime(e) + e.time - e.timings.receive));
  }
  for (const [h, arr] of per) {
    arr.sort((a, b) => a - b);
    const med = arr[arr.length >> 1];
    A.skew.set(h, med);
    if (Math.abs(med) >= 60000) A.notes.push('The clock of ' + h + ' is about ' + fmtDelta(med) + (med > 0 ? ' ahead of' : ' behind') + ' the computer that captured this HAR (from its Date headers). Token expiry (JWT exp/nbf), SAML validity windows, Kerberos (5 minute tolerance) and AWS signatures (15 minutes) all depend on clocks agreeing.');
  }
}

function addMethod(host, method, e) {
  if (!host) return;
  if (!A.hosts.has(host)) A.hosts.set(host, new Map());
  const m = A.hosts.get(host);
  m.set(method, (m.get(method) || 0) + 1);
}
function flagEntry(e, kind, headline, cause) {
  if (!e.flagged) e.flagged = { kind, headline, causes: [] };
  e.flagged.causes.push(cause);
}
async function pkceS256(verifier) {
  const cr = globalThis.crypto;
  if (!(cr && cr.subtle)) return null;
  const d = await cr.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  let s = ''; for (const b of new Uint8Array(d)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function clientAuthMethod(tk) {
  const q = tk.tokenReq || {};
  if (/^basic /i.test(hdr((tk.raw.request || {}).headers, 'authorization'))) return 'client_secret_basic (secret in an HTTP Basic header)';
  if (q.client_secret) return 'client_secret_post (secret in the request body)';
  if (q.client_assertion) return 'private_key_jwt (signed client assertion)';
  return 'none (public client, client_id only)';
}
function oauthFixes(error, grant) {
  switch (error) {
    case 'invalid_grant':
      if (grant === 'refresh_token') return ['Send the user through interactive sign-in again to get a new refresh token.', 'If refresh tokens rotate, always store and use the newest one and avoid parallel refreshes.'];
      if (grant === 'password') return ['Check the username and password; accounts that need MFA or consent cannot use the password grant.'];
      return ['Redeem the code once, immediately, with the same redirect_uri and client_id and the matching code_verifier.'];
    case 'invalid_client': return ['Check the client_id and secret (use the secret’s value, not its ID; make sure it has not expired) and the client authentication method configured at the identity provider.'];
    case 'unauthorized_client': case 'unsupported_response_type': return ['Enable this grant / response type for the app at the identity provider, or use the flow the app is registered for.'];
    case 'invalid_scope': return ['Request only scopes defined for this API, spelled exactly as configured (including any API URI prefix).'];
    case 'access_denied': return ['Check the user’s consent, app assignment and Conditional Access / sign-in policies in the identity provider’s sign-in logs.'];
    case 'login_required': case 'interaction_required': return ['Fall back to interactive sign-in (redirect or popup) when silent renewal fails. Silent renewal in an iframe fails when third-party cookies are blocked; prefer refresh tokens.'];
    case 'consent_required': return ['Have the user, or an administrator, grant consent for the requested permissions.'];
    default: return [];
  }
}
function grantHint(grant) {
  if (grant === 'authorization_code') return ' An authorization code is single-use and short-lived (typically 1–10 minutes), and must be redeemed with the same redirect_uri and client_id and the matching PKCE code_verifier.';
  if (grant === 'refresh_token') return ' A refresh token may have expired (absolute or inactivity lifetime), been revoked (sign-out, password change, admin action), or been replaced by rotation (an older refresh token reused after a newer one was issued).';
  if (grant === 'password') return ' For the password grant this means the username or password is wrong, or the account requires MFA or consent, which this grant cannot handle.';
  return '';
}
function aadstsCause(text) {
  const m = /AADSTS(\d+)/.exec(text || ''); if (!m) return null;
  const d = AADSTS[m[1]];
  return { conf: d ? 'high' : 'likely', id: 'aadsts_' + m[1], title: 'Microsoft Entra ID error AADSTS' + m[1] + (d ? ': ' + d : ''), detail: text, fixes: d ? [] : ['Look up AADSTS' + m[1] + ' in Microsoft’s Entra ID error code reference.'] };
}
function oauthErrorCause(error, desc, grant) {
  const k = OAUTH_ERR[error];
  return { conf: 'high', id: 'oauth_' + error, title: (k ? k.t : 'Sign-in error "' + error + '"') + (desc ? ': ' + desc : ''), detail: (k ? k.d : '') + (error === 'invalid_grant' ? grantHint(grant) : ''), fixes: oauthFixes(error, grant) };
}

/* ---------- OAuth 2.0 / OpenID Connect ---------- */
async function detectOAuth(byTime) {
  const authz = [], toks = [], usedCodes = new Map(), byClient = new Map();
  for (const e of byTime) {
    if (!e.u) continue;
    const q = e.u.searchParams;
    if (q.get('client_id') && q.get('response_type')) { e.oauthRole = 'authorize'; authz.push(e); continue; }
    const b = e.method === 'POST' ? bodyParams(e) : null;
    if (b && typeof b.grant_type === 'string') {
      e.oauthRole = 'token'; e.tokenReq = b; toks.push(e);
      for (const [k, v] of Object.entries(b)) if (SECRET_FIELD.test(k) && typeof v === 'string') secret(v);
    }
    if (/\.well-known\/(openid-configuration|oauth-authorization-server)|\/jwks(\.json)?(\?|$)|\/discovery\/(v2\.0\/)?keys|\/oauth2\/(v1\/)?keys/i.test(e.url) && (e.status >= 400 || e.status === 0)) e.idpMetaFail = true;
  }
  for (const a of authz) {
    const p = Object.fromEntries(a.u.searchParams);
    const flow = { kind: 'oauth', title: 'OAuth 2.0' + (/(^|\s)openid(\s|$)/.test(p.scope || '') ? ' / OpenID Connect' : '') + ' sign-in', idp: a.u.host, client_id: p.client_id, steps: [{ e: a, label: 'Authorization request (response_type=' + p.response_type + (p.prompt ? ', prompt=' + p.prompt : '') + (p.response_mode ? ', response_mode=' + p.response_mode : '') + ')' }], checks: [] };
    A.flows.push(flow); a.flow = flow;
    if (!byClient.has(p.client_id)) byClient.set(p.client_id, []);
    byClient.get(p.client_id).push(a);
    addMethod(a.u.host, 'OAuth 2.0 / OIDC sign-in', a);
    const ru = p.redirect_uri ? noQuery(p.redirect_uri) : null;
    let back = null, cb = null;
    if (ru) for (const x of byTime) {
      if (x.start < a.start) continue;
      if (x.start - a.start > 600000) break;
      const loc = hdr((x.raw.response || {}).headers, 'location');
      if (loc && noQuery(absUrl(loc, x.url)) === ru) { back = x; cb = urlParamsAll(absUrl(loc, x.url)); break; }
      if (x !== a && x.method === 'POST' && noQuery(x.url) === ru) { const b = bodyParams(x) || {}; if (b.code || b.error || b.id_token) { back = x; cb = b; break; } }
      if (x !== a && noQuery(x.url) === ru && /[?&](code|error)=/.test(x.url)) { back = x; cb = urlParamsAll(x.url); break; }
    }
    if (!back) { flow.checks.push({ ok: null, label: 'Did not return to the redirect_uri in this HAR', detail: 'The user may not have finished signing in, or the capture stopped early.' }); continue; }
    if (cb.code) secret(cb.code);
    flow.steps.push({ e: back, label: cb.error ? 'Identity provider sent the browser back with error "' + cb.error + '"' : 'Identity provider sent the browser back to the app' + (cb.code ? ' with an authorization code' : cb.id_token || cb.access_token ? ' with tokens' : '') });
    if (noQuery(back.url) !== ru) {
      const land = byTime.find(x => x !== back && x.start >= back.start && x.start - back.start < 120000 && noQuery(x.url) === ru);
      if (land) flow.steps.push({ e: land, label: 'Browser lands on the app’s redirect_uri' + (land.status >= 400 || land.status === 0 ? ' (failed: ' + (land.status || 'no response') + ')' : '') });
    }
    if (cb.error) {
      flow.checks.push({ ok: false, label: 'Identity provider returned error ' + cb.error, detail: cb.error_description || '' });
      flagEntry(back, 'OAuth sign-in', 'Sign-in error: ' + cb.error, oauthErrorCause(cb.error, cb.error_description, ''));
      const ad = aadstsCause(cb.error_description); if (ad) flagEntry(back, 'OAuth sign-in', '', ad);
    }
    if (p.state) {
      if (!cb.state) { flow.checks.push({ ok: false, label: 'state missing from the response' }); flagEntry(back, 'OAuth sign-in', 'State missing', { conf: 'likely', id: 'state_missing', title: 'The identity provider did not return the state parameter', detail: 'The app sent state="' + p.state + '" but the response has none, so the app cannot verify the sign-in.', fixes: ['Check the identity provider configuration and any proxy that rewrites the redirect.'] }); }
      else if (cb.state !== p.state) { flow.checks.push({ ok: false, label: 'state does not match', detail: 'sent "' + p.state + '", got "' + cb.state + '"' }); flagEntry(back, 'OAuth sign-in', 'State mismatch', { conf: 'high', id: 'state_mismatch', title: 'The state returned does not match the state sent', detail: 'Sent "' + p.state + '", got back "' + cb.state + '". Apps reject this to prevent CSRF. It usually means the sign-in was started in another tab, the stored state was lost (storage cleared, a different subdomain or port), or the back button was used.', fixes: ['Keep state in storage that survives the redirect on the same origin, and start only one sign-in at a time.'] }); }
      else flow.checks.push({ ok: true, label: 'state matches' });
    }
    if (cb.error) continue;
    const tok = toks.find(x => x.start >= back.start && x.tokenReq.grant_type === 'authorization_code' && !x.flow && (cb.code ? x.tokenReq.code === cb.code : x.tokenReq.client_id === p.client_id));
    if (!tok) { if (cb.code) flow.checks.push({ ok: null, label: 'The authorization code was not redeemed in this HAR', detail: 'A server-side (confidential) client redeems the code from its backend, which a browser HAR does not capture.' }); continue; }
    const q = tok.tokenReq; tok.flow = flow;
    flow.steps.push({ e: tok, label: 'Token request (authorization_code) → ' + (tok.status >= 400 || tok.status === 0 ? 'failed with HTTP ' + (tok.status || 'error') : 'tokens issued') });
    addMethod(tok.host, 'OAuth 2.0 token endpoint', tok);
    const fc = [];
    const fail = (conf, id, label, detail, fixes) => fc.push({ ok: false, label, detail, cause: { conf, id, title: label, detail, fixes: fixes || [] } });
    if (q.code) { const prior = usedCodes.get(q.code); if (prior) fail('high', 'code_reused', 'The authorization code was already redeemed by #' + prior.i, 'Codes are single-use. The second redemption fails, and many identity providers also revoke the tokens from the first.', ['Make sure the callback handler runs only once (React StrictMode double effects, reloads, two tabs).']); usedCodes.set(q.code, tok); }
    if (p.redirect_uri) {
      if (!q.redirect_uri) fail('likely', 'redirect_uri_missing', 'redirect_uri missing from the token request', 'The authorization request included redirect_uri, so the token request must send the same value.', ['Send redirect_uri with the token request, identical to the one in the authorization request.']);
      else if (q.redirect_uri !== p.redirect_uri) fail('high', 'redirect_uri_mismatch', 'redirect_uri differs between the authorization and token requests', 'Authorization request: ' + p.redirect_uri + '\nToken request: ' + q.redirect_uri + '\nThey must match exactly, character for character.', ['Use exactly the same redirect_uri in both requests.']);
      else fc.push({ ok: true, label: 'redirect_uri matches' });
    }
    if (q.client_id && p.client_id && q.client_id !== p.client_id) fail('high', 'client_id_mismatch', 'client_id differs between the authorization and token requests', p.client_id + ' vs ' + q.client_id, []);
    if (p.code_challenge) {
      if (!q.code_verifier) fail('high', 'pkce_missing', 'PKCE code_verifier missing from the token request', 'The authorization request sent a code_challenge, so the token request must include the matching code_verifier.', ['Store the code_verifier before redirecting and send it with the token request.']);
      else {
        const m = (p.code_challenge_method || 'plain').toUpperCase();
        const calc = m === 'S256' ? await pkceS256(q.code_verifier) : q.code_verifier;
        if (calc == null) fc.push({ ok: null, label: 'PKCE could not be checked here (Web Crypto unavailable)' });
        else if (calc !== p.code_challenge) fail('high', 'pkce_mismatch', 'PKCE code_verifier does not match the code_challenge', (m === 'S256' ? 'The SHA-256 of the code_verifier' : 'The code_verifier') + ' sent with the token request does not equal the code_challenge sent with the authorization request. The verifier was regenerated or lost between the redirect and the callback (storage cleared, another tab, or a second sign-in started).', ['Store the code_verifier before redirecting and read back the same value in the callback; do not start a second sign-in in between.']);
        else fc.push({ ok: true, label: 'PKCE code_verifier matches the code_challenge (' + m + ')' });
      }
    } else if (/code/.test(p.response_type || '')) fc.push({ ok: null, label: 'PKCE not used', detail: 'Single-page and mobile apps should use PKCE, and many identity providers require it.' });
    const age = entryTime(tok) - entryTime(back);
    if (age > 60000) fc.push({ ok: tok.status >= 400 ? false : null, label: 'Code redeemed ' + fmtDelta(age) + ' after it was issued', cause: tok.status >= 400 ? { conf: 'possible', id: 'code_slow', title: 'The code was redeemed ' + fmtDelta(age) + ' after it was issued', detail: 'Authorization codes usually expire within 1–10 minutes.', fixes: ['Redeem the code immediately in the callback.'] } : null });
    fc.push({ ok: null, label: 'Client authentication: ' + clientAuthMethod(tok) });
    if (tok.tokenResponse) {
      const idt = [...A.tokens.values()].find(t => t.kinds.has('id') && t.issued.includes(tok));
      if (p.nonce && idt && idt.jwt && idt.jwt.payload) {
        if (idt.jwt.payload.nonce !== p.nonce) fail('high', 'nonce_mismatch', 'The ID token nonce does not match the authorization request', 'Sent nonce "' + p.nonce + '", ID token has "' + (idt.jwt.payload.nonce ?? '(none)') + '". The app will reject the ID token (replay protection).', ['Keep the nonce in storage that survives the redirect and compare it with the same sign-in’s ID token.']);
        else fc.push({ ok: true, label: 'ID token nonce matches' });
      }
      if (tok.tokenResponse.scope && p.scope) {
        const granted = new Set(String(tok.tokenResponse.scope).split(/\s+/));
        const missing = p.scope.split(/\s+/).filter(s => s && !granted.has(s) && !/^(openid|offline_access)$/.test(s));
        fc.push(missing.length ? { ok: null, label: 'Requested but not granted: ' + missing.join(', ') } : { ok: true, label: 'All requested scopes granted' });
      }
    }
    flow.checks.push(...fc);
    tok.flowChecks = fc;
    if (tok.status > 0 && tok.status < 400) for (const c of fc) if (c.cause && c.cause.id === 'nonce_mismatch') flagEntry(tok, 'OpenID Connect', 'ID token nonce mismatch', c.cause);
  }
  for (const tk of toks) {
    if (tk.flow) continue;
    const q = tk.tokenReq, checks = [{ ok: null, label: 'Client authentication: ' + clientAuthMethod(tk) }];
    if (q.client_assertion) {
      const j = parseJwt(q.client_assertion), t = entryTime(tk);
      if (j && j.payload) {
        if (typeof j.payload.exp === 'number' && j.payload.exp * 1000 <= t) checks.push({ ok: false, label: 'Client assertion expired ' + fmtDelta(t - j.payload.exp * 1000) + ' before use', cause: { conf: 'high', id: 'client_assertion_expired', title: 'The client assertion (private_key_jwt) had expired', detail: 'exp is ' + fmtDate(j.payload.exp * 1000) + '.', fixes: ['Create a fresh assertion for every token request.'] } });
        const aud = [].concat(j.payload.aud || []).map(String);
        if (aud.length && !aud.some(x => noQuery(x) === noQuery(tk.url) || (x.length > 8 && tk.url.startsWith(x)))) checks.push({ ok: false, label: 'Client assertion audience is not this token endpoint', detail: 'aud ' + aud.join(', '), cause: { conf: 'likely', id: 'client_assertion_aud', title: 'The client assertion audience does not match the token endpoint', detail: 'aud is ' + aud.join(', ') + ' but the assertion was sent to ' + noQuery(tk.url) + '.', fixes: ['Set aud to the token endpoint URL (or issuer) the identity provider documents.'] } });
      }
    }
    const fl = { kind: 'oauth', title: 'OAuth 2.0 token request (' + q.grant_type + ')', idp: tk.host, client_id: q.client_id || '', steps: [{ e: tk, label: q.grant_type + ' → ' + (tk.status >= 400 || tk.status === 0 ? 'failed with HTTP ' + (tk.status || 'error') : 'tokens issued') }], checks };
    tk.flow = fl; tk.flowChecks = checks; A.flows.push(fl);
    addMethod(tk.host, 'OAuth 2.0 token endpoint', tk);
  }
  for (const [cid, list] of byClient) if (list.length >= 3) list[list.length - 1].loginLoop = { count: list.length, client_id: cid, first: list[0], span: list[list.length - 1].start - list[0].start };
}

/* ---------- SAML 2.0 ---------- */
async function inflateRaw(bytes) {
  if (typeof DecompressionStream === 'undefined') return null;
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return await new Response(stream).text();
}
async function samlXml(val) {
  let b; try { b = b64ToBytes(val); } catch (_) { return null; }
  const t = utf8(b);
  if (/^\s*</.test(t)) return t;
  try { return await inflateRaw(b); } catch (_) { return null; }
}
function parseXml(t) {
  if (typeof DOMParser === 'undefined') return miniXml(t);
  const d = new DOMParser().parseFromString(t, 'application/xml');
  return d.getElementsByTagName('parsererror').length ? null : d;
}
const xq = (d, name) => d.getElementsByTagNameNS('*', name);
const xtext = (d, name) => { const n = xq(d, name)[0]; return n ? n.textContent.trim() : ''; };
async function detectSaml(byTime) {
  const reqs = new Map();
  for (const e of byTime) {
    const params = {};
    if (e.u) for (const k of ['SAMLRequest', 'SAMLResponse']) if (e.u.searchParams.get(k)) params[k] = e.u.searchParams.get(k);
    if (e.method === 'POST') { const b = bodyParams(e); if (b) for (const k of ['SAMLRequest', 'SAMLResponse']) if (typeof b[k] === 'string') params[k] = b[k]; }
    let idpUrl = params.SAMLRequest ? e.url : '';
    if (!params.SAMLRequest) {
      const loc = hdr((e.raw.response || {}).headers, 'location');
      if (loc && /[?&]SAMLRequest=/.test(loc)) { try { const lu = new URL(loc, e.url); params.SAMLRequest = lu.searchParams.get('SAMLRequest'); idpUrl = lu.href; } catch (_) { /* bad URL */ } }
    }
    for (const v of Object.values(params)) secret(v);
    if (params.SAMLRequest) {
      const xml = await samlXml(params.SAMLRequest), d = xml && parseXml(xml), ar = d && d.documentElement;
      if (ar && ar.localName === 'AuthnRequest') {
        const id = ar.getAttribute('ID');
        if (!reqs.has(id)) {
          const info = { id, issuer: xtext(d, 'Issuer'), acs: ar.getAttribute('AssertionConsumerServiceURL'), destination: ar.getAttribute('Destination'), isPassive: ar.getAttribute('IsPassive'), forceAuthn: ar.getAttribute('ForceAuthn'), e };
          const idpHost = (() => { try { return new URL(idpUrl).host; } catch (_) { return ''; } })();
          const flow = { kind: 'saml', title: 'SAML 2.0 sign-in', idp: idpHost, steps: [{ e, label: 'Service provider ' + (info.issuer || '?') + ' sent AuthnRequest ' + id + (idpHost ? ' to ' + idpHost : '') }], checks: [] };
          info.flow = flow; reqs.set(id, info); A.flows.push(flow);
          addMethod(idpHost, 'SAML 2.0 sign-in', e);
        }
      }
    }
    if (params.SAMLResponse) await analyzeSamlResponse(e, params.SAMLResponse, reqs);
  }
}
async function analyzeSamlResponse(e, val, reqs) {
  const xml = await samlXml(val), d = xml && parseXml(xml);
  if (!d) return;
  const root = d.documentElement, t = entryTime(e), short = v => String(v || '').split(':').pop();
  const sc = xq(d, 'StatusCode');
  const info = {
    status: sc[0] ? short(sc[0].getAttribute('Value')) : '', subStatus: sc[1] ? short(sc[1].getAttribute('Value')) : '', message: xtext(d, 'StatusMessage'),
    destination: root.getAttribute('Destination'), inResponseTo: root.getAttribute('InResponseTo'), issuer: xtext(d, 'Issuer'),
    encrypted: xq(d, 'EncryptedAssertion').length > 0, signed: xq(d, 'Signature').length > 0,
    audiences: [...xq(d, 'Audience')].map(x => x.textContent.trim()), nameId: xtext(d, 'NameID'),
  };
  const cond = xq(d, 'Conditions')[0], scd = xq(d, 'SubjectConfirmationData')[0];
  info.notBefore = cond ? Date.parse(cond.getAttribute('NotBefore')) : NaN;
  const ends = [cond && Date.parse(cond.getAttribute('NotOnOrAfter')), scd && Date.parse(scd.getAttribute('NotOnOrAfter'))].filter(x => isFinite(x));
  info.notOnOrAfter = ends.length ? Math.min(...ends) : NaN;
  info.recipient = scd ? scd.getAttribute('Recipient') : null;
  const req = info.inResponseTo ? reqs.get(info.inResponseTo) : null;
  let flow = req && req.flow;
  if (!flow) { flow = { kind: 'saml', title: 'SAML 2.0 sign-in (identity-provider-initiated, or the request was not captured)', idp: info.issuer, steps: [], checks: [] }; A.flows.push(flow); }
  const postUrl = noQuery(e.url);
  flow.steps.push({ e, label: 'SAMLResponse (status ' + (info.status || '?') + (info.subStatus ? ' / ' + info.subStatus : '') + ') posted to ' + postUrl + ' → service provider answered ' + (e.status || 'with a network error') });
  const checks = [], causes = [];
  const fail = (conf, id, label, detail, fixes) => { checks.push({ ok: false, label, detail }); causes.push({ conf, id, title: label, detail, fixes: fixes || [] }); };
  if (info.status && info.status !== 'Success') fail('high', 'saml_status', 'The identity provider returned status ' + info.status + (info.subStatus ? ' / ' + info.subStatus : ''), [SAML_STATUS[info.subStatus] || SAML_STATUS[info.status] || '', info.message ? 'Message: "' + info.message + '"' : ''].filter(Boolean).join(' '), ['Check the identity provider’s sign-in logs for this user and time.']);
  else if (info.status) checks.push({ ok: true, label: 'Status Success' + (info.nameId ? ' for ' + info.nameId : '') });
  if (info.destination && noQuery(info.destination) !== postUrl) fail('high', 'saml_destination', 'Destination does not match where the response was posted', 'Destination="' + info.destination + '", but it was posted to ' + postUrl + '. The service provider will reject it.', ['Make the ACS URL configured at the identity provider exactly match the service provider’s (scheme, host, port, path, trailing slash).']);
  else if (info.destination) checks.push({ ok: true, label: 'Destination matches the ACS URL' });
  if (info.recipient && noQuery(info.recipient) !== postUrl) fail('likely', 'saml_recipient', 'Recipient does not match where the response was posted', 'Recipient="' + info.recipient + '" vs ' + postUrl + '.', ['Fix the ACS URL at the identity provider.']);
  if (req) {
    checks.push({ ok: true, label: 'InResponseTo matches AuthnRequest ' + req.id });
    if (req.issuer && info.audiences.length && !info.audiences.includes(req.issuer)) fail('high', 'saml_audience', 'Audience does not match the service provider', 'The assertion is for ' + info.audiences.join(', ') + ', but the service provider identified itself as "' + req.issuer + '" in its AuthnRequest. Service providers reject assertions meant for another entity ID.', ['At the identity provider, set the service provider’s entity ID (Identifier / Audience URI) to exactly "' + req.issuer + '".']);
    else if (info.audiences.length) checks.push({ ok: true, label: 'Audience matches the service provider entity ID' });
    if (req.acs && noQuery(req.acs) !== postUrl) fail('likely', 'saml_acs', 'Posted to a different ACS URL than the service provider requested', 'Requested ' + req.acs + ', posted to ' + postUrl + '.', ['Align the ACS URL in the identity provider configuration.']);
  } else if (info.inResponseTo) fail('possible', 'saml_inresponseto', 'InResponseTo "' + info.inResponseTo + '" does not match an AuthnRequest in this HAR', 'If the service provider started the sign-in, it may have lost track of its request (its cookie was not sent on the cross-site POST, the sign-in started in another tab, or the service provider restarted).', ['Make the service provider’s request-tracking cookie SameSite=None; Secure.']);
  if (isFinite(info.notBefore) && info.notBefore > t + 60000) fail('likely', 'saml_notyet', 'The assertion is not valid yet (NotBefore is ' + fmtDelta(info.notBefore - t) + ' in the future)', 'The identity provider’s clock is ahead of this computer’s.', ['Sync clocks with NTP, or allow a few minutes of clock skew at the service provider.']);
  if (isFinite(info.notOnOrAfter) && info.notOnOrAfter <= t) fail('high', 'saml_expired', 'The assertion expired ' + fmtDelta(t - info.notOnOrAfter) + ' before it was posted', 'NotOnOrAfter is ' + fmtDate(info.notOnOrAfter) + '.', ['Check the clocks of identity provider and service provider; resubmitting an old response (back button) also causes this.']);
  else if (isFinite(info.notBefore) || isFinite(info.notOnOrAfter)) { if (!causes.some(c => c.id === 'saml_notyet')) checks.push({ ok: true, label: 'Within its validity window' }); }
  if (!info.signed) fail('possible', 'saml_unsigned', 'Neither the response nor the assertion is signed', 'Most service providers require a signature.', ['Enable response or assertion signing at the identity provider.']);
  if (info.encrypted) checks.push({ ok: null, label: 'Assertion is encrypted (its contents are not visible here)' });
  const err = errorInfo(e);
  const spRejected = e.status >= 400 || e.status === 0 || (e.status >= 300 && e.status < 400 && /error|fail|denied|login|signin/i.test(e.redirectTarget || ''));
  if (spRejected) {
    checks.push({ ok: false, label: 'Service provider rejected the response (HTTP ' + (e.status || 'error') + ')', detail: msgOf(err) });
    if (!causes.length) causes.push({ conf: 'possible', id: 'saml_rejected', title: 'The service provider rejected the SAML response', detail: 'Nothing in the response itself explains it. Common causes: the signature was checked against the wrong (rotated) identity provider certificate, an unexpected NameID format, missing required attributes, or the service provider’s cookie was not sent on the cross-site POST (SameSite).', fixes: ['Check the service provider’s logs, and compare the identity provider signing certificate with the one configured at the service provider.'] });
  } else checks.push({ ok: true, label: 'Service provider accepted the response' });
  flow.checks.push(...checks);
  e.saml = { info, failed: !!(info.status && info.status !== 'Success') || spRejected, causes };
  addMethod(e.host, 'SAML 2.0 (service provider)', e);
}

/* ---------- NTLM and Kerberos handshakes ---------- */
function detectNtlm(byTime) {
  const lastT2 = new Map();
  for (const e of byTime) {
    if (!e.auth) continue;
    const resTok = e.auth.ch.find(x => /^(ntlm|negotiate)$/i.test(x.scheme) && x.token);
    e.auth.resNeg = resTok ? parseNegotiate(resTok.token) : null;
    const c = e.auth.creds.find(x => x.neg && !x.proxy);
    if (!c) continue;
    const n = c.neg;
    if (n.ntlm && n.ntlm.type === 1 && e.auth.resNeg && e.auth.resNeg.ntlm && e.auth.resNeg.ntlm.type === 2) { lastT2.set(e.host, e); e.auth.ntlmTarget = e.auth.resNeg.ntlm.target; }
    if (n.ntlm && n.ntlm.type === 3) {
      const t2 = lastT2.get(e.host) || null;
      e.auth.ntlmT2 = t2;
      e.auth.ntlmSplit = !!(t2 && t2.connection && e.connection && t2.connection !== e.connection);
      const steps = [];
      if (t2) {
        const pre = byTime.filter(x => x.host === t2.host && x.start < t2.start && x.status === 401 && x.auth && !x.auth.creds.length && t2.start - x.start < 30000).pop();
        if (pre) steps.push({ e: pre, label: 'Anonymous request → 401, server offers ' + pre.auth.ch.map(x => x.scheme).join(', ') });
        steps.push({ e: t2, label: 'NTLM negotiate (type 1) → server challenge (type 2)' + (t2.auth.ntlmTarget ? ' from ' + t2.auth.ntlmTarget : '') + ' on connection ' + (t2.connection || '?') });
      }
      steps.push({ e, label: 'NTLM authenticate (type 3) for ' + (n.ntlm.domain ? n.ntlm.domain + '\\' : '') + (n.ntlm.user || '(anonymous)') + ' on connection ' + (e.connection || '?') + ' → ' + (e.status || 'error') });
      const checks = [];
      if (t2) checks.push(e.auth.ntlmSplit ? { ok: false, label: 'Handshake split across connections (' + t2.connection + ' → ' + e.connection + ')', detail: 'NTLM authenticates the TCP connection, so all three messages must travel on the same one.' } : { ok: true, label: 'Challenge and response on the same connection' });
      else checks.push({ ok: null, label: 'Server challenge (type 2) not found in this HAR' });
      checks.push(n.ntlm.version === 'NTLMv1' ? { ok: false, label: 'NTLMv1 response', detail: 'Most servers require NTLMv2.' } : { ok: n.ntlm.version === 'NTLMv2' ? true : null, label: n.ntlm.version + ' response' });
      if (/^(h2|http\/2)/i.test(e.httpVersion)) checks.push({ ok: false, label: 'Sent over HTTP/2', detail: 'Connection-based authentication (NTLM, Kerberos) does not work over HTTP/2.' });
      checks.push(e.status > 0 && e.status < 400 ? { ok: true, label: 'Authenticated' } : { ok: false, label: 'Rejected with HTTP ' + (e.status || 'error') });
      A.flows.push({ kind: 'windows', title: 'NTLM handshake', idp: e.host, steps, checks });
    }
    if (n.mech === 'Kerberos') A.flows.push({ kind: 'windows', title: 'Kerberos (Negotiate)', idp: e.host, steps: [{ e, label: 'Kerberos ticket sent → ' + (e.status || 'error') + (e.auth.resNeg && e.auth.resNeg.negState ? ' (' + e.auth.resNeg.negState + ')' : '') }], checks: [e.status > 0 && e.status < 400 ? { ok: true, label: 'Authenticated with Kerberos' } : { ok: false, label: 'Rejected with HTTP ' + (e.status || 'error') }] });
  }
}

/* ---------- why did it fail? ---------- */
function credLabel(list) { return list.length ? list.map(c => c.label).join('; ') : 'none (no Authorization header, API key or session cookie)'; }
function claimsHint(sent) {
  const bits = [];
  for (const c of sent) if (c.jwt && c.jwt.payload) {
    const p = c.jwt.payload, sc = [].concat(p.scp || p.scope || []).join(' '), roles = [].concat(p.roles || []), groups = [].concat(p.groups || []);
    if (sc) bits.push('scopes: ' + sc); if (roles.length) bits.push('roles: ' + roles.join(', ')); if (groups.length) bits.push(groups.length + ' group(s)');
  }
  return bits.length ? 'The token carries ' + bits.join('; ') + '.' : '';
}
function jwtCauses(c, e, add) {
  const j = c.jwt; if (!j || !j.payload) return;
  const p = j.payload, t = entryTime(e), skew = A.skew.get(e.host) || 0, tok = tokenOf(c.token);
  const isId = tok && tok.kinds.has('id') && !tok.kinds.has('access');
  if (isId) add('high', 'id_token_as_access', 'An ID token was sent instead of an access token', 'This token was issued as the id_token by #' + tok.issued[0].i + '. ID tokens tell the app who signed in, and their audience is the app’s own client_id (' + [].concat(p.aud || []).join(', ') + '). APIs expect the access_token.', ['Send the access_token from the token response in the Authorization header, not the id_token.']);
  else if (p.nonce && !(tok && tok.kinds.has('access'))) add('likely', 'id_token_as_access', 'This looks like an ID token, not an access token', 'It carries a nonce claim, which ID tokens have and access tokens normally do not.', ['Send the access_token instead of the id_token.']);
  if (typeof p.exp === 'number') {
    const exp = p.exp * 1000;
    if (exp <= t) add('high', 'jwt_expired', 'The token expired ' + fmtDelta(t - exp) + ' before this request', 'exp is ' + fmtDate(exp) + '; the request was sent at ' + fmtDate(t) + (tok && tok.issued.length ? '. It was issued by #' + tok.issued[0].i : '') + (typeof p.iat === 'number' ? ', with a lifetime of ' + fmtDelta(exp - p.iat * 1000) : '') + '.', ['Renew the token before it expires (from expires_in or exp), and on a 401 refresh once and retry.']);
    else if (skew > 0 && exp <= t + skew) add('likely', 'jwt_expired_skew', 'The token is expired by the server’s clock', 'By this computer’s clock it was still valid for ' + fmtDelta(exp - t) + ', but ' + e.host + ' runs about ' + fmtDelta(skew) + ' ahead.', ['Fix the clock (NTP) on the server or client, or renew tokens earlier.']);
  }
  if (typeof p.nbf === 'number' && p.nbf * 1000 > t + skew + 60000) add('likely', 'jwt_nbf', 'The token is not valid yet (nbf is in the future)', 'nbf is ' + fmtDate(p.nbf * 1000) + ', ' + fmtDelta(p.nbf * 1000 - t) + ' after the request: the token issuer’s clock is ahead.', ['Sync clocks (NTP) on the identity provider and the API servers, or allow a little clock skew.']);
  if (String(j.header.alg).toLowerCase() === 'none') add('likely', 'jwt_alg_none', 'The token is unsigned (alg "none")', 'Servers reject unsigned tokens.', []);
  const auds = [].concat(p.aud || []).map(String);
  const want = e.u ? expectedToken(e.u.host) : null;
  if (want && !isId) {
    if (want.issuer && p.iss && p.iss !== want.issuer) add('high', 'jwt_issuer_mismatch', 'The token was issued by ' + p.iss + ', but this API expects ' + want.issuer, 'From your settings for ' + want.hosts.join(', ') + '. A token from another tenant, realm or environment (e.g. staging vs. production) is rejected even when it is otherwise valid.', ['Sign in against the identity provider this API trusts (' + want.issuer + ').']);
    if (want.audience.length && auds.length && !auds.some(a => want.audience.includes(a))) add('high', 'jwt_audience_mismatch', 'The token is for ' + auds.join(', ') + ', but this API expects ' + want.audience.join(' or '), 'From your settings for ' + want.hosts.join(', ') + '. The app requested a token for a different API (wrong scope or resource).', ['Request the token with this API’s scope / resource (' + want.audience.join(', ') + ').']);
  } else if (auds.length && e.u && !isId) {
    const host = e.u.hostname.toLowerCase();
    const looksLikeHost = auds.every(x => /^[a-z][\w+.-]*:\/\/|^[\w-]+(\.[\w-]+)+$/i.test(x));
    const match = auds.some(x => { const h = ((/^[a-z][\w+.-]*:\/\/([^/:]+)/i.exec(x) || [null, x])[1] || '').toLowerCase(); return h === host || siteOf(h) === siteOf(host); });
    if (looksLikeHost && !match) add('possible', 'jwt_audience', 'The token’s audience may not be this API', 'aud is ' + auds.join(', ') + ', but the request went to ' + host + '.', ['Request the token for this API’s audience / scope rather than another API’s.']);
  }
}
function scopeCause(required, sent, add, desc) {
  const have = new Set(); for (const c of sent) for (const s of scopesOf(c.jwt && c.jwt.payload)) have.add(s);
  const need = String(required || '').split(/\s+/).filter(Boolean), missing = need.filter(s => !have.has(s));
  add('high', 'insufficient_scope', 'The token lacks the required scope' + (missing.length ? ': ' + missing.join(', ') : ''), [desc ? desc + '.' : '', need.length ? 'Required: ' + need.join(' ') + '.' : '', have.size ? 'The token has: ' + [...have].join(' ') + '.' : ''].filter(Boolean).join(' '), ['Request the missing scope at sign-in, and make sure the app is allowed and consented to receive it.', 'If it is already requested, check the user’s or app’s granted permissions and roles.']);
}
function bearerChallenge(ch, sent, add, has) {
  const b = ch.find(c => /^(bearer|dpop)$/i.test(c.scheme) && c.params.error);
  if (!b) return;
  const er = b.params.error, d = b.params.error_description || '';
  if (er === 'invalid_token') {
    if (/expir/i.test(d)) { if (!has('jwt_expired') && !has('jwt_expired_skew')) add('high', 'bearer_expired', 'The server says the access token expired', 'WWW-Authenticate: ' + challengeText(b), ['Renew the token before it expires, and on a 401 refresh once and retry.']); }
    else add('high', 'bearer_invalid', 'The server rejected the access token (invalid_token)' + (d ? ': ' + d : ''), BEARER_ERR.invalid_token, ['Decode the token (see Tokens below) and compare iss, aud and exp with what this API expects.']);
  } else if (er === 'insufficient_scope') scopeCause(b.params.scope, sent, add, d);
  else if (er === 'invalid_request') add('likely', 'bearer_invalid_request', 'The server says the request was malformed (invalid_request)' + (d ? ': ' + d : ''), BEARER_ERR.invalid_request, []);
  else add('likely', 'bearer_other', 'The server returned error "' + er + '"' + (d ? ': ' + d : ''), '', []);
}
function noCredCauses(e, add) {
  if (A.sanitized) { add('possible', 'sanitized', 'No credentials are visible, but this HAR looks sanitized', 'No request in this HAR has an Authorization or Cookie header and no response sets a cookie. Chrome’s “Export HAR (sanitized)” and some tools strip these, so it is impossible to tell whether credentials were sent.', ['Re-capture the HAR with sensitive data included (and use Export → Redacted HAR here before sharing it).']); return; }
  const prev = e.redirectFrom;
  const crossRedirect = prev && prev.u && e.u && prev.u.origin !== e.u.origin;
  if (crossRedirect && prev.auth && prev.auth.creds.some(c => c.header === 'Authorization')) add('high', 'header_dropped_redirect', 'The Authorization header was dropped on a cross-origin redirect', '#' + prev.i + ' to ' + prev.u.origin + ' carried ' + credLabel(prev.auth.creds.filter(c => c.header === 'Authorization')) + ' and was redirected to ' + e.u.origin + '. Browsers and most HTTP clients remove the Authorization header when a redirect leaves the original origin, so this request arrived without credentials.', ['Call the final URL directly with the token, or have the first server return the content instead of redirecting.', 'If the redirect target is meant to work without the header, give it its own credential (for example a short-lived signed URL).']);
  const earlier = (idx().byHost.get(e.host) || []).filter(x => x.start < e.start && x.auth && x.auth.creds.some(c => c.header === 'Authorization' && !c.proxy));
  if (earlier.length && !crossRedirect) {
    const last = earlier[earlier.length - 1], m = last.auth.creds.find(c => c.header === 'Authorization');
    add('likely', 'header_missing', 'This request did not carry the Authorization header that earlier requests used', earlier.length + ' earlier request(s) to ' + e.host + ' sent ' + m.method + ' (most recently #' + last.i + '); this one sent none.', ['Check that the HTTP client or interceptor attaches the token to this call (URL filters, a second client instance, a call made before the token was loaded).', 'Requests made by <img>, <a>, <form>, window.open, EventSource or WebSocket cannot carry an Authorization header; use a cookie or a signed URL for those.']);
  }
  const sentNames = new Set(requestCookies(e).keys()), t = entryTime(e), latest = new Map();
  for (const c of A.jar) if (c.at < t && SESSION_COOKIE.test(c.name) && cookieApplies(c, e)) latest.set(c.name + '|' + (c.domain || c.host) + '|' + (c.path || ''), c);
  for (const c of latest.values()) {
    if (sentNames.has(c.name)) continue;
    const why = cookieWhyNotSent(c, e);
    add(why.conf, 'cookie_' + why.id, 'The session cookie "' + c.name + '" was not sent: ' + why.short, 'It was set by #' + c.e.i + ' (' + setCookieSummary(c) + '). ' + why.text, why.fixes);
  }
}
function credCauses(c, e, add, mode, err) {
  const t = entryTime(e), a = e.auth;
  if (c.jwt) jwtCauses(c, e, add);
  if (c.presign && isFinite(c.presign.expires) && c.presign.expires <= t) add('high', 'presign_expired', 'The presigned URL expired ' + fmtDelta(t - c.presign.expires) + ' before it was used', 'It was signed at ' + fmtDate(c.presign.signed) + ' with X-Amz-Expires=' + c.presign.seconds + ' s, so it was valid until ' + fmtDate(c.presign.expires) + '. It was requested at ' + fmtDate(t) + '.' + (c.presign.temp ? ' It was signed with temporary credentials, which also end the URL’s validity when they expire.' : ''), ['Generate the presigned URL right before it is used, or sign it with a longer expiry.']);
  if (c.sas) {
    if (isFinite(c.sas.expiry) && c.sas.expiry <= t) add('high', 'sas_expired', 'The SAS token expired ' + fmtDelta(t - c.sas.expiry) + ' before it was used', 'se=' + fmtDate(c.sas.expiry) + '.', ['Issue a new SAS with a later expiry (se).']);
    else if (isFinite(c.sas.start) && c.sas.start > t + 60000) add('likely', 'sas_not_yet', 'The SAS token is not valid yet (st is in the future)', 'st=' + fmtDate(c.sas.start) + ', ' + fmtDelta(c.sas.start - t) + ' after the request (clock skew where it was generated?).', ['Omit st, or set it a few minutes in the past.']);
  }
  if (mode === 403) return;
  if (c.method === 'HTTP Basic') {
    if (c.pwLen === 0) add('high', 'basic_empty_password', 'An empty password was sent for "' + c.user + '"', 'The Basic credentials decode to a user name with no password.', ['Check where the client gets the password from (configuration, environment variable, prompt).']);
    else add('likely', 'basic_rejected', 'The server rejected the user name or password for "' + (c.user ?? '?') + '"', 'HTTP Basic credentials were sent' + (a.ch[0] && a.ch[0].params.realm ? ' for realm "' + a.ch[0].params.realm + '"' : '') + ' and the server answered 401 again.' + (c.user && c.user.includes('\\') ? ' The user name is in DOMAIN\\user form; some servers expect user@domain instead.' : ''), ['Check the user name, password and account status (locked, expired password, MFA-only accounts cannot use Basic).']);
  } else if (c.method === 'HTTP Digest') {
    const ch = a.ch.find(x => /^digest$/i.test(x.scheme));
    const sa = String(ch && ch.params.algorithm || 'MD5').toUpperCase(), ca = String(c.params && c.params.algorithm || 'MD5').toUpperCase();
    if (ch && sa !== ca) add('likely', 'digest_algorithm', 'Digest algorithm mismatch (server wants ' + sa + ', client used ' + ca + ')', '', ['Use a client that supports ' + sa + ' Digest.']);
    else add('likely', 'digest_rejected', 'The server rejected the Digest credentials for "' + (c.user || '?') + '"', '', ['Check the user name and password, and that the realm matches.']);
  } else if (c.neg) {
    const n = c.neg;
    if (n.ntlm && n.ntlm.type === 3) {
      if (a.ntlmSplit) add('high', 'ntlm_split', 'The NTLM handshake was split across connections', 'The server challenge (type 2) came on connection ' + a.ntlmT2.connection + ' (#' + a.ntlmT2.i + ') but the response (type 3) was sent on connection ' + e.connection + '. NTLM authenticates a single TCP connection, so the server cannot match the response to its challenge. Typical causes: a load balancer or proxy without connection affinity, a proxy that pools or closes connections, or keep-alive disabled.', ['Enable session/connection affinity on the load balancer (or pass connections straight through).', 'Prefer Kerberos, which is not tied to a connection.']);
      if (n.ntlm.version === 'NTLMv1') add('likely', 'ntlm_v1', 'The client sent an NTLMv1 response, which the server probably refuses', 'Modern Windows servers require NTLMv2 (LmCompatibilityLevel 3 or higher).', ['Configure the client to use NTLMv2.']);
      if (!n.ntlm.user) add('likely', 'ntlm_anonymous', 'Anonymous NTLM: no user credentials were offered', 'The browser did not offer the signed-in Windows user, typically because the site is not trusted for integrated authentication (Intranet zone, AuthServerAllowlist).', ['Add the site to the Intranet zone or the browser’s integrated-authentication allow list.']);
      if (!a.ntlmSplit && n.ntlm.user) add('likely', 'ntlm_rejected', 'The server rejected the Windows credentials for ' + (n.ntlm.domain ? n.ntlm.domain + '\\' : '') + n.ntlm.user, 'The handshake completed but the server refused the user (wrong password, locked or disabled account, wrong domain, or not allowed on this site).', ['Check the account in Active Directory and the site’s authorization rules.']);
    } else if (n.mech === 'Kerberos') {
      const sk = Math.abs(A.skew.get(e.host) || 0);
      if (sk > 300000) add('high', 'kerberos_skew', 'Clock difference over 5 minutes breaks Kerberos', e.host + ' differs from this computer by ' + fmtDelta(sk) + '.', ['Sync clocks with the domain (NTP).']);
      add('likely', 'kerberos_rejected', 'The server rejected the Kerberos ticket', 'Common causes: the SPN (HTTP/' + (e.u ? e.u.hostname : 'host') + ') is missing, duplicated or registered to another account; the site is reached by a CNAME or IP address; or the service account’s keys changed.' + (a.resNeg && a.resNeg.negState === 'reject' ? ' The server’s Negotiate reply says "reject".' : ''), ['Check the SPN with setspn -Q HTTP/' + (e.u ? e.u.hostname : 'host') + ', and the server’s security event log.']);
    } else if (c.scheme && /^negotiate$/i.test(c.scheme) && n.mech === 'NTLM') add('possible', 'kerberos_fallback', 'Kerberos was not used: the client fell back to NTLM', 'Usually the SPN is missing, the host name is not in the Intranet zone, or the client is not domain-joined.', []);
    if (/^(h2|http\/2)/i.test(e.httpVersion)) add('possible', 'ntlm_http2', 'Windows authentication over HTTP/2', 'NTLM and Kerberos are connection-based and do not work over HTTP/2; IIS normally falls back to HTTP/1.1.', ['Disable HTTP/2 for this site or switch to a token-based method.']);
  } else if (c.method === 'API key' || /^API token/.test(c.method)) add('likely', 'api_key_rejected', 'The server rejected the API key', 'It was sent as ' + c.label + '.' + (msgOf(err) ? ' Server: "' + msgOf(err) + '"' : ''), ['Check that the key is correct, active, not expired, allowed for this API/project, and not restricted to other referrers, IP addresses or apps.']);
  else if (c.method === 'Session cookie' && !c.jwt) add('likely', 'session_invalid', 'The session cookie was sent but the server no longer accepts it', 'The request carried ' + c.cookies.join(', ') + '. The session expired or was ended (sign-out, password change, idle timeout), or the server lost it (restart or deploy without a shared session store, or a load balancer without sticky sessions sent the request to another server).', ['Sign in again, and check the session lifetime and idle timeout.', 'If it happens soon after signing in, check the session store and load-balancer affinity.']);
  else if (/^Bearer token \(opaque\)/.test(c.method)) add('possible', 'bearer_opaque_rejected', 'The opaque access token was rejected', 'Opaque tokens cannot be decoded here; it may be expired, revoked, or meant for another API.', ['Use the identity provider’s token introspection endpoint to check it.']);
  else if (/^Custom/.test(c.method) || c.method === 'Hawk' || c.method === 'OAuth 1.0a') add('possible', 'custom_rejected', 'The server rejected the ' + c.method + ' credentials', '', []);
}
function findRetry(e) {
  const u = noQuery(e.url);
  return sameUrl(e).find(x => x !== e && x.start > e.start && x.start - e.start < 300000 && x.method === e.method && noQuery(x.url) === u);
}
function classifyAuth(e) {
  const req = e.raw.request || {}, a = e.auth || { creds: [], ch: [], pch: [] };
  if (!e.auth) e.auth = a;
  if (e.method === 'OPTIONS' && hdr(req.headers, 'access-control-request-method') && e.status !== 401) return null;
  const sent = a.creds.filter(c => !c.proxy), st = e.status, causes = [], evidence = [];
  const add = (conf, id, title, detail, fixes) => { if (!causes.some(c => c.id === id)) causes.push({ conf, id, title, detail: detail || '', fixes: fixes || [] }); };
  const has = id => causes.some(c => c.id === id);
  const highCount = () => causes.filter(c => c.conf === 'high').length;
  let kind = '', headline = '', normal = false;
  const err = (st >= 400 || st === 0 || (st === 200 && e.type === 'xhr')) ? errorInfo(e) : {};
  let loginRedirect = false;
  if (st >= 300 && st < 400 && e.redirectTarget) { try { loginRedirect = LOGIN_RE.test(new URL(e.redirectTarget).pathname); } catch (_) { /* bad URL */ } }

  if (e.flagged) { kind = e.flagged.kind; headline = e.flagged.headline || e.flagged.causes[0].title; for (const c of e.flagged.causes) add(c.conf, c.id, c.title, c.detail, c.fixes); }
  else if (e.oauthRole === 'token' && (st >= 400 || st === 0)) {
    const q = e.tokenReq || {}, er = err.error || '';
    kind = 'OAuth token request'; headline = 'Token request (' + q.grant_type + ') failed' + (er ? ': ' + er : ' with HTTP ' + (st || 'error'));
    for (const c of (e.flowChecks || [])) if (c.ok === false && c.cause) add(c.cause.conf, c.cause.id, c.cause.title, c.cause.detail, c.cause.fixes);
    const ad = aadstsCause(err.description); if (ad) add(ad.conf, ad.id, ad.title, ad.detail, ad.fixes);
    if (er) { const oc = oauthErrorCause(er, err.description, q.grant_type); if (er === 'invalid_client') oc.detail += ' This client used ' + clientAuthMethod(e) + '.'; add(highCount() ? 'likely' : oc.conf, oc.id, oc.title, oc.detail, oc.fixes); }
    else add('possible', 'oauth_http', 'The token request failed with HTTP ' + (st || 'error'), msgOf(err), []);
  }
  else if (e.saml && e.saml.failed) { kind = 'SAML sign-in'; headline = e.saml.info.status && e.saml.info.status !== 'Success' ? 'SAML sign-in failed at the identity provider (' + e.saml.info.status + ')' : 'SAML response rejected by the service provider'; for (const c of e.saml.causes) add(c.conf, c.id, c.title, c.detail, c.fixes); }
  else if (st === 0 && /CLIENT_AUTH_CERT|SSL_CLIENT_AUTH|CLIENT_CERT/i.test(e.error)) { kind = 'Client certificate'; headline = 'TLS client certificate error'; add('high', 'client_cert', 'The server requires a client certificate (mutual TLS)', 'The TLS handshake failed with ' + e.error + ': the server asked for a client certificate and the browser had none, the certificate prompt was cancelled, or the certificate was rejected (expired, untrusted issuer, missing intermediate).', ['Install the client certificate and its private key in the OS / browser certificate store.', 'Check that the certificate is valid and issued by a CA the server trusts.']); }
  else if (st === 495 || st === 496) { kind = 'Client certificate'; headline = st + ' ' + (e.statusText || (st === 496 ? 'SSL Certificate Required' : 'SSL Certificate Error')); add('high', 'client_cert', st === 496 ? 'No client certificate was presented' : 'The client certificate was rejected', st === 496 ? 'The server (or its TLS proxy) requires mutual TLS and the client did not send a certificate.' : 'The client certificate is invalid, expired, revoked or from an untrusted issuer.', ['Install / select a valid client certificate.']); }
  else if (st === 511) { kind = 'Network login'; headline = '511 Network Authentication Required'; add('high', 'captive_portal', 'The network requires you to sign in (captive portal)', 'A hotel/guest Wi-Fi portal or a proxy is intercepting requests until you sign in to the network.', ['Open any http:// page in a browser and complete the network sign-in.']); }
  else if (st === 407) {
    kind = 'Proxy authentication'; headline = '407 Proxy Authentication Required';
    const schemes = a.pch.map(c => c.scheme).join(', ') || 'no Proxy-Authenticate header', pc = a.creds.filter(c => c.proxy);
    if (!pc.length) add('high', 'proxy_required', 'A proxy requires authentication (' + schemes + ')', 'A proxy between this client and ' + e.host + ' asked for credentials and none were sent.' + (/negotiate|ntlm/i.test(schemes) ? ' It offers Windows integrated authentication (Negotiate/NTLM), which needs a domain-joined machine and a client that supports it.' : ''), ['Configure proxy credentials in the OS, browser or application.', 'Check the proxy / PAC settings, or ask IT to allow this destination without authentication.']);
    else add('likely', 'proxy_rejected', 'The proxy rejected the credentials', pc.map(c => c.label).join('; '), ['Check the proxy user name, password or domain account.']);
  }
  else if (st === 401) {
    kind = 'Authentication'; headline = '401 ' + (e.statusText || 'Unauthorized');
    if (e.method === 'OPTIONS' && hdr(req.headers, 'access-control-request-method')) add('high', 'preflight_auth', 'The server demands credentials on the CORS preflight', 'Browsers never send credentials (Authorization, cookies) with an OPTIONS preflight, so a 401 here always fails and the real request is never sent.', ['Let OPTIONS requests through without authentication at the server or API gateway.']);
    for (const c of sent) if (c.jwt) jwtCauses(c, e, add);
    bearerChallenge(a.ch, sent, add, has);
    if (!sent.length && !has('preflight_auth')) noCredCauses(e, add);
    else {
      const schemes = a.ch.map(c => c.scheme.toLowerCase()), sentSchemes = sent.filter(c => c.scheme).map(c => c.scheme.toLowerCase());
      const fam = s => s === 'ntlm' || s === 'negotiate' ? 'windows' : s === 'dpop' ? 'bearer' : s;
      if (schemes.length && sentSchemes.length && !sentSchemes.some(s => schemes.map(fam).includes(fam(s)))) add('likely', 'scheme_mismatch', 'The server expects ' + a.ch.map(c => c.scheme).join(' or ') + ' but the client sent ' + sent.filter(c => c.scheme).map(c => c.scheme).join(', '), 'The credentials are of a type this endpoint does not accept.', ['Use the authentication method the endpoint advertises in WWW-Authenticate.']);
      for (const c of sent) credCauses(c, e, add, 401, err);
    }
  }
  else if (st === 403) {
    kind = 'Authorization'; headline = '403 ' + (e.statusText || 'Forbidden');
    const waf = wafVendor(e, err);
    if (waf) add('high', 'waf', 'Blocked by ' + waf + ', not an authentication problem', 'The response comes from ' + waf + ' (security rules, bot protection, IP reputation or geo-blocking) rather than from the application.', ['Look up the block reference or ray ID in the firewall logs, or test from another network.', 'Ask the site owner to allow the client or adjust the rule.']);
    bearerChallenge(a.ch, sent, add, has);
    const msg = msgOf(err);
    if (/csrf|xsrf|anti.?forgery|request ?verification/i.test(msg)) {
      const hasHdr = (req.headers || []).some(x => /^(x-csrf-token|x-xsrf-token|csrf-token|x-csrftoken|requestverificationtoken)$/i.test(x.name));
      add('high', 'csrf', 'CSRF protection rejected the request', hasHdr ? 'The request had a CSRF header, but its value did not match (a stale page, a token from another session, or the cookie half of a double-submit pair was not sent).' : 'The request did not include a CSRF token (X-CSRF-Token / X-XSRF-TOKEN header or form field), which the server requires for state-changing requests.', ['Read the current CSRF token (meta tag or XSRF-TOKEN cookie) and send it with every POST/PUT/PATCH/DELETE.', 'Reload the page if the session was renewed.']);
    }
    for (const c of sent) credCauses(c, e, add, 403, err);
    if (!sent.length) { noCredCauses(e, add); if (!causes.length) add('likely', 'forbidden_anonymous', 'The server refuses anonymous access', 'No credentials were sent and the server answered 403 Forbidden.', ['Sign in, or send the credentials this API expects.']); }
  }
  else if (st === 419) { kind = 'Session'; headline = '419 Page Expired'; add('high', 'session_419', 'The session or CSRF token expired (HTTP 419)', 'Laravel and similar frameworks return 419 when the CSRF token no longer matches the session, usually because the page was open longer than the session lifetime.', ['Reload the page to get a fresh token; increase the session lifetime if needed.']); }
  else if (st === 440) { kind = 'Session'; headline = '440 Login Time-out'; add('high', 'session_440', 'The login session timed out (HTTP 440)', 'IIS / Exchange (Outlook on the web) return 440 when the session has expired.', ['Sign in again.']); }
  else if (st === 498) { kind = 'Authentication'; headline = '498 Invalid Token'; add('high', 'token_498', 'The token is expired or invalid (HTTP 498)', 'Some platforms (for example ArcGIS) return 498 for expired or invalid tokens.', ['Generate a new token.']); for (const c of sent) if (c.jwt) jwtCauses(c, e, add); }
  else if (e.type === 'xhr' && (loginRedirect || (st === 200 && err.loginForm))) {
    if (e.redirectFrom && e.redirectFrom.auth && e.redirectFrom.auth.event) return null;
    kind = 'Session'; headline = 'API call ' + (st === 200 ? 'answered with a sign-in page' : 'redirected to the sign-in page');
    evidence.push('This ' + e.method + ' fetch/XHR expected data but got ' + (st === 200 ? 'an HTML page with a password field' : 'a redirect to ' + e.redirectTarget) + ', so the server treated it as not signed in.');
    for (const c of sent) credCauses(c, e, add, 401, err);
    if (!sent.length) noCredCauses(e, add);
    if (!causes.length) add('likely', 'session_invalid', 'The server does not consider this request signed in', 'No session credential was accepted.', ['Sign in again; have APIs return 401 instead of redirecting so the app can handle it.']);
  }
  else if (e.loginLoop) {
    const L = e.loginLoop;
    kind = 'Sign-in loop'; headline = 'Sign-in started ' + L.count + ' times for client ' + L.client_id + ' in ' + fmtDelta(L.span);
    add('likely', 'login_loop', 'The app keeps sending the user back to sign in', 'Each sign-in apparently succeeds, but the app does not keep the result. Typical causes: the session cookie is not stored or not sent after the redirect back (SameSite: a response_mode=form_post callback is a cross-site POST, so Lax cookies are not sent; Secure cookies over HTTP; third-party cookie blocking in iframes), the stored state/nonce was lost, or the callback fails and restarts sign-in.', ['Look at the cookies set by the callback response and whether the next request sends them.', 'For form_post callbacks, cookies that must survive the POST need SameSite=None; Secure.']);
  }
  else if (e.idpMetaFail) { kind = 'Identity provider'; headline = 'Identity provider metadata unavailable'; add('high', 'idp_metadata', 'Could not load the identity provider’s discovery document or signing keys', 'Without them the app cannot start sign-in or validate tokens. ' + (st === 0 ? 'The request failed without a response (network, DNS, or a CORS block in the browser).' : 'The server answered HTTP ' + st + '.'), ['Check the authority / issuer URL configured in the app (tenant, realm or environment), and that the endpoint allows CORS for browser apps.']); }
  else if (st >= 400 && err.code && CLOUD_CODES[err.code]) { kind = 'Cloud storage'; headline = st + ' ' + err.code; }
  else return null;

  // Cloud storage error codes (AWS / S3-compatible, Azure Storage)
  let code = err.code;
  if (code === 'AccessDenied' && /expired/i.test(err.description || '')) code = 'RequestExpired';
  if (code && CLOUD_CODES[code] && !(code === 'RequestExpired' && (has('presign_expired') || has('sas_expired')))) { const [conf, title, detail] = CLOUD_CODES[code]; add(conf, 'cloud_' + code, title, detail + (err.detail ? ' Detail: ' + err.detail : ''), []); }
  if (st === 403 && sent.length && !highCount()) add('likely', 'forbidden', 'Signed in, but not allowed to access this resource', 'The request carried ' + credLabel(sent) + ', so the server knows who is calling, but refused this action. ' + claimsHint(sent), ['Check the user’s or app’s roles, group membership, permissions on this resource, tenant or organization, and any IP or device restrictions.']);

  // What the server said
  const msg = msgOf(err);
  if (msg) evidence.push('Server said: "' + msg.slice(0, 300) + '"');
  for (const c of a.ch) evidence.push('WWW-Authenticate: ' + challengeText(c));
  for (const c of a.pch) evidence.push('Proxy-Authenticate: ' + challengeText(c));
  const ad = aadstsCause(msg); if (ad) add(ad.conf, ad.id, ad.title, ad.detail, ad.fixes);
  if (sent.some(c => c.method === 'HTTP Basic') && e.u && e.u.protocol === 'http:') evidence.push('The Basic credentials were sent unencrypted over HTTP; anyone on the network path can read them.');
  if (!highCount() && msg) for (const [re, id, title, related] of KEYWORDS) if (re.test(msg) && !related.some(has)) add('likely', id, title, '"' + msg.slice(0, 300) + '"', []);
  if (!causes.length) add('possible', 'generic_rejected', sent.length ? 'The server rejected the credentials' : 'No credentials were sent', sent.length ? 'Nothing more specific could be determined from the HAR.' : 'The request carried no Authorization header, API key or session cookie.', []);

  // Normal challenge/response steps and later recovery
  const retry = st === 401 ? findRetry(e) : null;
  if (st === 401 && a.ch.length && retry && retry.start - e.start < 30000) {
    if (!sent.length && retry.auth && retry.auth.creds.some(c => !c.proxy)) normal = true;
    if (sent.some(c => c.neg && c.neg.ntlm && c.neg.ntlm.type === 1) && a.ch.some(c => c.token)) normal = true;
    if (a.ch.some(c => /^digest$/i.test(c.scheme) && /^true$/i.test(c.params.stale || ''))) normal = true;
  }
  if (normal) {
    kind = 'Challenge'; headline = 'Authentication challenge (normal)';
    causes.length = 0;
    causes.push({ conf: 'high', id: 'challenge', title: 'The server asked for credentials and the client answered on the next request (#' + retry.i + ')', detail: 'This is the normal first step of ' + a.ch.map(c => c.scheme).join(' / ') + ' authentication, not a failure.', fixes: [] });
  }
  causes.sort((x, y) => CONF_ORDER[x.conf] - CONF_ORDER[y.conf]);
  let recovered = null;
  if (!normal) recovered = sameUrl(e).find(x => x.start > e.start && x.start - e.start < 600000 && x.method === e.method && noQuery(x.url) === noQuery(e.url) && x.status >= 200 && x.status < 300) || null;
  return { e, kind, headline, causes, evidence, sent: credLabel(sent), expected: a.ch.length ? a.ch.map(challengeText).join(' | ') : a.pch.length ? a.pch.map(challengeText).join(' | ') : '', normal, recovered };
}

/* ---------- main entry ---------- */
async function analyzeAuth() {
  Object.assign(A, { events: [], tokens: new Map(), flows: [], notes: [], hosts: new Map(), jar: [], skew: new Map(), secrets: new Set(), sanitized: false, error: '' });
  const E = S.entries, byTime = [...E].sort((a, b) => a.start - b.start);
  const anyCred = E.some(e => ((e.raw.request || {}).headers || []).some(x => /^(authorization|cookie|proxy-authorization)$/i.test(x.name)) || ((e.raw.request || {}).cookies || []).length);
  const anySet = E.some(e => hdr((e.raw.response || {}).headers, 'set-cookie') || ((e.raw.response || {}).cookies || []).length);
  A.sanitized = !anyCred && !anySet && E.length > 5;
  if (A.sanitized) A.notes.push('This HAR has no Authorization or Cookie headers and no Set-Cookie headers at all. It was probably exported “sanitized”, so credentials cannot be analyzed. Re-export it with sensitive data for a full diagnosis.');
  computeSkew();
  for (const e of byTime) {
    e.auth = null; e.flagged = null; e.saml = null; e.oauthRole = null; e.flow = null; e.loginLoop = null; e.idpMetaFail = false;
    const res = e.raw.response || {};
    const creds = credentialsOf(e);
    const ch = parseChallenges(hdrAll(res.headers, 'www-authenticate').join(', '));
    const pch = parseChallenges(hdrAll(res.headers, 'proxy-authenticate').join(', '));
    A.jar.push(...setCookiesOf(e));
    harvestResponseTokens(e);
    if (creds.length || ch.length || pch.length) e.auth = { creds, ch, pch };
    for (const c of creds) addMethod(e.host, c.proxy ? 'Proxy: ' + c.method : c.method, e);
    if (pch.length) addMethod(e.host, 'Proxy asks for ' + pch.map(c => c.scheme).join('/'), e);
  }
  await detectOAuth(byTime);
  await detectSaml(byTime);
  detectNtlm(byTime);
  for (const e of byTime) {
    if (isIgnoredHost(e.host)) continue;
    const ev = classifyAuth(e);
    if (ev) { A.events.push(ev); e.auth.event = ev; } else if (e.auth && !e.auth.creds.length && !e.auth.ch.length && !e.auth.pch.length && !e.oauthRole && !e.saml) e.auth = null;
  }
  const explained = new Set(A.events.filter(v => !v.normal).map(v => v.e));
  S.findings = S.findings.filter(f => !(f.code === 'client_error' && explained.has(f.e)));
  for (const e of explained) e.findings = e.findings.filter(f => f.code !== 'client_error');
  for (const v of A.events) if (!v.normal) {
    const f = { code: v.recovered ? 'auth_recovered' : 'auth', sev: v.recovered ? 'warn' : 'error', e: v.e, detail: v.causes[0] ? v.causes[0].title : v.headline };
    v.e.findings.push(f); S.findings.push(f);
  }
  S.findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
}

/* ---------- report ---------- */
function scrub(text) {
  for (const s of [...A.secrets].sort((a, b) => b.length - a.length)) if (s.length >= 4) text = text.split(s).join('[REDACTED]');
  return text;
}
function authReport() {
  const fails = A.events.filter(v => !v.normal), L = [];
  const safeUrl = u => redactUrl(u);
  L.push('# Authentication report', '', '- File: ' + S.fileName, '- Captured: ' + fmtDate(S.base) + ', ' + S.entries.length + ' requests', '- Generated locally by HAR Analytics. Tokens, passwords, cookie values, codes and keys are removed.', '');
  L.push('## Summary', '', verdictText(), '');
  if (A.notes.length) { L.push('## Notes', ''); for (const n of A.notes) L.push('- ' + n); L.push(''); }
  L.push('## Authentication methods in use', '', '| Host | Methods |', '|---|---|');
  for (const [host, m] of A.hosts) L.push('| ' + host + ' | ' + [...m].map(([k, n]) => k + ' (' + n + ')').join(', ') + ' |');
  L.push('');
  L.push('## Failures', '');
  if (!fails.length) L.push('No authentication failures found.', '');
  fails.forEach((v, n) => {
    L.push('### ' + (n + 1) + '. ' + v.headline + (v.recovered ? ' (recovered later)' : ''), '');
    L.push('- Request: #' + v.e.i + ' `' + v.e.method + ' ' + safeUrl(v.e.url) + '` at ' + fmtDate(entryTime(v.e)) + ' → ' + (v.e.status || 'no response'));
    L.push('- Credentials sent: ' + v.sent);
    if (v.expected) L.push('- Server asked for: ' + v.expected);
    const c0 = v.causes[0];
    if (c0) L.push('- **Most likely cause** (' + CONF_LABEL[c0.conf].toLowerCase() + '): ' + c0.title + (c0.detail ? '. ' + c0.detail.replace(/\n/g, ' ') : ''));
    for (const c of v.causes.slice(1)) L.push('- Also ' + CONF_LABEL[c.conf].toLowerCase() + ': ' + c.title);
    for (const x of v.evidence) L.push('- Evidence: ' + x);
    const fx = fixesOf(v); if (fx.length) { L.push('- What to try:'); for (const f of fx) L.push('  - ' + f); }
    if (v.recovered) L.push('- The same request succeeded later (#' + v.recovered.i + ').');
    L.push('');
  });
  if (A.flows.length) {
    L.push('## Sign-in flows', '');
    for (const f of A.flows) {
      L.push('### ' + f.title + (f.idp ? ' (' + f.idp + ')' : '') + (f.client_id ? ', client ' + f.client_id : ''), '');
      for (const s of f.steps) L.push('1. #' + s.e.i + ' ' + s.label);
      for (const c of f.checks) L.push('- ' + (c.ok === true ? '✓' : c.ok === false ? '✗' : 'ℹ') + ' ' + c.label + (c.detail ? ' (' + c.detail.replace(/\n/g, ' ') + ')' : ''));
      L.push('', '```mermaid', flowMermaid(f), '```', '');
    }
  }
  const toks = [...A.tokens.values()].filter(t => t.jwt && t.jwt.payload);
  if (toks.length) {
    L.push('## Tokens (JWT)', '', '| Token | Kind | Issuer | Audience | Scopes / roles | Expires | Used |', '|---|---|---|---|---|---|---|');
    for (const t of toks) {
      const p = t.jwt.payload;
      L.push('| ' + t.fp + ' | ' + ([...t.kinds].join('/') || 'sent') + ' | ' + (p.iss || '') + ' | ' + [].concat(p.aud || []).join(', ') + ' | ' + [...scopesOf(p)].join(' ') + ' | ' + (p.exp ? fmtDate(p.exp * 1000) : '') + ' | ' + t.uses.length + '× |');
    }
    L.push('');
  }
  return scrub(L.join('\n'));
}
const fixesOf = v => [...new Set(v.causes.slice(0, 2).flatMap(c => c.fixes || []))];
function verdictText() {
  const fails = A.events.filter(v => !v.normal);
  if (!fails.length) return A.events.length ? 'No authentication failures. ' + A.events.length + ' normal challenge step(s) were seen.' : 'No authentication failures found.';
  const open = fails.filter(v => !v.recovered).length, groups = new Map();
  for (const v of fails) { const t = v.causes[0] ? v.causes[0].title : v.headline; groups.set(t, (groups.get(t) || 0) + 1); }
  const hosts = new Set(fails.map(v => v.e.host));
  return fails.length + ' authentication failure' + (fails.length > 1 ? 's' : '') + ' on ' + hosts.size + ' host' + (hosts.size > 1 ? 's' : '') + (open !== fails.length ? ' (' + (fails.length - open) + ' recovered later)' : '') + '. Most likely causes: ' + [...groups].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([t, n]) => t + (n > 1 ? ' (×' + n + ')' : '')).join('; ') + '.';
}
