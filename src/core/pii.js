/* ---------- personal data (PII) detection ----------
   Finds personal data in URLs, headers, cookies and bodies so it can be
   reported and masked before a HAR is shared. Validators (Luhn for card
   numbers, mod-97 for IBANs, SSN ranges) keep false alarms down. */
function luhnOk(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) { let d = digits.charCodeAt(i) - 48; if (alt) { d *= 2; if (d > 9) d -= 9; } sum += d; alt = !alt; }
  return sum % 10 === 0;
}
function ibanOk(s) {
  s = s.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const r = s.slice(4) + s.slice(0, 4);
  let m = 0; for (const ch of r) { const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55); for (const d of v) m = (m * 10 + (+d)) % 97; }
  return m === 1;
}
const PII_KINDS = {
  email: { label: 'Email address', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g, ok: () => true },
  card: { label: 'Payment card number', re: /(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])/g, ok: m => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && !/^(\d)\1+$/.test(d) && /^[2-6]/.test(d) && luhnOk(d); } },
  ssn: { label: 'US Social Security number', re: /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g, ok: () => true },
  iban: { label: 'Bank account (IBAN)', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, ok: ibanOk },
  phone: { label: 'Phone number', re: /(?<![\w.:/-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]\d{3,4}(?![\w.:/-])/g, ok: m => { const d = m.replace(/\D/g, ''); return d.length >= 9 && d.length <= 15 && !/^(19|20)\d{2}[01]\d[0-3]\d/.test(d); } },
};
const CLIENT_IP_HEADERS = /^(x-forwarded-for|x-real-ip|cf-connecting-ip|true-client-ip|x-client-ip|forwarded)$/i;
function maskSample(kind, m) {
  if (kind === 'email') { const [u, d] = m.split('@'); return u[0] + '***@' + d; }
  const d = m.replace(/\s/g, '');
  return d.length > 6 ? d.slice(0, 2) + '*'.repeat(Math.max(3, d.length - 6)) + d.slice(-4) : '***';
}
const PII_ORDER = ['email', 'card', 'iban', 'ssn', 'phone']; // specific patterns first; a phone match inside one of them is dropped
function piiInText(text, kinds) {
  const out = [];
  if (!text || typeof text !== 'string') return out;
  const want = new Set(kinds || PII_ORDER);
  for (const k of PII_ORDER) {
    if (!want.has(k)) continue;
    const P = PII_KINDS[k]; P.re.lastIndex = 0;
    let m;
    while ((m = P.re.exec(text))) {
      const a = m.index, b = a + m[0].length;
      if (P.ok(m[0]) && !out.some(x => a < x.index + x.value.length && x.index < b)) out.push({ kind: k, value: m[0], index: a });
      if (out.length > 500) return out;
    }
  }
  return out;
}
// Scan every entry; returns { byKind: Map(kind → {count, samples:Set, entries:Set}), hits: [{e, where, kind, sample}] }
function scanPii(entries) {
  const byKind = new Map(), hits = [];
  const note = (e, where, kind, value) => {
    if (!byKind.has(kind)) byKind.set(kind, { count: 0, samples: new Set(), entries: new Set() });
    const k = byKind.get(kind); k.count++; if (k.samples.size < 5) k.samples.add(maskSample(kind, value)); k.entries.add(e);
    if (hits.length < 2000) hits.push({ e, where, kind, sample: maskSample(kind, value) });
  };
  for (const e of entries) {
    const req = e.raw.request || {}, res = e.raw.response || {};
    let url = e.url; try { url = decodeURIComponent(e.url); } catch (_) { /* keep raw */ }
    for (const f of piiInText(url, ['email', 'card', 'ssn', 'phone', 'iban'])) note(e, 'URL', f.kind, f.value);
    for (const [list, side] of [[req.headers, 'request header'], [res.headers, 'response header']]) for (const x of (list || [])) {
      const n = String(x.name), v = String(x.value || '');
      if (/^(authorization|cookie|set-cookie|:path|referer|location|date|expires|last-modified|etag|content-security-policy)$/i.test(n)) continue;
      if (CLIENT_IP_HEADERS.test(n)) { for (const ip of v.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}/gi) || []) note(e, side + ' ' + n, 'ip', ip); continue; }
      for (const f of piiInText(v, ['email', 'phone', 'card', 'ssn'])) note(e, side + ' ' + n, f.kind, f.value);
    }
    if (req.postData && req.postData.text) for (const f of piiInText(String(req.postData.text).slice(0, 2e6))) note(e, 'request body', f.kind, f.value);
    const body = (res.content && res.content.text && (res.content.encoding !== 'base64' || isTextMime(e.mime))) ? bodyText(res.content) : null;
    if (body) for (const f of piiInText(body.slice(0, 2e6))) note(e, 'response body', f.kind, f.value);
  }
  return { byKind, hits };
}
PII_KINDS.ip = { label: 'Client IP address (forwarding header)', re: /$^/g, ok: () => true };
// Mask PII inside a string (used by the redacted export).
function maskPii(s) {
  if (typeof s !== 'string' || s.length < 6) return s;
  // Percent-encoded emails in URLs and form bodies (jane%40example.com)
  s = s.replace(/[A-Za-z0-9._+-]+%40[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/gi, '[REDACTED]');
  for (const k of PII_ORDER) { const P = PII_KINDS[k]; s = s.replace(P.re, m => (P.ok(m) ? '[REDACTED]' : m)); }
  return s;
}
function diagPii() {
  const { byKind } = scanPii(S.entries);
  if (!byKind.size) return;
  const all = new Set(); for (const v of byKind.values()) for (const e of v.entries) all.add(e);
  const list = [...all].sort((a, b) => a.start - b.start);
  const strong = ['card', 'ssn', 'iban'].some(k => byKind.has(k));
  dAdd('security', strong ? 'warn' : 'info', list[0], 'Personal data found in ' + list.length + ' request' + (list.length > 1 ? 's' : '') + ': ' + [...byKind].map(([k, v]) => v.count + ' × ' + PII_KINDS[k].label.toLowerCase()).join(', '),
    [C(strong ? 'likely' : 'possible', 'pii', 'This HAR contains personal data', 'Before sharing it, use Export → Redacted HAR with "Mask personal data" (on by default). Personal data in URLs also ends up in server logs, analytics and Referer headers.', ['Export a redacted copy before sharing; avoid putting personal data in URLs.'])],
    [...byKind].map(([k, v]) => PII_KINDS[k].label + ': ' + v.count + ' (e.g. ' + [...v.samples].join(', ') + ')'), list);
}
