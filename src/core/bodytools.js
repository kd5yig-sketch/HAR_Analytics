/* ---------- body tools: path search, decoders, diffs ---------- */

// JSONPath subset: $  .key  ['key']  [n]  [-n]  [a:b]  [*]  .*  ..key  ..*
// A leading "$" is optional ("data.items[*].id" works).
function jsonPath(root, expr) {
  expr = String(expr || '').trim();
  if (!expr) return [];
  if (expr[0] !== '$') expr = '$' + (expr[0] === '[' || expr.startsWith('..') ? '' : '.') + expr;
  const toks = []; let i = 1;
  const name = () => { const m = /^(\*|[^.[\]\s]+)/.exec(expr.slice(i)); if (!m) throw new Error('expected a name at position ' + (i + 1)); i += m[1].length; return m[1]; };
  while (i < expr.length) {
    if (expr.startsWith('..', i)) { i += 2; toks.push({ deep: true, key: expr[i] === '[' ? '*' : name() }); continue; }
    if (expr[i] === '.') { i++; toks.push({ key: name() }); continue; }
    if (expr[i] === '[') {
      const j = expr.indexOf(']', i); if (j < 0) throw new Error('missing ]');
      const inner = expr.slice(i + 1, j).trim(); i = j + 1;
      if (inner === '*') toks.push({ key: '*' });
      else if (/^-?\d+$/.test(inner)) toks.push({ index: +inner });
      else if (/^(['"]).*\1$/.test(inner)) toks.push({ key: inner.slice(1, -1) });
      else if (/^-?\d*:-?\d*$/.test(inner)) { const [a, b] = inner.split(':'); toks.push({ slice: [a === '' ? 0 : +a, b === '' ? undefined : +b] }); }
      else throw new Error('unsupported [' + inner + ']');
      continue;
    }
    throw new Error('unexpected "' + expr[i] + '" at position ' + (i + 1));
  }
  const kidPath = (p, k, isArr) => isArr ? p + '[' + k + ']' : (/^[A-Za-z_$][\w$]*$/.test(k) ? p + '.' + k : p + "['" + String(k).replace(/'/g, "\\'") + "']");
  const kids = n => Array.isArray(n.v) ? n.v.map((x, k) => ({ path: kidPath(n.path, k, true), v: x, k })) : n.v && typeof n.v === 'object' ? Object.keys(n.v).map(k => ({ path: kidPath(n.path, k, false), v: n.v[k], k })) : [];
  let cur = [{ path: '$', v: root }];
  for (const t of toks) {
    const next = [];
    for (const n of cur) {
      if (t.deep) { const walk = x => { for (const c of kids(x)) { if (t.key === '*' || String(c.k) === t.key) next.push(c); if (next.length < 20000) walk(c); } }; walk(n); }
      else if (t.key === '*') next.push(...kids(n));
      else if (t.key != null) { if (n.v && typeof n.v === 'object' && !Array.isArray(n.v) && Object.prototype.hasOwnProperty.call(n.v, t.key)) next.push({ path: kidPath(n.path, t.key, false), v: n.v[t.key] }); }
      else if (t.index != null) { if (Array.isArray(n.v)) { const k = t.index < 0 ? n.v.length + t.index : t.index; if (k >= 0 && k < n.v.length) next.push({ path: kidPath(n.path, k, true), v: n.v[k] }); } }
      else if (t.slice && Array.isArray(n.v)) { const len = n.v.length, norm = x => x < 0 ? Math.max(0, len + x) : x, a = norm(t.slice[0]), b = t.slice[1] === undefined ? len : norm(t.slice[1]); for (let k = a; k < Math.min(b, len); k++) next.push({ path: kidPath(n.path, k, true), v: n.v[k] }); }
    }
    cur = next.slice(0, 20000);
  }
  return cur;
}

// Try every sensible decoding of a string; returns [{ label, value }].
async function decodeAll(input) {
  const s = String(input || '').trim(), out = [], seen = new Set();
  const add = (label, value) => { if (value == null) return; value = String(value); if (!value || value === s || seen.has(label + value)) return; seen.add(label + value); out.push({ label, value }); };
  if (!s) return out;
  const printable = t => t && !/[\u0000-\u0008\u000e-\u001f�]/.test(t.slice(0, 2000));
  const pretty = t => { try { return JSON.stringify(JSON.parse(t), null, 2); } catch (_) { return null; } };
  const j = parseJwt(s);
  if (j) {
    add('JWT header', JSON.stringify(j.header, null, 2));
    if (j.payload) {
      add('JWT payload (signature not verified)', JSON.stringify(j.payload, null, 2));
      const times = ['exp', 'iat', 'nbf', 'auth_time'].filter(k => typeof j.payload[k] === 'number').map(k => k + ': ' + fmtDate(j.payload[k] * 1000));
      if (times.length) add('JWT times', times.join('\n'));
    }
  }
  if (/%[0-9a-f]{2}/i.test(s) || /\+/.test(s) && /=/.test(s)) { try { add('URL-decoded', decodeURIComponent(s.replace(/\+/g, ' '))); } catch (_) { /* malformed escape */ } }
  if (/^[\w.%+-]+=[^&]*(&[\w.%+-]+=[^&]*)+$/.test(s)) { try { add('Form / query parameters', [...new URLSearchParams(s)].map(([k, v]) => k + ' = ' + v).join('\n')); } catch (_) { /* not a form */ } }
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(s.replace(/\s+/g, '')) && s.length >= 8) {
    let bytes = null; try { bytes = b64ToBytes(s); } catch (_) { /* not base64 */ }
    if (bytes && bytes.length) {
      const txt = utf8(bytes);
      if (printable(txt)) add('Base64-decoded' + (pretty(txt) ? ' (JSON)' : ''), pretty(txt) || txt);
      for (const [fmt, label, test] of [['gzip', 'Base64 + gzip', b => b[0] === 0x1f && b[1] === 0x8b], ['deflate', 'Base64 + zlib', b => b[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(b[1])], ['deflate-raw', 'Base64 + deflate (e.g. a SAML redirect)', () => true]]) {
        if (!test(bytes) || typeof DecompressionStream === 'undefined') continue;
        try { const t = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream(fmt))).text(); if (printable(t) && t.length) { add(label, pretty(t) || t); break; } } catch (_) { /* not compressed this way */ }
      }
      if (!printable(txt) && !out.some(x => x.label.startsWith('Base64 +')) && !/^(\d+|[0-9a-f]+)$/i.test(s)) add('Base64-decoded bytes (hex)', [...bytes.slice(0, 256)].map(b => b.toString(16).padStart(2, '0')).join(' ') + (bytes.length > 256 ? ' … (' + bytes.length + ' bytes)' : ''));
    }
  }
  if (/^(0x)?[0-9a-f]+$/i.test(s) && s.replace(/^0x/i, '').length % 2 === 0 && s.length >= 8 && /[a-f]/i.test(s)) {
    const hex = s.replace(/^0x/i, ''), b = new Uint8Array(hex.length / 2); for (let k = 0; k < b.length; k++) b[k] = parseInt(hex.substr(k * 2, 2), 16);
    const t = utf8(b); if (printable(t)) add('Hex-decoded', t);
  }
  if (/^\d{10}(\.\d+)?$/.test(s)) add('Unix time (seconds)', fmtDate(+s * 1000));
  if (/^\d{13}$/.test(s)) add('Unix time (milliseconds)', fmtDate(+s));
  if (/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(s)) add('HTML entities decoded', s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-f]+);/gi, (m, e) => ({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" })[e.toLowerCase()] || String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10))));
  if (/^[\[{]/.test(s) && pretty(s)) add('JSON (formatted)', pretty(s));
  return out.length > 1 ? out.filter(x => !x.label.startsWith('Base64-decoded bytes')) : out;
}

// Structural JSON diff: [{ path, kind: 'added' | 'removed' | 'changed', a, b }]
function diffJson(a, b, path = '$', out = []) {
  if (out.length >= 1000) return out;
  const type = v => Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v;
  if (type(a) !== type(b)) { out.push({ path, kind: 'changed', a, b }); return out; }
  if (type(a) === 'object') {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      const p = /^[A-Za-z_$][\w$]*$/.test(k) ? path + '.' + k : path + "['" + k + "']";
      if (!(k in b)) out.push({ path: p, kind: 'removed', a: a[k] });
      else if (!(k in a)) out.push({ path: p, kind: 'added', b: b[k] });
      else diffJson(a[k], b[k], p, out);
    }
  } else if (type(a) === 'array') {
    for (let k = 0; k < Math.max(a.length, b.length); k++) {
      const p = path + '[' + k + ']';
      if (k >= b.length) out.push({ path: p, kind: 'removed', a: a[k] });
      else if (k >= a.length) out.push({ path: p, kind: 'added', b: b[k] });
      else diffJson(a[k], b[k], p, out);
    }
  } else if (a !== b) out.push({ path, kind: 'changed', a, b });
  return out;
}
// Line diff (LCS); returns [{ op: ' ' | '-' | '+', line }]
function diffLines(a, b) {
  const A = String(a).split('\n'), B = String(b).split('\n');
  if (A.length * B.length > 4e6) return [...A.map(line => ({ op: '-', line })), ...B.map(line => ({ op: '+', line }))];
  const n = A.length, m = B.length, L = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = A[i] === B[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) { if (A[i] === B[j]) { out.push({ op: ' ', line: A[i] }); i++; j++; } else if (L[i + 1][j] >= L[i][j + 1]) out.push({ op: '-', line: A[i++] }); else out.push({ op: '+', line: B[j++] }); }
  while (i < n) out.push({ op: '-', line: A[i++] });
  while (j < m) out.push({ op: '+', line: B[j++] });
  return out;
}
