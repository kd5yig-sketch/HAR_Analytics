/* ---------- custom rules ----------
   A rule selects requests (host, path, method, status, type) and states a
   check; requests that fail the check are reported in Diagnose under
   "Your rules". Example:
   { name: 'API calls must be fast', host: 'api.example.com', path: '/v1/*',
     check: 'slower', value: '800', severity: 'warn' }                        */
const RULE_CHECKS = {
  slower: { label: 'takes longer than (ms)', needs: 'number', test: (e, v) => e.time > +v, say: (e, v) => 'took ' + fmtMs(e.time) + ' (limit ' + fmtMs(+v) + ')' },
  ttfb: { label: 'server waiting time longer than (ms)', needs: 'number', test: (e, v) => e.timings.wait > +v, say: (e, v) => 'waited ' + fmtMs(e.timings.wait) + ' for the first byte (limit ' + fmtMs(+v) + ')' },
  larger: { label: 'transfer larger than (KB)', needs: 'number', test: (e, v) => e.transfer > +v * 1024, say: (e, v) => 'transferred ' + fmtBytes(e.transfer) + ' (limit ' + v + ' KB)' },
  status: { label: 'status is (e.g. 5xx, 401, failed)', needs: 'text', test: (e, v) => statusIn(e, v), say: e => 'returned ' + (e.status || 'no response') },
  reqHeaderMissing: { label: 'request header is missing', needs: 'text', test: (e, v) => !hdr((e.raw.request || {}).headers, v), say: (e, v) => 'request had no ' + v + ' header' },
  resHeaderMissing: { label: 'response header is missing', needs: 'text', test: (e, v) => e.status > 0 && !hdr((e.raw.response || {}).headers, v), say: (e, v) => 'response had no ' + v + ' header' },
  resHeaderNot: { label: 'response header does not match (Name: regex)', needs: 'text', test: (e, v) => { const [n, re] = splitNameRe(v); if (!n || e.status === 0) return false; return !re.test(hdr((e.raw.response || {}).headers, n)); }, say: (e, v) => { const [n] = splitNameRe(v); return n + ' was "' + (hdr((e.raw.response || {}).headers, n) || '(missing)') + '"'; } },
  bodyContains: { label: 'response body contains', needs: 'text', test: (e, v) => (bodyText((e.raw.response || {}).content || {}) || '').includes(v), say: (e, v) => 'response body contains "' + v + '"' },
  bodyMissing: { label: 'response body does not contain', needs: 'text', test: (e, v) => e.status > 0 && !(bodyText((e.raw.response || {}).content || {}) || '').includes(v), say: (e, v) => 'response body lacks "' + v + '"' },
};
function splitNameRe(v) { const i = String(v).indexOf(':'); if (i < 0) return [String(v).trim(), /.^/]; try { return [v.slice(0, i).trim(), new RegExp(v.slice(i + 1).trim(), 'i')]; } catch (_) { return [v.slice(0, i).trim(), /.^/]; } }
function statusIn(e, spec) {
  return String(spec).split(/[\s,]+/).filter(Boolean).some(s => {
    s = s.toLowerCase();
    if (s === 'failed' || s === '0') return e.status === 0;
    if (/^[1-5]xx$/.test(s)) return Math.floor(e.status / 100) === +s[0];
    if (/^!?[1-5]xx$/.test(s)) return Math.floor(e.status / 100) !== +s[1];
    return String(e.status) === s;
  });
}
function globToRe(g) { return new RegExp('^' + String(g).split('*').map(x => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$', 'i'); }
function normalizeRule(r) {
  if (!r || typeof r !== 'object' || !RULE_CHECKS[r.check]) return null;
  const value = String(r.value ?? '').trim();
  if (RULE_CHECKS[r.check].needs === 'number' && !(Number(value) >= 0)) return null;
  if (RULE_CHECKS[r.check].needs === 'text' && !value) return null;
  return {
    name: String(r.name || '').trim().slice(0, 120), host: String(r.host || '').trim().toLowerCase(), path: String(r.path || '').trim(),
    method: String(r.method || '').trim().toUpperCase(), status: String(r.status || '').trim(), type: String(r.type || '').trim().toLowerCase(),
    check: r.check, value, severity: ['error', 'warn', 'info'].includes(r.severity) ? r.severity : 'warn', message: String(r.message || '').trim().slice(0, 500),
  };
}
function ruleSelects(r, e) {
  if (r.host && !anyHost(asList(r.host), e.host)) return false;
  if (r.path && !(e.u && (r.path.includes('*') ? globToRe(r.path).test(e.u.pathname) : e.u.pathname.startsWith(r.path)))) return false;
  if (r.method && !asList(r.method).map(x => x.toUpperCase()).includes(e.method)) return false;
  if (r.status && !statusIn(e, r.status)) return false;
  if (r.type && e.type !== r.type && !TYPE_LABEL[e.type].toLowerCase().startsWith(r.type)) return false;
  return true;
}
function ruleTitle(r) { return r.name || ((r.host || 'any host') + (r.path ? ' ' + r.path : '') + ': ' + RULE_CHECKS[r.check].label.replace(/ \(.*\)$/, '') + ' ' + r.value); }
function diagRules() {
  for (const r of SETTINGS.rules) {
    const C0 = RULE_CHECKS[r.check], hits = [];
    for (const e of S.entries) { try { if (ruleSelects(r, e) && C0.test(e, r.value)) hits.push(e); } catch (_) { /* a bad rule never stops the analysis */ } }
    if (!hits.length) continue;
    dAdd('rules', r.severity, hits[0], ruleTitle(r) + ' — ' + hits.length + ' request' + (hits.length > 1 ? 's' : ''),
      [C(r.severity === 'error' ? 'high' : r.severity === 'warn' ? 'likely' : 'possible', 'rule', r.message || 'Your rule "' + ruleTitle(r) + '" matched', 'From your settings: ' + [r.host && 'host ' + r.host, r.path && 'path ' + r.path, r.method && 'method ' + r.method, r.status && 'status ' + r.status, r.type && 'type ' + r.type].filter(Boolean).join(', ') + (r.host || r.path || r.method || r.status || r.type ? '; ' : '') + 'fails when ' + C0.label.replace(/ \(.*\)$/, '') + ' ' + r.value + '.', [])],
      hits.slice(0, 10).map(x => '#' + x.i + ' ' + x.method + ' ' + x.host + (x.u ? x.u.pathname : '').slice(0, 80) + ': ' + C0.say(x, r.value)), hits);
  }
}
