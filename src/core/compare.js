function normPath(u) {
  return u.pathname.split('/').map(s => /^\d+$/.test(s) ? ':n' : /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s) ? ':uuid' : /^[0-9a-f]{16,}$/i.test(s) ? ':hash' : (s.length >= 20 && /\d/.test(s) && /^[A-Za-z0-9_-]+$/.test(s)) ? ':id' : s).join('/').replace(/[.\-_][0-9a-f]{8,}(?=\.\w+$)/i, '.:hash');
}
const cmpKey = e => e.method + ' ' + (e.u ? e.u.host + normPath(e.u) + (e.u.search ? '?' + [...new Set(e.u.searchParams.keys())].sort().join('&') : '') : e.url);
function statusSet(list) { return [...new Set(list.map(x => x.status))].sort((a, b) => a - b); }
const fmtStatuses = s => s.map(x => x || 'failed').join(', ');
function cmpHeaderDiff(a, b) {
  const out = [], rq = (e, n) => hdr(reqH(e), n), rs = (e, n) => hdr(resH(e), n);
  const checks = [
    ['Request Authorization', e => { const v = rq(e, 'authorization'); return v ? v.split(' ')[0] + ' …' : '(none)'; }],
    ['Request cookies', e => [...requestCookies(e).keys()].sort().join(', ') || '(none)'],
    ['Request Origin', e => rq(e, 'origin') || '(none)'],
    ['Request Content-Type', e => rq(e, 'content-type') || '(none)'],
    ['Response Content-Type', e => (rs(e, 'content-type') || '(none)').split(';')[0]],
    ['Response Location', e => rs(e, 'location') ? noQuery(absUrl(rs(e, 'location'), e.url)) : '(none)'],
    ['Response Set-Cookie', e => hdrAll(resH(e), 'set-cookie').map(x => x.split('=')[0].trim()).sort().join(', ') || '(none)'],
    ['Response Access-Control-Allow-Origin', e => rs(e, 'access-control-allow-origin') || '(none)'],
    ['Response WWW-Authenticate', e => rs(e, 'www-authenticate') || '(none)'],
    ['Response cache status', e => cacheStatus(e) || '(none)'],
    ['Server header', e => rs(e, 'server') || '(none)'],
    ['Server IP', e => e.serverIP || '(none)'],
    ['HTTP version', e => e.httpVersion || '(none)'],
  ];
  for (const [label, f] of checks) { const va = f(a), vb = f(b); if (va !== vb) out.push([label, va, vb]); }
  const xs = e => new Set(reqH(e).map(x => x.name.toLowerCase()).filter(n => /^x-|^api-key$|^ocp-apim/.test(n)));
  const na = xs(a), nb = xs(b);
  for (const n of na) if (!nb.has(n)) out.push(['Request header ' + n, 'sent', '(not sent)']);
  for (const n of nb) if (!na.has(n)) out.push(['Request header ' + n, '(not sent)', 'sent']);
  return out;
}
function compareHars(A, B) {
  const g = new Map(), put = (e, side) => { const k = cmpKey(e); if (!g.has(k)) g.set(k, { k, a: [], b: [] }); g.get(k)[side].push(e); };
  A.entries.forEach(e => put(e, 'a')); B.entries.forEach(e => put(e, 'b'));
  const r = { onlyA: [], onlyB: [], changed: [], slower: [], faster: [], hdr: [], hosts: [], env: [], explain: [] };
  for (const x of g.values()) {
    if (!x.b.length) { r.onlyA.push(x); continue; }
    if (!x.a.length) { r.onlyB.push(x); continue; }
    const sa = statusSet(x.a), sb = statusSet(x.b), failA = x.a.some(isFail), failB = x.b.some(isFail);
    if (sa.join() !== sb.join()) r.changed.push({ ...x, sa, sb, failA, failB });
    const ma = median(x.a.map(e => e.time)), mb = median(x.b.map(e => e.time));
    if (mb > ma * 2 && mb - ma > 300) r.slower.push({ ...x, ma, mb }); else if (ma > mb * 2 && ma - mb > 300) r.faster.push({ ...x, ma, mb });
    const d = cmpHeaderDiff(x.a[x.a.length - 1], x.b[x.b.length - 1]);
    if (d.length) r.hdr.push({ ...x, d, statusChanged: sa.join() !== sb.join() });
  }
  r.hdr.sort((p, q) => (q.statusChanged - p.statusChanged) || q.d.length - p.d.length);
  const hostStats = list => { const m = new Map(); for (const e of list) { const s = m.get(e.host) || { n: 0, fail: 0, ips: new Set(), proto: new Set() }; s.n++; if (isFail(e)) s.fail++; if (e.serverIP) s.ips.add(e.serverIP.replace(/^\[|\]$/g, '')); if (e.httpVersion) s.proto.add(e.httpVersion.toLowerCase()); m.set(e.host, s); } return m; };
  const ha = hostStats(A.entries), hb = hostStats(B.entries);
  for (const host of new Set([...ha.keys(), ...hb.keys()])) {
    const a = ha.get(host), b = hb.get(host), ipsA = a ? [...a.ips].sort().join(', ') : '', ipsB = b ? [...b.ips].sort().join(', ') : '', pA = a ? [...a.proto].sort().join(', ') : '', pB = b ? [...b.proto].sort().join(', ') : '';
    const ipDiff = a && b && ipsA && ipsB && ![...a.ips].some(ip => b.ips.has(ip));
    r.hosts.push({ host, a, b, ipsA, ipsB, pA, pB, ipDiff, protoDiff: a && b && pA && pB && pA !== pB, failDiff: (a ? a.fail : 0) !== (b ? b.fail : 0), missing: !a || !b });
  }
  r.hosts.sort((p, q) => (q.ipDiff + q.protoDiff + q.failDiff + q.missing) - (p.ipDiff + p.protoDiff + p.failDiff + p.missing));
  const envOf = H => { const e0 = H.entries[0]; return { ua: e0 ? hdr(reqH(e0), 'user-agent') : '', lang: e0 ? hdr(reqH(e0), 'accept-language') : '', creator: H.creator || '', when: fmtDate(H.base) }; };
  const ea = envOf({ entries: A.entries, creator: A.creator, base: A.base }), eb = envOf(B);
  for (const [label, k] of [['Browser (User-Agent)', 'ua'], ['Accept-Language', 'lang'], ['Captured with', 'creator'], ['Captured at', 'when']]) if (ea[k] !== eb[k]) r.env.push([label, ea[k] || '(none)', eb[k] || '(none)']);
  // Ranked explanations
  const ex = (rank, text, ref) => r.explain.push({ rank, text, ref });
  for (const c of r.changed) if (c.failB && !c.failA) {
    const hd = r.hdr.find(x => x.k === c.k);
    ex(0, 'Works in A (' + fmtStatuses(c.sa) + ') but fails in B (' + fmtStatuses(c.sb) + '): ' + c.k + (hd ? '. Differences on this request: ' + hd.d.slice(0, 4).map(([l, va, vb]) => l + ' ' + va + ' → ' + vb).join('; ') : ''), c);
  }
  for (const x of r.onlyB) if (x.b.some(isFail)) ex(1, 'Fails in B and was not requested in A: ' + x.k + ' (' + fmtStatuses(statusSet(x.b)) + ')', x);
  const okOnlyA = r.onlyA.filter(x => x.a.every(isOk) && x.a.some(e => ['xhr', 'doc'].includes(e.type)));
  for (const x of okOnlyA.slice(0, 15)) ex(2, 'Requested in A but never in B: ' + x.k + ' — the client in B never got to this step (or took a different path).', x);
  for (const c of r.changed) if (!(c.failB && !c.failA) && !(c.failA && !c.failB)) ex(3, 'Different status: ' + c.k + ' — A ' + fmtStatuses(c.sa) + ', B ' + fmtStatuses(c.sb), c);
  for (const hh of r.hosts) { if (hh.ipDiff) ex(3, hh.host + ' resolved to different servers: A ' + hh.ipsA + ' vs B ' + hh.ipsB + ' (DNS, geo-routing, VPN or a hosts-file entry).', null); if (hh.protoDiff) ex(4, hh.host + ' used ' + hh.pA + ' in A but ' + hh.pB + ' in B (a proxy or network in between?).', null); }
  for (const [l, va, vb] of r.env) if (/User-Agent|Language/.test(l)) ex(4, l + ' differs: A "' + va.slice(0, 80) + '" vs B "' + vb.slice(0, 80) + '".', null);
  for (const s of r.slower.slice(0, 10)) ex(5, 'Slower in B: ' + s.k + ' (' + fmtMs(s.ma) + ' → ' + fmtMs(s.mb) + ')', s);
  for (const c of r.changed) if (c.failA && !c.failB) ex(6, 'Fails in A but works in B: ' + c.k + ' (' + fmtStatuses(c.sa) + ' → ' + fmtStatuses(c.sb) + ')', c);
  r.explain.sort((p, q) => p.rank - q.rank);
  const sum = H => { const E = H.entries; return { req: E.length, failed: E.filter(e => e.status === 0).length, http: E.filter(e => e.status >= 400).length, bytes: E.reduce((s, e) => s + e.transfer, 0), span: E.reduce((s, e) => Math.max(s, e.start + e.time), 0), load: ((H.pages || [])[0] || {}).pageTimings ? H.pages[0].pageTimings.onLoad : null, hosts: new Set(E.map(e => e.host)).size }; };
  r.sumA = sum(A); r.sumB = sum(B);
  return r;
}
// Markdown version of the comparison (used by the command-line tool).
function compareReport(r, nameA, nameB) {
  const L = ['# Comparison report', '', '- A: ' + nameA, '- B: ' + nameB, '- Generated locally by HAR Analytics. Tokens, passwords, cookie values and keys are removed.', '', '## What changed (most likely to matter first)', ''];
  if (!r.explain.length) L.push('The same requests got the same results.');
  r.explain.slice(0, 40).forEach((x, k) => L.push((k + 1) + '. ' + x.text));
  L.push('', '## Summary', '', '| | A | B |', '|---|---|---|');
  for (const [label, k, f] of [['Requests', 'req'], ['Failed (no response)', 'failed'], ['HTTP 4xx / 5xx', 'http'], ['Transferred', 'bytes', fmtBytes], ['First request → last byte', 'span', fmtMs]]) L.push('| ' + label + ' | ' + (f ? f(r.sumA[k]) : r.sumA[k]) + ' | ' + (f ? f(r.sumB[k]) : r.sumB[k]) + ' |');
  if (r.changed.length) { L.push('', '## Different status codes', ''); for (const c of r.changed) L.push('- ' + c.k + ': A ' + fmtStatuses(c.sa) + ', B ' + fmtStatuses(c.sb)); }
  if (r.hdr.length) { L.push('', '## Header and server differences', ''); for (const x of r.hdr.slice(0, 25)) { L.push('### ' + x.k, ''); for (const [l, a, b] of x.d) L.push('- ' + l + ': A `' + a + '` → B `' + b + '`'); L.push(''); } }
  if (r.onlyA.length) { L.push('', '## Only in A', ''); for (const x of r.onlyA.slice(0, 80)) L.push('- ' + x.k + ' (' + fmtStatuses(statusSet(x.a)) + ')'); }
  if (r.onlyB.length) { L.push('', '## Only in B', ''); for (const x of r.onlyB.slice(0, 80)) L.push('- ' + x.k + ' (' + fmtStatuses(statusSet(x.b)) + ')'); }
  return scrub(L.join('\n').replace(/https?:\/\/[^\s`)]+/g, u => redactUrl(u))) + '\n';
}
