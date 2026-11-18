const CMP = { b: null, text: '' };
function loadCompare(text, name) {
  let har;
  try { har = JSON.parse(text.replace(/^\ufeff/, '')); } catch (err) { toast('Could not read ' + name + ' as JSON'); return; }
  compareWithHar(har, name);
}
function compareWithHar(har, name) {
  let n; try { n = normalize(har); } catch (err) { toast(err.message); return; }
  const creator = har.log.creator ? [har.log.creator.name, har.log.creator.version].filter(Boolean).join(' ') : '';
  CMP.b = { name, har, entries: n.entries, pages: n.pages, base: n.base, creator };
  for (const e of n.entries) { const r = e.raw.response || {}, loc = hdr(r.headers, 'location'); if (e.status >= 300 && e.status < 400 && loc) e.redirectTarget = absUrl(loc, e.url); }
  renderCompare(); show('compare');
}
function cmpLink(x) { const e = x.a && x.a[0]; return e ? stepLink(e) : h('span', { class: 'muted', text: 'B #' + x.b[0].i }); }
function renderCompare() {
  const root = $('#view-compare');
  if (!CMP.b) {
    root.replaceChildren(h('div', { class: 'av' }, h('div', { class: 'verdict' }, h('div', { class: 'vt', text: 'Compare with another HAR' }),
      h('p', { text: 'Open a second HAR, for example one captured where things work, to see which requests, statuses, headers, servers and timings differ from this one (' + S.fileName + ').' }),
      h('div', { class: 'vbtns' }, h('button', { class: 'primary', id: 'cmp-open', onclick: () => $('#file2').click(), text: 'Choose a HAR to compare…' }), h('span', { class: 'muted', text: 'You can also drop two HAR files at once.' })))));
    return;
  }
  const A = { entries: S.entries, pages: S.pages, base: S.base, creator: S.har && S.har.log.creator ? [S.har.log.creator.name, S.har.log.creator.version].filter(Boolean).join(' ') : '' };
  const r = compareHars(A, CMP.b), B = CMP.b;
  const row = (label, a, b, fmt) => { const fa = fmt ? fmt(a) : String(a ?? '—'), fb = fmt ? fmt(b) : String(b ?? '—'); return h('tr', { class: fa !== fb ? 'diff' : '' }, h('td', { text: label }), h('td', { class: 'num', text: fa }), h('td', { class: 'num', text: fb })); };
  const tbl = (cols, rows, widths) => h('table', { class: 'simple cmp' }, widths ? h('colgroup', null, widths.map(w => h('col', w ? { style: { width: w } } : null))) : null, h('thead', null, h('tr', null, cols.map(c => h('th', { text: c })))), h('tbody', null, rows));
  root.replaceChildren(h('div', { class: 'av' },
    h('div', { class: 'verdict ' + (r.explain.some(x => x.rank <= 1) ? 'bad' : r.explain.length ? 'warn' : 'good') },
      h('div', { class: 'vt', text: r.explain.length ? r.explain.length + ' difference' + (r.explain.length > 1 ? 's' : '') + ' that may matter' : '✓ No meaningful differences found' }),
      h('p', null, h('b', { text: 'A' }), ' = ' + S.fileName + ' (open)   ·   ', h('b', { text: 'B' }), ' = ' + B.name),
      h('div', { class: 'vbtns' },
        h('button', { id: 'cmp-swap', onclick: async () => { const a = S.har, na = S.fileName, b = CMP.b.har, nb = CMP.b.name; await loadHar(b, nb); compareWithHar(a, na); }, text: 'Swap A and B' }),
        h('button', { onclick: () => $('#file2').click(), text: 'Compare with a different file…' }),
        h('button', { onclick: () => { CMP.b = null; renderCompare(); }, text: 'Clear' }))),
    h('h3', { text: 'What changed (most likely to matter first)' }),
    r.explain.length ? h('ol', { class: 'explain' }, r.explain.slice(0, 40).map(x => h('li', { class: 'rank' + x.rank }, h('span', { text: x.text }), x.ref ? h('span', { class: 'muted' }, ' ', cmpLink(x.ref)) : null))) : h('p', { class: 'muted', text: 'The same requests got the same results.' }),
    h('h3', { text: 'Summary' }),
    tbl(['', 'A', 'B'], [row('Requests', r.sumA.req, r.sumB.req), row('Failed (no response)', r.sumA.failed, r.sumB.failed), row('HTTP 4xx / 5xx', r.sumA.http, r.sumB.http), row('Transferred', r.sumA.bytes, r.sumB.bytes, fmtBytes), row('First request → last byte', r.sumA.span, r.sumB.span, fmtMs), row('Page load event', r.sumA.load, r.sumB.load, v => v == null || v < 0 ? '—' : fmtMs(v)), row('Hosts', r.sumA.hosts, r.sumB.hosts)], [null, '160px', '160px']),
    r.env.length ? [h('h3', { text: 'Environment' }), tbl(['', 'A', 'B'], r.env.map(([l, a, b]) => h('tr', { class: 'diff' }, h('td', { text: l }), h('td', { text: a }), h('td', { text: b }))), ['160px', null, null])] : null,
    r.changed.length ? [h('h3', { text: 'Requests with different status codes (' + r.changed.length + ')' }), tbl(['Request', 'A', 'B'], r.changed.map(c => h('tr', { class: c.failB && !c.failA ? 'worse' : c.failA && !c.failB ? 'better' : '' }, h('td', { class: 'url' }, cmpLink(c), ' ', c.k), h('td', { class: 'num', text: fmtStatuses(c.sa) }), h('td', { class: 'num', text: fmtStatuses(c.sb) }))), [null, '120px', '120px'])] : null,
    r.hdr.length ? [h('h3', { text: 'Header and server differences on matching requests (' + r.hdr.length + ')' }), ...r.hdr.slice(0, 25).map(x => h('div', { class: 'acard' + (x.statusChanged ? ' fail' : '') }, h('div', { class: 'ahead' }, cmpLink(x), h('b', { class: 'mono', text: x.k })), tbl(['', 'A', 'B'], x.d.map(([l, a, b]) => h('tr', null, h('td', { text: l }), h('td', { class: 'mono', text: a }), h('td', { class: 'mono', text: b }))), ['230px', null, null])))] : null,
    h('h3', { text: 'Hosts' }),
    tbl(['Host', 'Requests A / B', 'Failures A / B', 'Server IPs A', 'Server IPs B', 'Protocol A / B'], r.hosts.slice(0, 60).map(x => h('tr', { class: x.ipDiff || x.protoDiff || x.failDiff || x.missing ? 'diff' : '' }, h('td', { class: 'url', text: x.host }), h('td', { class: 'num', text: (x.a ? x.a.n : 0) + ' / ' + (x.b ? x.b.n : 0) }), h('td', { class: 'num', text: (x.a ? x.a.fail : 0) + ' / ' + (x.b ? x.b.fail : 0) }), h('td', { class: 'mono', text: x.ipsA }), h('td', { class: 'mono', text: x.ipsB }), h('td', { text: (x.pA || '—') + ' / ' + (x.pB || '—') }))), [null, '120px', '120px', null, null, '150px']),
    r.onlyA.length ? [h('h3', { text: 'Only in A (' + r.onlyA.length + ')' }), h('ul', { class: 'klist' }, r.onlyA.sort((p, q) => q.a.some(isFail) - p.a.some(isFail)).slice(0, 80).map(x => h('li', null, cmpLink(x), ' ', h('span', { class: 'mono', text: x.k }), ' — ' + fmtStatuses(statusSet(x.a)))))] : null,
    r.onlyB.length ? [h('h3', { text: 'Only in B (' + r.onlyB.length + ')' }), h('ul', { class: 'klist' }, r.onlyB.sort((p, q) => q.b.some(isFail) - p.b.some(isFail)).slice(0, 80).map(x => h('li', { class: x.b.some(isFail) ? 'errtxt' : '' }, h('span', { class: 'mono', text: x.k }), ' — ' + fmtStatuses(statusSet(x.b)))))] : null,
    r.slower.length || r.faster.length ? [h('h3', { text: 'Timing differences' }), tbl(['Request', 'A', 'B'], [...r.slower, ...r.faster].map(s => h('tr', { class: s.mb > s.ma ? 'worse' : 'better' }, h('td', { class: 'url' }, cmpLink(s), ' ', s.k), h('td', { class: 'num', text: fmtMs(s.ma) }), h('td', { class: 'num', text: fmtMs(s.mb) }))), [null, '110px', '110px'])] : null));
}
