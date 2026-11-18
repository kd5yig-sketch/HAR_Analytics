/* ---------- Timeline view: charts over time and per-endpoint statistics ---------- */
const SVGNS = 'http://www.w3.org/2000/svg';
function sv(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, v);
  for (const c of kids.flat()) if (c != null) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
S.epKeys = new Map();
const relLabel = ms => ms >= 3600000 ? Math.floor(ms / 3600000) + 'h' + String(Math.floor(ms / 60000) % 60).padStart(2, '0') : ms >= 60000 ? Math.floor(ms / 60000) + ':' + String(Math.floor(ms / 1000) % 60).padStart(2, '0') : (ms / 1000).toFixed(ms < 10000 && ms % 1000 ? 1 : 0) + 's';
function niceMax(v) { if (!(v > 0)) return 1; const p = Math.pow(10, Math.floor(Math.log10(v))); for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p; return 10 * p; }
function chartFrame(tb, yMax, yFmt, height, title) {
  const W = 1000, H = height, L = 56, R = 12, T = 12, Bm = 28, n = tb.buckets.length, bw = (W - L - R) / n;
  const x = k => L + k * bw, y = v => T + (H - T - Bm) * (1 - v / yMax);
  const g = sv('g', { class: 'axes' });
  for (let k = 0; k <= 4; k++) { const v = yMax * k / 4; g.append(sv('line', { x1: L, x2: W - R, y1: y(v), y2: y(v), class: 'grid' }), sv('text', { x: L - 6, y: y(v) + 4, 'text-anchor': 'end', class: 'tick' }, yFmt(v))); }
  const every = Math.max(1, Math.ceil(n / 10));
  for (let k = 0; k <= n; k += every) g.append(sv('text', { x: x(k), y: H - 8, 'text-anchor': k === 0 ? 'start' : 'middle', class: 'tick' }, '+' + relLabel(k * tb.step)));
  const svg = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'chart', role: 'img', 'aria-label': title, preserveAspectRatio: 'none' }, sv('title', null, title), g);
  return { svg, x, y, bw, W, H, L, R, T, Bm };
}
function requestsChart(tb) {
  const max = niceMax(Math.max(...tb.buckets.map(b => b.n))), f = chartFrame(tb, max, v => String(Math.round(v)), 220, 'Requests over time by outcome');
  tb.buckets.forEach((b, k) => {
    let acc = 0; const g = sv('g', { class: 'bucket', 'data-k': k, tabindex: '0', role: 'button', 'aria-label': b.n + ' requests from +' + relLabel(b.from) + ' to +' + relLabel(b.to) });
    g.append(sv('title', null, '+' + relLabel(b.from) + ' – +' + relLabel(b.to) + ': ' + b.n + ' requests (' + b.ok + ' OK, ' + b['4xx'] + ' 4xx, ' + b['5xx'] + ' 5xx, ' + b.failed + ' failed). Click to list them.'));
    g.append(sv('rect', { x: f.x(k), y: f.T, width: f.bw, height: f.H - f.T - f.Bm, class: 'hit' }));
    for (const o of ['ok', '4xx', '5xx', 'failed']) { if (!b[o]) continue; const y0 = f.y(acc), y1 = f.y(acc + b[o]); g.append(sv('rect', { x: f.x(k) + 0.5, y: y1, width: Math.max(1, f.bw - 1), height: Math.max(0.5, y0 - y1), class: 'bar-' + o })); acc += b[o]; }
    const go = () => filterTime(b.from, b.to);
    g.addEventListener('click', go); g.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } });
    f.svg.append(g);
  });
  return f.svg;
}
function latencyChart(tb) {
  const vals = tb.buckets.flatMap(b => [b.p95].filter(v => v >= 0)), max = niceMax(Math.max(1, ...vals)), f = chartFrame(tb, max, v => fmtMs(v), 200, 'Latency over time: median and 95th percentile');
  for (const [key, cls] of [['p95', 'line-p95'], ['p50', 'line-p50']]) {
    const pts = tb.buckets.map((b, k) => b.n ? [f.x(k) + f.bw / 2, f.y(b[key])] : null);
    let d = ''; pts.forEach((p, k) => { if (!p) return; d += (d && pts[k - 1] ? ' L' : ' M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); });
    if (d) f.svg.append(sv('path', { d: d.trim(), class: cls }));
    pts.forEach((p, k) => { if (p) f.svg.append(sv('circle', { cx: p[0], cy: p[1], r: 2.5, class: cls + ' dotc' }, sv('title', null, key + ' ' + fmtMs(tb.buckets[k][key]) + ' at +' + relLabel(tb.buckets[k].from) + ' (' + tb.buckets[k].n + ' requests)'))); });
  }
  return f.svg;
}
function filterTime(from, to) {
  resetFilters();
  $('#q').value = 'time:' + (from / 1000).toFixed(1) + '-' + (to / 1000).toFixed(1);
  applyFilters(); show('requests');
}
function filterEndpoint(key) {
  const id = shortHash(key).slice(0, 8); S.epKeys.set(id, key);
  resetFilters(); $('#q').value = 'endpoint:' + id; applyFilters(); show('requests');
}
S.epSort = { key: 'count', dir: -1 };
function renderTimeline() {
  const root = $('#view-timeline');
  if (!S.entries.length) { root.replaceChildren(); return; }
  const tb = timeBuckets(S.entries), ins = timelineInsights(S.entries), eps = endpointStats(S.entries);
  const sorted = [...eps].sort((a, b) => { const k = S.epSort.key, x = a[k], y = b[k]; return (typeof x === 'string' ? x.localeCompare(y) : (x > y) - (x < y)) * S.epSort.dir || b.count - a.count; });
  const th = (k, l, num) => h('th', { class: (num ? 'num ' : '') + 'sortable' + (S.epSort.key === k ? ' sorted' : ''), 'data-k': k, onclick: () => { S.epSort = { key: k, dir: S.epSort.key === k ? -S.epSort.dir : (k === 'key' ? 1 : -1) }; renderTimeline(); } }, l + (S.epSort.key === k ? (S.epSort.dir > 0 ? ' ▲' : ' ▼') : ''));
  root.replaceChildren(h('div', { class: 'av' },
    h('div', { class: 'verdict' }, h('div', { class: 'vt', text: 'Timeline' }),
      h('p', { text: S.entries.length + ' requests over ' + fmtMs(tb.span) + ', starting ' + fmtDate(S.base) + '. Each bar is ' + fmtMs(tb.step) + '; click one to list its requests.' }),
      ins.length ? h('ul', { class: 'insights' }, ins.map(i => h('li', { class: 'ins-' + i.kind }, i.at != null ? h('a', { href: '#', onclick: ev => { ev.preventDefault(); filterTime(i.at, i.at + tb.step); }, text: i.text }) : i.text))) : h('p', { class: 'muted', text: 'No notable changes over time.' })),
    h('h3', { text: 'Requests over time' }),
    h('div', { class: 'legend' }, [['ok', 'OK (1xx–3xx)'], ['4xx', '4xx'], ['5xx', '5xx'], ['failed', 'failed / no response']].map(([k, l]) => h('span', null, h('i', { class: 'lg-' + k }), l))),
    h('div', { class: 'chartbox' }, requestsChart(tb)),
    h('h3', { text: 'Latency over time' }),
    h('div', { class: 'legend' }, h('span', null, h('i', { class: 'lg-p50' }), 'median (p50)'), h('span', null, h('i', { class: 'lg-p95' }), '95th percentile (p95)')),
    h('div', { class: 'chartbox' }, latencyChart(tb)),
    h('h3', { text: 'Endpoints (' + eps.length + ')' }),
    h('p', { class: 'note', text: 'IDs, UUIDs and hashes in paths are grouped (shown as :n, :uuid, :hash). Click a row to list its requests.' }),
    h('div', { class: 'tscroll' }, h('table', { class: 'simple eps' },
      h('colgroup', null, h('col'), ...['80px', '110px', '80px', '80px', '80px', '90px'].map(w => h('col', { style: { width: w } }))),
      h('thead', null, h('tr', null, th('key', 'Endpoint'), th('count', 'Requests', 1), th('errorRate', 'Errors', 1), th('p50', 'p50', 1), th('p95', 'p95', 1), th('max', 'Max', 1), th('avgBytes', 'Avg size', 1))),
      h('tbody', null, cappedRows(sorted, s => h('tr', { class: 'click' + (s.errorRate >= 0.5 ? ' bad-row' : ''), onclick: () => filterEndpoint(s.key), title: 'Statuses: ' + s.statuses.map(([st, c]) => (st || 'failed') + ' ×' + c).join(', ') },
        h('td', { class: 'url', text: s.key }), h('td', { class: 'num', text: String(s.count) }),
        h('td', { class: 'num', text: s.errors ? s.errors + ' (' + Math.round(s.errorRate * 100) + '%)' : '0' }),
        h('td', { class: 'num', text: fmtMs(s.p50) }), h('td', { class: 'num', text: fmtMs(s.p95) }), h('td', { class: 'num', text: fmtMs(s.max) }), h('td', { class: 'num', text: fmtBytes(Math.round(s.avgBytes)) })), 100, 7))))));
}
