async function loadText(text, name) {
  $('#loaderr').textContent = '';
  await stage('Reading ' + name + ' (' + fmtBytes(text.length) + ')…');
  let har;
  try { har = JSON.parse(text.replace(/^\ufeff/, '')); }
  catch (err) { stageDone(); showLoadError('Could not read ' + name + ' as JSON.\n' + err.message); return; }
  text = null; // let the raw text be garbage-collected; only the parsed HAR is kept
  await loadHar(har, name);
}
async function loadHar(har, name) {
  CMP.b = null;
  let n;
  try { await stage('Reading ' + name + '…'); n = normalize(har); } catch (err) { stageDone(); showLoadError(err.message); return; }
  Object.assign(S, { fileName: name, har, pages: n.pages, entries: n.entries, base: n.base, selected: null, types: new Set(), sort: { key: 'start', dir: 1 } });
  loadNotes();
  await stage('Finding problems in ' + n.entries.length.toLocaleString() + ' requests…');
  analyze();
  await stage('Checking authentication…');
  try { await analyzeAuth(); } catch (err) { A.error = (err && err.message) || String(err); }
  await stage('Diagnosing…');
  try { runDiagnostics(); } catch (err) { D.error = (err && err.message) || String(err); }
  await stage('Drawing…');
  setupFilters();
  const creator = har.log.creator ? [har.log.creator.name, har.log.creator.version].filter(Boolean).join(' ') : '';
  $('#fileinfo').textContent = name + ' · ' + S.entries.length + ' requests' + (creator ? ' · ' + creator : '');
  $('#fileinfo').title = $('#fileinfo').textContent;
  $$('#tabs button').forEach(b => (b.disabled = false));
  $('#btn-export').disabled = false;
  $('#b-req').textContent = S.entries.length;
  const errs = S.findings.filter(f => f.sev === 'error').length, warns = S.findings.filter(f => f.sev === 'warn').length;
  const bf = $('#b-find'); bf.textContent = S.findings.length; bf.className = 'badge' + (errs ? ' err' : warns ? ' warn' : '');
  const authFails = A.events.filter(v => !v.normal);
  const ba = $('#b-auth'); ba.textContent = authFails.length; ba.className = 'badge' + (authFails.some(v => !v.recovered) ? ' err' : authFails.length ? ' warn' : '');
  const dc = D.events.filter(v => !v.normal && v.sev !== 'info'), bd = $('#b-diag');
  bd.textContent = dc.length; bd.className = 'badge' + (dc.some(v => v.sev === 'error') ? ' err' : dc.length ? ' warn' : '');
  $('#btn-compare').disabled = false;
  renderOverview(); renderFindings(); renderAuth(); renderDiag(); renderCompare(); applyFilters();
  stageDone();
  show('overview');
}
function showLoadError(msg) { show('empty'); $('#loaderr').textContent = msg; }
function readFile(file) {
  if (!file) return;
  const r = new FileReader();
  r.onload = () => loadText(String(r.result), file.name);
  r.onerror = () => showLoadError('Could not read the file: ' + (r.error && r.error.message));
  r.readAsText(file);
}

/* ---------- view switching ---------- */
function show(view) {
  S.view = view;
  $$('section.view').forEach(s => s.classList.add('hidden'));
  $(view === 'empty' ? '#empty' : '#view-' + view).classList.remove('hidden');
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  if (view === 'requests') requestAnimationFrame(renderRows);
}
function openRequest(e, tab) {
  show('requests');
  if (!S.filtered.includes(e)) { resetFilters(); }
  select(e, tab);
}

/* ---------- overview ---------- */
function bars(rows, max) {
  return rows.map(([label, n, title]) => h('div', { class: 'barrow', title: title || '' },
    h('span', { text: label, style: { overflow: 'hidden', 'text-overflow': 'ellipsis', 'white-space': 'nowrap' } }),
    h('div', { class: 'track' }, h('div', { class: 'fill', style: { width: (max ? n / max * 100 : 0) + '%' } })),
    h('span', { class: 'n', text: String(n) })));
}
function reqTable(list, valueLabel, valueFn) {
  return h('table', { class: 'simple' },
    h('colgroup', null, h('col', { style: { width: '54px' } }), h('col'), h('col', { style: { width: '80px' } })),
    h('thead', null, h('tr', null, h('th', { text: 'Status' }), h('th', { text: 'URL' }), h('th', { class: 'num', text: valueLabel }))),
    h('tbody', null, list.map(e => h('tr', { class: 'click', onclick: () => openRequest(e) },
      h('td', { text: e.status || 'failed' }),
      h('td', { class: 'url', title: e.url, text: e.host + e.path }),
      h('td', { class: 'num', text: valueFn(e) })))));
}
function renderOverview() {
  const E = S.entries;
  const failed = E.filter(isFailed).length;
  const errs = E.filter(e => e.status >= 400).length;
  const transfer = E.reduce((a, e) => a + e.transfer, 0);
  const content = E.reduce((a, e) => a + e.contentSize, 0);
  const span = E.reduce((a, e) => Math.max(a, e.start + e.time), 0);
  const hosts = new Map();
  for (const e of E) {
    const k = e.host || '(none)';
    const d = hosts.get(k) || { n: 0, bytes: 0, time: 0, errs: 0 };
    d.n++; d.bytes += e.transfer; d.time += e.time; if (isFailed(e) || e.status >= 400) d.errs++;
    hosts.set(k, d);
  }
  const card = (v, l, cls, title) => h('div', { class: 'card ' + (cls || ''), title: title || '' }, h('div', { class: 'v', text: v }), h('div', { class: 'l', text: l }));
  const pt = S.pages.map(p => p.pageTimings || {});
  const onLoad = pt.map(x => x.onLoad).filter(x => typeof x === 'number' && x >= 0);
  const onDCL = pt.map(x => x.onContentLoad).filter(x => typeof x === 'number' && x >= 0);

  const cards = h('div', { class: 'cards' },
    card(String(E.length), 'requests'),
    card(String(failed), 'failed (no response)', failed ? 'err' : ''),
    card(String(errs), 'HTTP 4xx / 5xx', errs ? (E.some(e => e.status >= 500) ? 'err' : 'warn') : ''),
    card(fmtBytes(transfer), 'transferred', '', fmtBytes(content) + ' uncompressed content'),
    card(fmtMs(span), 'first request → last byte'),
    onLoad.length ? card(fmtMs(onLoad[0]), 'page load event', '', onDCL.length ? 'DOMContentLoaded at ' + fmtMs(onDCL[0]) : '') : null,
    card(String(hosts.size), 'domains'),
    A.events.some(v => !v.normal) ? card(String(A.events.filter(v => !v.normal).length), 'authentication failures', 'err', 'See the Authentication tab') : null);

  // Findings summary
  const groups = groupFindings();
  const fbox = h('div', { class: 'box' }, h('h3', { text: 'Findings' }),
    groups.length ? h('table', { class: 'simple' },
      h('colgroup', null, h('col', { style: { width: '62px' } }), h('col'), h('col', { style: { width: '50px' } })),
      h('tbody', null, groups.map(g => h('tr', { class: 'click', onclick: () => { show('findings'); const d = document.getElementById('fg-' + g.code); if (d) { d.open = true; d.scrollIntoView({ block: 'start' }); } } },
        h('td', null, h('span', { class: 'sev ' + g.sev, text: g.sev })),
        h('td', { text: RULES[g.code].title }),
        h('td', { class: 'num', text: String(g.items.length) })))))
      : h('p', { class: 'allgood', text: '✓ No problems detected.' }));

  const slow = [...E].sort((a, b) => b.time - a.time).slice(0, 10);
  const big = [...E].sort((a, b) => b.transfer - a.transfer).slice(0, 10).filter(e => e.transfer > 0);

  const statusCounts = new Map();
  for (const e of E) { const k = isFailed(e) ? 'failed' : String(e.status); statusCounts.set(k, (statusCounts.get(k) || 0) + 1); }
  const sc = [...statusCounts].sort((a, b) => b[1] - a[1]);
  const typeCounts = new Map();
  for (const e of E) typeCounts.set(e.type, (typeCounts.get(e.type) || 0) + 1);
  const tc = [...typeCounts].sort((a, b) => b[1] - a[1]);
  const hostRows = [...hosts].sort((a, b) => b[1].n - a[1].n);

  const dcounts = diagCounts();
  const dbox = h('div', { class: 'box' }, h('h3', { text: 'Diagnosis' }),
    dcounts.size ? h('table', { class: 'simple' }, h('colgroup', null, h('col'), h('col', { style: { width: '50px' } })),
      h('tbody', null, DCATS.filter(([k]) => dcounts.get(k)).map(([k, l]) => h('tr', { class: 'click', onclick: () => { show('diag'); const sct = document.getElementById('dsec-' + k); if (sct) sct.scrollIntoView({ block: 'start' }); } }, h('td', { text: l }), h('td', { class: 'num', text: String(dcounts.get(k)) })))))
      : h('p', { class: 'allgood', text: '✓ Nothing diagnosed.' }),
    A.events.some(v => !v.normal) ? h('p', { class: 'note' }, h('a', { href: '#', onclick: ev => { ev.preventDefault(); show('auth'); }, text: A.events.filter(v => !v.normal).length + ' authentication failure(s) →' })) : null);
  $('#view-overview').replaceChildren(h('div', { class: 'ov' },
    cards, dbox, fbox,
    h('div', { class: 'box' }, h('h3', { text: 'Status codes' }), bars(sc.map(([k, n]) => [k, n]), sc.length ? sc[0][1] : 0),
      h('h3', { text: 'Resource types', style: { 'margin-top': '14px' } }), bars(tc.map(([k, n]) => [TYPE_LABEL[k], n]), tc.length ? tc[0][1] : 0)),
    h('div', { class: 'box' }, h('h3', { text: 'Slowest requests' }), reqTable(slow, 'Time', e => fmtMs(e.time))),
    h('div', { class: 'box' }, h('h3', { text: 'Largest transfers' }), big.length ? reqTable(big, 'Size', e => fmtBytes(e.transfer)) : h('p', { class: 'muted', text: 'No size information in this HAR.' })),
    h('div', { class: 'box wide' }, h('h3', { text: 'Domains' }),
      h('table', { class: 'simple' },
        h('colgroup', null, h('col'), h('col', { style: { width: '90px' } }), h('col', { style: { width: '90px' } }), h('col', { style: { width: '90px' } }), h('col', { style: { width: '90px' } })),
        h('thead', null, h('tr', null, h('th', { text: 'Domain' }), h('th', { class: 'num', text: 'Requests' }), h('th', { class: 'num', text: 'Errors' }), h('th', { class: 'num', text: 'Transferred' }), h('th', { class: 'num', text: 'Avg time' }))),
        h('tbody', null, hostRows.map(([k, d]) => h('tr', { class: 'click', title: 'Show requests to ' + k, onclick: () => { resetFilters(); $('#f-domain').value = k === '(none)' ? '' : k; applyFilters(); show('requests'); } },
          h('td', { class: 'url', text: k }), h('td', { class: 'num', text: String(d.n) }),
          h('td', { class: 'num', text: String(d.errs), style: d.errs ? { color: 'var(--err)' } : {} }),
          h('td', { class: 'num', text: fmtBytes(d.bytes) }), h('td', { class: 'num', text: fmtMs(d.time / d.n) }))))))
  ));
}

function renderFindings() {
  const groups = groupFindings();
  const LIMIT = 200;
  $('#view-findings').replaceChildren(h('div', { class: 'fv' },
    groups.length ? null : h('p', { class: 'allgood', text: '✓ No problems detected in this HAR.' }),
    groups.map(g => h('details', { id: 'fg-' + g.code, open: g.sev !== 'info' ? true : null },
      h('summary', null, h('span', { class: 'sev ' + g.sev, text: g.sev }), h('span', { class: 't', text: RULES[g.code].title }), h('span', { class: 'badge', text: String(g.items.length) })),
      h('p', { class: 'help', text: RULES[g.code].help }),
      h('table', { class: 'simple' },
        h('colgroup', null, h('col', { style: { width: '50px' } }), h('col', { style: { width: '60px' } }), h('col', { style: { width: '70px' } }), h('col'), h('col', { style: { width: '32%' } })),
        h('tbody', null, g.items.slice(0, LIMIT).map(f => h('tr', { class: 'click', onclick: () => openRequest(f.e, 'issues') },
          h('td', { class: 'muted', text: '#' + f.e.i }),
          h('td', { text: f.e.status || 'failed' }),
          h('td', { text: f.e.method }),
          h('td', { class: 'url', title: f.e.url, text: f.e.url }),
          h('td', { text: f.detail, title: f.detail }))))),
      g.items.length > LIMIT ? h('div', { class: 'more muted', text: '… and ' + (g.items.length - LIMIT) + ' more. Use the Requests tab with “With findings” to see all.' }) : null))));
}

/* ---------- requests: filters ---------- */
function setupFilters() {
  const hosts = [...new Set(S.entries.map(e => e.host).filter(Boolean))].sort();
  $('#f-domain').replaceChildren(h('option', { value: '', text: 'All domains' }), ...hosts.map(x => h('option', { value: x, text: x })));
  const pg = $('#f-page');
  pg.replaceChildren(h('option', { value: '', text: 'All pages' }), ...S.pages.map(p => h('option', { value: p.id, text: (p.title || p.id || '').slice(0, 80) })));
  pg.classList.toggle('hidden', S.pages.length < 2);
  const present = new Set(S.entries.map(e => e.type));
  const chips = $('#type-chips');
  chips.replaceChildren(h('button', { class: 'chip on', 'data-type': '', text: 'All' }),
    ...Object.keys(TYPE_LABEL).filter(k => present.has(k)).map(k => h('button', { class: 'chip', 'data-type': k, text: TYPE_LABEL[k] })));
  resetFilters();
}
function resetFilters() {
  $('#q').value = ''; $('#f-status').value = ''; $('#f-domain').value = ''; $('#f-page').value = '';
  $('#f-issues').checked = false; $('#f-deep').checked = false; S.types.clear(); syncChips(); applyFilters();
}
function syncChips() {
  $$('#type-chips .chip').forEach(c => c.classList.toggle('on', c.dataset.type ? S.types.has(c.dataset.type) : S.types.size === 0));
}
function parseSize(v) { const m = /^([\d.]+)\s*(b|k|kb|m|mb|g|gb)?$/i.exec(v); if (!m) return NaN; const mult = { b: 1, k: 1024, kb: 1024, m: 1048576, mb: 1048576, g: 1073741824, gb: 1073741824 }[(m[2] || 'b').toLowerCase()]; return parseFloat(m[1]) * mult; }
function parseDur(v) { const m = /^([\d.]+)\s*(ms|s)?$/i.exec(v); if (!m) return NaN; return parseFloat(m[1]) * ((m[2] || 'ms').toLowerCase() === 's' ? 1000 : 1); }
function parseQuery(s) {
  return s.trim().split(/\s+/).filter(Boolean).map(tok => {
    let neg = false;
    if (tok.length > 1 && tok[0] === '-') { neg = true; tok = tok.slice(1); }
    const m = /^(status|method|domain|host|type|mime|larger|slower|auth|diag|note):(.+)$/i.exec(tok);
    return m ? { neg, key: m[1].toLowerCase(), val: m[2].toLowerCase() } : { neg, key: null, val: tok.toLowerCase() };
  });
}
function haystack(e) {
  if (e._hay == null) {
    const r = e.raw.request || {}, s = e.raw.response || {};
    const parts = [e.url];
    for (const x of (r.headers || [])) parts.push(x.name + ': ' + x.value);
    for (const x of (s.headers || [])) parts.push(x.name + ': ' + x.value);
    if (r.postData && r.postData.text) parts.push(String(r.postData.text).slice(0, 200000));
    const body = bodyText(s.content || {}); if (body) parts.push(body.slice(0, 500000));
    e._hay = parts.join('\n').toLowerCase();
  }
  return e._hay;
}
function tokMatch(e, t, deep) {
  const v = t.val;
  switch (t.key) {
    case 'status':
      if (v === 'failed' || v === '0') return isFailed(e);
      if (/^[1-5]xx$/.test(v)) return Math.floor(e.status / 100) === +v[0];
      return String(e.status) === v;
    case 'method': return e.method.toLowerCase() === v;
    case 'domain': case 'host': return e.host.toLowerCase().includes(v);
    case 'type': return e.type === v || TYPE_LABEL[e.type].toLowerCase().startsWith(v);
    case 'mime': return e.mime.toLowerCase().includes(v);
    case 'larger': return e.transfer > parseSize(v);
    case 'slower': return e.time > parseDur(v);
    case 'note': { const n = S.notes.get(e.i); return !!n && (v === 'starred' ? n.star : v === 'text' ? !!(n.text || '').trim() : n.star || !!(n.text || '').trim()); }
    case 'diag': return !!(e.diag && e.diag.some(x => !x.normal && (v === 'any' || x.cat === v || x.sev === v)));
    case 'auth': return v === 'fail' ? !!(e.auth && e.auth.event && !e.auth.event.normal) : !!(e.auth || e.oauthRole || e.saml);
    default: return (deep ? haystack(e) : e.url.toLowerCase()).includes(v);
  }
}
function applyFilters() {
  const q = parseQuery($('#q').value);
  const st = $('#f-status').value, dom = $('#f-domain').value, pg = $('#f-page').value;
  const issues = $('#f-issues').checked, deep = $('#f-deep').checked;
  S.filtered = S.entries.filter(e => {
    if (pg && e.pageref !== pg) return false;
    if (dom && e.host !== dom) return false;
    if (S.types.size && !S.types.has(e.type)) return false;
    if (issues && !e.findings.length) return false;
    if (st === 'errors' && !(isFailed(e) || e.status >= 400)) return false;
    if (st === 'failed' && !isFailed(e)) return false;
    if (/^\d$/.test(st) && Math.floor(e.status / 100) !== +st) return false;
    for (const t of q) if (tokMatch(e, t, deep) === t.neg) return false;
    return true;
  });
  sortFiltered();
  S.span = S.filtered.reduce((a, e) => Math.max(a, e.start + e.time), 0);
  S.minStart = S.filtered.reduce((a, e) => Math.min(a, e.start), Infinity);
  if (S.minStart === Infinity) S.minStart = 0;
  $('#count').textContent = S.filtered.length === S.entries.length ? S.entries.length + ' requests' : S.filtered.length + ' of ' + S.entries.length + ' requests';
  renderRows();
}
function sortFiltered() {
  const { key, dir } = S.sort;
  S.filtered.sort((a, b) => {
    let x = a[key], y = b[key];
    if (key === 'start') { x = a.start; y = b.start; if (x === y) return (a.i - b.i) * dir; }
    if (typeof x === 'string') return x.localeCompare(y) * dir || (a.i - b.i);
    return ((x > y) - (x < y)) * dir || (a.i - b.i);
  });
  $$('#thead > div').forEach(d => {
    const on = d.dataset.key === key;
    d.classList.toggle('sorted', on);
    d.textContent = d.textContent.replace(/ [▲▼]$/, '') + (on ? (dir > 0 ? ' ▲' : ' ▼') : '');
  });
}

/* ---------- requests: virtualised table ---------- */
const ROW_H = 26;
function renderRows() {
  const vp = $('#rows'), inner = $('#rows-inner');
  if (!S.filtered.length) {
    inner.style.height = 'auto';
    inner.replaceChildren(h('div', { class: 'nomatch', text: S.entries.length ? 'No requests match the current filters.' : '' }));
    return;
  }
  inner.style.height = S.filtered.length * ROW_H + 'px';
  const top = vp.scrollTop, height = vp.clientHeight || 600;
  const first = Math.max(0, Math.floor(top / ROW_H) - 8);
  const last = Math.min(S.filtered.length, Math.ceil((top + height) / ROW_H) + 8);
  const span = Math.max(1, S.span - S.minStart);
  const frag = document.createDocumentFragment();
  for (let k = first; k < last; k++) {
    const e = S.filtered[k];
    const sc = statusClass(e);
    const ws = worstSev(e);
    const left = (e.start - S.minStart) / span * 100;
    const width = Math.max(e.time / span * 100, 0.2);
    const t = e.timings, tot = t.blocked + t.dns + t.connect + t.send + t.wait + t.receive;
    const segs = tot > 0 ? [['blocked', t.blocked], ['dns', t.dns], ['connect', t.tcp], ['ssl', t.ssl], ['send', t.send], ['wait', t.wait], ['receive', t.receive]]
      .filter(s => s[1] > 0).map(s => h('span', { class: 'ph-' + s[0], style: { width: (s[1] / tot * 100) + '%' } })) : [];
    frag.append(h('div', {
      class: 'grid-row row' + (e === S.selected ? ' sel' : '') + (sc === 'err' ? ' st-err' : sc === 'warn' ? ' st-warn' : ''),
      style: { top: k * ROW_H + 'px' }, 'data-k': k, title: e.url
    },
      h('div', { class: 'c-idx muted' }, ws ? h('span', { class: 'dot ' + ws }) : null, String(e.i), noteMark(e)),
      h('div', { class: 'c-status', text: isFailed(e) ? 'failed' : String(e.status) }),
      h('div', { class: 'c-method', text: e.method }),
      h('div', { class: 'c-domain', text: e.host }),
      h('div', { class: 'c-path', text: S.selected ? (e.u ? (e.u.pathname.split('/').filter(Boolean).pop() || e.host) + e.u.search : e.url) : e.path }),
      h('div', { class: 'c-type', text: TYPE_LABEL[e.type] }),
      h('div', { class: 'c-size', text: e.fromCache && !e.transfer ? '(cache)' : fmtBytes(e.transfer) }),
      h('div', { class: 'c-time', text: fmtMs(e.time) }),
      h('div', { class: 'c-wf' }, h('div', { class: 'wf' }, h('div', { class: 'bar', style: { left: Math.min(left, 99.8) + '%', width: width + '%' } }, segs)))));
  }
  inner.replaceChildren(frag);
}
function select(e, tab) {
  S.selected = e;
  if (tab) S.dtab = tab;
  $('#split').classList.toggle('has-detail', !!e);
  $('#detail').classList.toggle('hidden', !e);
  if (e) {
    const k = S.filtered.indexOf(e), vp = $('#rows');
    if (k >= 0) {
      const y = k * ROW_H;
      if (y < vp.scrollTop || y + ROW_H > vp.scrollTop + vp.clientHeight) vp.scrollTop = Math.max(0, y - vp.clientHeight / 2);
    }
    renderDetail();
  }
  renderRows();
}

const MAX_SHOW = 1_000_000;
function prettyBody(text, mime) {
  if (text == null) return null;
  let out = text, note = '';
  if (/json/i.test(mime) || /^\s*[\[{]/.test(text)) {
    try { out = JSON.stringify(JSON.parse(text), null, 2); note = 'JSON (formatted)'; } catch (_) { /* not JSON */ }
  }
  if (out.length > MAX_SHOW) { note = (note ? note + ' · ' : '') + 'showing first ' + fmtBytes(MAX_SHOW) + ' of ' + fmtBytes(out.length); out = out.slice(0, MAX_SHOW); }
  return { out, note };
}
function kvList(rows) {
  if (!rows || !rows.length) return h('p', { class: 'note', text: 'None.' });
  return h('div', { class: 'kv' }, rows.map(([k, v]) => [h('div', { class: 'k', text: k }), h('div', { class: 'v', text: v == null ? '' : String(v) })]));
}
function timingRows(e) {
  const t = e.timings;
  const phases = [
    ['blocked', 'Queued / stalled', t.blocked], ['dns', 'DNS lookup', t.dns], ['connect', 'TCP connect', t.tcp], ['ssl', 'TLS handshake', t.ssl],
    ['send', 'Request sent', t.send], ['wait', 'Waiting (TTFB)', t.wait], ['receive', 'Content download', t.receive]];
  const total = Math.max(e.time, phases.reduce((a, p) => a + p[2], 0), 0.0001);
  let offset = 0;
  return phases.map(([k, label, v]) => {
    const row = h('div', { class: 'trow' }, h('span', { text: label }),
      h('div', { class: 'track' }, v > 0 ? h('span', { class: 'ph-' + k, style: { left: (offset / total * 100) + '%', width: (v / total * 100) + '%' } }) : null),
      h('span', { class: 'n', text: v > 0 ? fmtMs(v) : '—' }));
    offset += v;
    return row;
  });
}
function renderDetail() {
  const e = S.selected; if (!e) return;
  const req = e.raw.request || {}, res = e.raw.response || {};
  const sc = statusClass(e);
  const tabs = [['headers', 'Headers'], ['payload', 'Payload'], ['response', 'Response'], ['timing', 'Timing'], ['cookies', 'Cookies'], ['issues', 'Findings' + (e.findings.length ? ' (' + e.findings.length + ')' : '')]];
  if (hasAuthInfo(e)) tabs.splice(5, 0, ['auth', 'Auth' + (e.auth && e.auth.event && !e.auth.event.normal ? ' ⚠' : '')]);
  if (e.diag && e.diag.length) tabs.splice(tabs.length - 1, 0, ['diag', 'Diagnosis' + (e.diag.some(v => !v.normal && v.sev !== 'info') ? ' ⚠' : '')]);
  if (!tabs.some(t => t[0] === S.dtab)) S.dtab = 'headers';

  const body = h('div', { class: 'dbody' });
  const fill = () => {
    body.replaceChildren(h('div', null, detailTab(e, S.dtab)));
    $$('.dtabs button', pane).forEach(b => b.classList.toggle('active', b.dataset.tab === S.dtab));
  };
  const pane = $('#detail');
  const nc = notesControls(e);
  pane.replaceChildren(
    h('div', { class: 'dhead' },
      h('div', { class: 'top' },
        h('span', { class: 'status-pill ' + sc, text: isFailed(e) ? 'failed' : e.status + ' ' + e.statusText }),
        h('b', { text: e.method }),
        h('span', { class: 'muted', text: '#' + e.i + ' · ' + fmtMs(e.time) + ' · ' + fmtBytes(e.transfer) }),
        h('span', { class: 'spacer' }),
        nc.star, nc.btn,
        h('button', { id: 'btn-decode', title: 'Decode the selected text (or paste some): JWT, base64, URL encoding, gzip, hex, timestamps', onclick: () => openDecode(String(window.getSelection ? window.getSelection() : '').trim()), text: 'Decode…' }),
        h('button', { id: 'btn-diff', title: 'Compare this response with another request (same endpoint first)', onclick: () => openDiff(e), text: 'Compare…' }),
        copyMenu(e),
        h('button', { title: 'Close (Esc)', onclick: () => select(null), text: '✕' })),
      h('div', { class: 'url', text: e.url }), nc.ta),
    h('div', { class: 'dtabs' }, tabs.map(([k, l]) => h('button', { 'data-tab': k, text: l, onclick: () => { S.dtab = k; fill(); } }))),
    body);
  fill();
}
function detailTab(e, tab) {
  const req = e.raw.request || {}, res = e.raw.response || {}, content = res.content || {};
  if (tab === 'headers') {
    const started = e.raw.startedDateTime || '';
    const chain = [];
    let c = e; while (c.redirectFrom && chain.length < 30) { c = c.redirectFrom; if (chain.includes(c)) break; }
    for (let x = c, n = 0; x && n < 30; x = x.redirectTo, n++) chain.push(x);
    return [
      h('h4', { text: 'General' }),
      kvList([
        ['Request URL', e.url], ['Method', e.method], ['Status', isFailed(e) ? '(failed)' : e.status + ' ' + e.statusText],
        e.error ? ['Error', e.error] : null,
        ['HTTP version', e.httpVersion || '—'], ['Remote address', e.serverIP || '—'], e.connection ? ['Connection ID', e.connection] : null,
        ['Type', TYPE_LABEL[e.type] + (e.mime ? ' (' + e.mime + ')' : '')],
        ['Started', started + (started ? '  (+' + fmtMs(e.start) + ')' : '')], ['Duration', fmtMs(e.time)],
        ['Transferred', fmtBytes(e.transfer)], ['Content size', fmtBytes(e.contentSize)],
        e.fromCache ? ['Served from', e.fromCache] : null,
        e.redirectTarget ? ['Redirects to', e.redirectTarget] : null,
        e.raw._initiator && e.raw._initiator.url ? ['Initiator', e.raw._initiator.url + (e.raw._initiator.lineNumber != null ? ':' + e.raw._initiator.lineNumber : '')] : (e.raw._initiator && e.raw._initiator.type ? ['Initiator', e.raw._initiator.type] : null),
      ].filter(Boolean)),
      chain.length > 1 ? [h('h4', { text: 'Redirect chain' }), h('div', { class: 'chain' }, chain.map(x => h('div', null,
        x === e ? h('b', { text: '▶ ' + (x.status || 'failed') + '  ' + x.url }) : h('a', { href: '#', text: (x.status || 'failed') + '  ' + x.url, onclick: ev => { ev.preventDefault(); select(x); } }))))] : null,
      h('h4', { text: 'Response headers (' + (res.headers || []).length + ')' }),
      kvList((res.headers || []).map(x => [x.name, x.value])),
      h('h4', { text: 'Request headers (' + (req.headers || []).length + ')' }),
      kvList((req.headers || []).map(x => [x.name, x.value])),
    ].flat();
  }
  if (tab === 'payload') {
    const out = [h('h4', { text: 'Query string parameters' }), kvList((req.queryString || []).map(x => [x.name, x.value]))];
    const pd = req.postData;
    out.push(h('h4', { text: 'Request body' }));
    if (!pd) out.push(h('p', { class: 'note', text: 'No request body.' }));
    else {
      if (pd.mimeType) out.push(h('p', { class: 'note', text: pd.mimeType }));
      if (Array.isArray(pd.params) && pd.params.length) out.push(kvList(pd.params.map(p => [p.name, p.fileName ? '(file: ' + p.fileName + ')' : p.value])));
      if (pd.text != null) {
        let text = String(pd.text);
        if (/x-www-form-urlencoded/i.test(pd.mimeType || '') && !(pd.params && pd.params.length)) {
          try { out.push(kvList([...new URLSearchParams(text)])); } catch (_) { /* show raw */ }
        }
        out.push(...bodyViewer(text, pd.mimeType || ''));
      }
    }
    return out;
  }
  if (tab === 'response') {
    const mime = content.mimeType || e.mime;
    const out = [h('p', { class: 'note', text: [mime, content.encoding ? 'encoding: ' + content.encoding : '', content.compression ? 'saved by compression: ' + fmtBytes(content.compression) : ''].filter(Boolean).join(' · ') })];
    if (content.text == null || content.text === '') {
      out.push(h('p', { class: 'note', text: e.contentSize ? 'The response body was not saved in this HAR. (Some browsers omit bodies, or the HAR was exported without content.)' : 'Empty response body.' }));
      if (content.comment) out.push(h('p', { class: 'note', text: content.comment }));
      return out;
    }
    if (/^image\/(png|jpe?g|gif|webp|avif|bmp|x-icon|vnd\.microsoft\.icon|svg\+xml)$/i.test(mime)) {
      const src = content.encoding === 'base64' ? 'data:' + mime + ';base64,' + content.text : 'data:' + mime + ';charset=utf-8,' + encodeURIComponent(content.text);
      const dims = h('p', { class: 'note' });
      out.push(h('img', { class: 'imgprev', src, alt: 'response image', onload: ev => { dims.textContent = ev.target.naturalWidth + ' × ' + ev.target.naturalHeight + ' px'; } }), dims);
      return out;
    }
    if (content.encoding === 'base64' && !isTextMime(mime)) {
      out.push(h('p', { class: 'note', text: 'Binary content (' + fmtBytes(Math.floor(content.text.length * 3 / 4)) + '), not shown.' }));
      return out;
    }
    const body = bodyText(content);
    if (body == null) { out.push(h('p', { class: 'note', text: 'Could not decode the body.' })); return out; }
    out.push(...bodyViewer(body, mime));
    return out;
  }
  if (tab === 'timing') {
    const t = e.timings;
    const ttfbStart = t.blocked + t.dns + t.connect + t.send;
    return [
      h('h4', { text: 'Where the time went' }),
      timingRows(e),
      h('div', { class: 'trow', style: { 'margin-top': '8px', 'font-weight': '600' } }, h('span', { text: 'Total' }), h('span'), h('span', { class: 'n', text: fmtMs(e.time) })),
      h('div', { class: 'legend' }, [['blocked', 'Queued'], ['dns', 'DNS'], ['connect', 'TCP'], ['ssl', 'TLS'], ['send', 'Send'], ['wait', 'Waiting'], ['receive', 'Download']].map(([k, l]) => h('span', null, h('i', { class: 'ph-' + k }), l))),
      h('p', { class: 'note', text: 'Started ' + fmtMs(e.start) + ' after the first request. First byte arrived after ' + fmtMs(ttfbStart + t.wait) + '. ' +
        (t.dns === 0 && t.connect === 0 ? 'No DNS or connect time: an existing connection was reused (or the browser did not record it). ' : '') +
        (t.wait > Math.max(t.receive, t.blocked, t.dns, t.connect) && t.wait > 200 ? 'Most of the time was spent waiting for the server.' : '') }),
    ].flat();
  }
  if (tab === 'cookies') {
    const ck = list => list && list.length ? h('table', { class: 'simple' },
      h('thead', null, h('tr', null, ['Name', 'Value', 'Domain', 'Path', 'Expires', 'Flags'].map(x => h('th', { text: x })))),
      h('tbody', null, list.map(c => h('tr', null,
        h('td', { class: 'mono', text: c.name || '' }), h('td', { class: 'mono', text: c.value || '', title: c.value || '' }),
        h('td', { text: c.domain || '' }), h('td', { text: c.path || '' }), h('td', { text: c.expires || '' }),
        h('td', { text: [c.httpOnly ? 'HttpOnly' : '', c.secure ? 'Secure' : '', c.sameSite ? 'SameSite=' + c.sameSite : ''].filter(Boolean).join(' ') })))))
      : h('p', { class: 'note', text: 'None.' });
    return [h('h4', { text: 'Sent with the request' }), ck(req.cookies), h('h4', { text: 'Set by the response' }), ck(res.cookies)];
  }
  if (tab === 'diag') return e.diag && e.diag.length ? [...e.diag].sort((a, b) => dSevRank[a.sev] - dSevRank[b.sev]).map(v => [v.e && v.e !== e ? h('p', { class: 'note' }, 'Part of a group; main request ', stepLink(v.e)) : null, dCard(v, v.e === e)]).flat() : [h('p', { class: 'note', text: 'Nothing diagnosed for this request.' })];
  if (tab === 'auth') return hasAuthInfo(e) ? authDetail(e) : [h('p', { class: 'note', text: 'No authentication information on this request.' })];
  if (tab === 'issues') {
    if (!e.findings.length) return [h('p', { class: 'allgood', text: '✓ No findings for this request.' })];
    return e.findings.map(f => h('div', { class: 'finding' },
      h('div', null, h('span', { class: 'sev ' + f.sev, text: f.sev }), ' ', h('span', { class: 't', text: RULES[f.code].title })),
      f.detail ? h('p', { class: 'mono', text: f.detail }) : null,
      h('p', { text: RULES[f.code].help })));
  }
  return [];
}

function exportCsv() { download(S.fileName.replace(/\.(har|json)$/i, '') + '-requests.csv', csvText(S.filtered), 'text/csv'); }
function csvText(list) {
  const cols = ['#', 'started_ms', 'method', 'status', 'status_text', 'url', 'domain', 'type', 'mime', 'transfer_bytes', 'content_bytes', 'time_ms', 'blocked_ms', 'dns_ms', 'connect_ms', 'tls_ms', 'send_ms', 'wait_ms', 'receive_ms', 'http_version', 'server_ip', 'error', 'findings'];
  const lines = [cols.join(',')];
  for (const e of list) {
    const t = e.timings;
    lines.push([e.i, Math.round(e.start), e.method, e.status, e.statusText, e.url, e.host, TYPE_LABEL[e.type], e.mime, e.transfer, e.contentSize, e.time.toFixed(1),
      t.blocked.toFixed(1), t.dns.toFixed(1), t.tcp.toFixed(1), t.ssl.toFixed(1), t.send.toFixed(1), t.wait.toFixed(1), t.receive.toFixed(1),
      e.httpVersion, e.serverIP, e.error, e.findings.map(f => RULES[f.code].title).join('; ')].map(csvCell).join(','));
  }
  return lines.join('\r\n');
}

/* ======================================================================
   Authentication analysis
   Works out which authentication methods are in use, finds failed
   authentication / authorization / sign-in attempts and explains why
   each one failed, from evidence in the HAR.
   ====================================================================== */

function noteMark(e) { const n = S.notes.get(e.i); if (!n || !(n.star || (n.text || '').trim())) return null; return h('span', { class: 'nmark', title: n.text || 'Bookmarked', text: n.star ? ' ★' : ' ✎' }); }
