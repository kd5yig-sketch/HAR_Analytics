/* ---------- body viewer: JSON tree, path search, HTML preview ---------- */
S.bodyMode = 'tree';
function jsonTree(value, key, depth = 0) {
  const kid = (k, v) => jsonTree(v, k, depth + 1);
  const label = key == null ? null : h('span', { class: 'jk', text: (typeof key === 'number' ? key : JSON.stringify(key)) + ': ' });
  if (value === null || typeof value !== 'object') {
    const t = value === null ? 'null' : typeof value;
    return h('div', { class: 'jrow' }, label, h('span', { class: 'jv j-' + t, text: t === 'string' ? JSON.stringify(value) : String(value) }));
  }
  const arr = Array.isArray(value), keys = arr ? value.map((_, i) => i) : Object.keys(value);
  const sum = arr ? '[' + keys.length + ']' : '{' + keys.length + '}';
  if (!keys.length) return h('div', { class: 'jrow' }, label, h('span', { class: 'jv', text: arr ? '[]' : '{}' }));
  return h('details', { class: 'jnode', open: depth < 2 ? true : null },
    h('summary', null, label, h('span', { class: 'jsum', text: sum })),
    h('div', { class: 'jkids' }, capped(keys, k => kid(k, value[k]), 200)));
}
function bodyViewer(text, mime) {
  if (text == null) return [];
  let parsed; const isJson = /^\s*[[{]/.test(text) && (() => { try { parsed = JSON.parse(text); return true; } catch (_) { return false; } })();
  const raw = () => { const p = prettyBody(text, mime); return [p.note ? h('p', { class: 'note', text: p.note }) : null, h('pre', { class: 'body', text: p.out })]; };
  if (isJson) {
    const view = h('div', { class: 'bview' });
    const out = h('div', { class: 'jmatches' });
    const q = h('input', { type: 'search', class: 'jpath', placeholder: 'Find by path, e.g. data.items[*].id or ..message', 'aria-label': 'Find by JSON path' });
    const run = () => {
      const expr = q.value.trim();
      if (!expr) { out.replaceChildren(); return; }
      try {
        const r = jsonPath(parsed, expr);
        out.replaceChildren(r.length ? h('div', { class: 'note', text: r.length + ' match' + (r.length > 1 ? 'es' : '') }) : h('div', { class: 'note', text: 'No matches.' }),
          h('div', { class: 'kv' }, r.slice(0, 500).map(m => [h('div', { class: 'k', text: m.path }), h('div', { class: 'v', text: typeof m.v === 'string' ? m.v : JSON.stringify(m.v) })])));
      } catch (err) { out.replaceChildren(h('div', { class: 'note errtxt', text: 'Path error: ' + err.message })); }
    };
    let t; q.oninput = () => { clearTimeout(t); t = setTimeout(run, 150); };
    const draw = () => { view.replaceChildren(...[].concat(S.bodyMode === 'tree' ? h('div', { class: 'jtree' }, jsonTree(parsed)) : raw()).filter(Boolean)); $$('.bmode button', bar).forEach(b => b.classList.toggle('on', b.dataset.mode === S.bodyMode)); };
    const bar = h('div', { class: 'btool' }, h('span', { class: 'bmode' }, ['tree', 'raw'].map(m => h('button', { 'data-mode': m, class: 'chip', text: m === 'tree' ? 'Tree' : 'Raw', onclick: () => { S.bodyMode = m; draw(); } }))), q);
    draw();
    return [bar, out, view];
  }
  if (/html/i.test(mime) || /^\s*<(!doctype|html)/i.test(text)) {
    const view = h('div', { class: 'bview' }); let mode = 'source';
    const draw = () => {
      // The preview is sandboxed (no scripts, no forms, no navigation) and inherits this page's
      // Content-Security-Policy, so it cannot load anything from the network.
      view.replaceChildren(...[].concat(mode === 'source' ? raw() : [h('p', { class: 'note', text: 'Sandboxed preview: scripts are disabled and nothing is loaded from the network, so images and stylesheets from other URLs will be missing.' }), h('iframe', { class: 'hprev', sandbox: '', referrerpolicy: 'no-referrer', title: 'Sandboxed preview of the HTML response', srcdoc: text.slice(0, 2e6) })]).filter(Boolean));
      $$('.bmode button', bar).forEach(b => b.classList.toggle('on', b.dataset.mode === mode));
    };
    const bar = h('div', { class: 'btool' }, h('span', { class: 'bmode' }, [['source', 'Source'], ['preview', 'Preview']].map(([m, l]) => h('button', { 'data-mode': m, class: 'chip', text: l, onclick: () => { mode = m; draw(); } }))));
    draw();
    return [bar, view];
  }
  return raw();
}

/* ---------- decode dialog ---------- */
function openDecode(prefill) {
  const d = $('#dlg-decode'), ta = $('#dec-in');
  ta.value = prefill || '';
  d.showModal(); ta.focus();
  runDecode();
}
async function runDecode() {
  const r = await decodeAll($('#dec-in').value);
  $('#dec-out').replaceChildren(...(r.length ? r.map(x => h('div', { class: 'decres' }, h('div', { class: 'k', text: x.label }), h('pre', { class: 'body', text: x.value }), h('button', { class: 'icon', text: 'Copy', onclick: () => copyText(x.value) }))) : [h('p', { class: 'note', text: $('#dec-in').value.trim() ? 'Nothing to decode: not recognized as JWT, base64, URL encoding, hex, a Unix time, HTML entities or JSON.' : 'Paste or select text to decode.' })]));
}

/* ---------- compare two responses ---------- */
function diffCandidates(e) {
  const k = cmpKey(e), same = S.entries.filter(x => x !== e && cmpKey(x) === k), host = S.entries.filter(x => x !== e && x.host === e.host && cmpKey(x) !== k);
  return { same, host };
}
function openDiff(e) {
  const { same, host } = diffCandidates(e), sel = $('#diff-with');
  const opt = x => h('option', { value: String(x.i), text: '#' + x.i + ' ' + x.method + ' ' + (x.u ? x.u.pathname + x.u.search : x.url).slice(0, 90) + ' → ' + (x.status || 'failed') });
  sel.replaceChildren(same.length ? h('optgroup', { label: 'Same endpoint' }, same.map(opt)) : null, host.length ? h('optgroup', { label: 'Same host' }, host.slice(0, 300).map(opt)) : null);
  $('#diff-base').textContent = '#' + e.i + ' ' + e.method + ' ' + e.url.slice(0, 120) + ' → ' + (e.status || 'failed');
  $('#dlg-diff').dataset.base = String(e.i);
  $('#dlg-diff').showModal();
  if (sel.options.length) renderDiff(); else $('#diff-out').replaceChildren(h('p', { class: 'note', text: 'No other requests to this host.' }));
}
function renderDiff() {
  const a = S.entries.find(x => x.i === +$('#dlg-diff').dataset.base), b = S.entries.find(x => x.i === +$('#diff-with').value);
  if (!a || !b) return;
  const sec = (title, nodes) => [h('h4', { text: title }), ...nodes];
  const bodyA = bodyText((a.raw.response || {}).content || {}), bodyB = bodyText((b.raw.response || {}).content || {});
  const out = [];
  const st = [['Status', a.status || 'failed', b.status || 'failed'], ['Time', fmtMs(a.time), fmtMs(b.time)], ['Size', fmtBytes(a.transfer), fmtBytes(b.transfer)], ['Content-Type', a.mime, b.mime]];
  out.push(...sec('Summary', [h('table', { class: 'simple cmp' }, h('thead', null, h('tr', null, h('th', { text: '' }), h('th', { text: '#' + a.i }), h('th', { text: '#' + b.i }))), h('tbody', null, st.map(([l, x, y]) => h('tr', { class: String(x) !== String(y) ? 'diff' : '' }, h('td', { text: l }), h('td', { text: String(x) }), h('td', { text: String(y) })))))]));
  let ja, jb; const jsonA = (() => { try { ja = JSON.parse(bodyA); return true; } catch (_) { return false; } })(), jsonB = (() => { try { jb = JSON.parse(bodyB); return true; } catch (_) { return false; } })();
  if (bodyA == null || bodyB == null) out.push(...sec('Response body', [h('p', { class: 'note', text: 'One of the responses has no saved body.' })]));
  else if (jsonA && jsonB) {
    const d = diffJson(ja, jb), fmt = v => v === undefined ? '' : JSON.stringify(v).slice(0, 300);
    out.push(...sec('Response body (JSON, ' + (d.length ? d.length + ' difference' + (d.length > 1 ? 's' : '') : 'identical') + ')', [d.length ? h('table', { class: 'simple cmp jdiff' }, h('colgroup', null, h('col', { style: { width: '34%' } }), h('col'), h('col')), h('thead', null, h('tr', null, h('th', { text: 'Path' }), h('th', { text: '#' + a.i }), h('th', { text: '#' + b.i }))),
      h('tbody', null, cappedRows(d, x => h('tr', { class: x.kind === 'added' ? 'better' : x.kind === 'removed' ? 'worse' : 'diff' }, h('td', { class: 'mono', text: x.path + (x.kind !== 'changed' ? ' (' + x.kind + ')' : '') }), h('td', { class: 'mono', text: fmt(x.a) }), h('td', { class: 'mono', text: fmt(x.b) })), 200, 3))) : h('p', { class: 'note', text: 'The JSON bodies are identical.' })]));
  } else {
    const d = diffLines(prettyBody(bodyA, a.mime).out, prettyBody(bodyB, b.mime).out), changed = d.filter(x => x.op !== ' ').length;
    const rows = []; let run = 0;
    d.forEach((x, k) => { const near = d.slice(Math.max(0, k - 2), k + 3).some(y => y.op !== ' '); if (x.op !== ' ' || near) { if (run) rows.push(h('div', { class: 'dl skip', text: '… ' + run + ' unchanged line' + (run > 1 ? 's' : '') })); run = 0; rows.push(h('div', { class: 'dl ' + (x.op === '+' ? 'add' : x.op === '-' ? 'del' : ''), text: x.op + ' ' + x.line })); } else run++; });
    if (run) rows.push(h('div', { class: 'dl skip', text: '… ' + run + ' unchanged line' + (run > 1 ? 's' : '') }));
    out.push(...sec('Response body (' + (changed ? changed + ' changed line' + (changed > 1 ? 's' : '') : 'identical') + ')', [h('div', { class: 'ldiff' }, rows.slice(0, 2000))]));
  }
  const hdrDiff = (la, lb) => { const m = new Map(); for (const x of la || []) m.set(x.name.toLowerCase(), [x.value, undefined]); for (const x of lb || []) { const k = x.name.toLowerCase(); m.set(k, [(m.get(k) || [])[0], x.value]); } return [...m].filter(([k, [x, y]]) => x !== y && !/^(date|x-request-id|x-amzn-requestid|cf-ray|age|x-amz-cf-id|traceparent|x-trace-id|content-length)$/.test(k)); };
  for (const [title, la, lb] of [['Response headers', a.raw.response.headers, b.raw.response.headers], ['Request headers', a.raw.request.headers, b.raw.request.headers]]) {
    const d = hdrDiff(la, lb);
    out.push(...sec(title + ' (' + (d.length || 'no') + ' difference' + (d.length === 1 ? '' : 's') + ', ignoring dates and request IDs)', d.length ? [h('table', { class: 'simple cmp' }, h('tbody', null, d.map(([k, [x, y]]) => h('tr', { class: 'diff' }, h('td', { class: 'mono', text: k }), h('td', { class: 'mono', text: x ?? '(none)' }), h('td', { class: 'mono', text: y ?? '(none)' })))))] : []));
  }
  $('#diff-out').replaceChildren(...out);
}

/* ---------- copy as… menu ---------- */
function copyMenu(e) {
  const menu = h('div', { class: 'menu hidden', role: 'menu', id: 'copy-menu' }, COPY_FORMATS.map(([k, label, fn]) => h('button', { role: 'menuitem', 'data-format': k, text: label, onclick: () => { copyText(fn(e)); menu.classList.add('hidden'); } })));
  const btn = h('button', { id: 'btn-copy', 'aria-haspopup': 'menu', title: 'Copy this request as a URL or as code: cURL, fetch, PowerShell, Python, HTTPie, wget', text: 'Copy as… ▾' });
  btn.onclick = ev => { ev.stopPropagation(); menu.classList.toggle('hidden'); if (!menu.classList.contains('hidden')) menu.querySelector('button').focus(); };
  menu.addEventListener('keydown', ev => { if (ev.key === 'Escape') { menu.classList.add('hidden'); btn.focus(); } });
  return h('span', { class: 'menuwrap' }, btn, menu);
}
document.addEventListener('click', ev => { const m = document.getElementById('copy-menu'); if (m && !ev.target.closest('.menuwrap')) m.classList.add('hidden'); });
function exportPostman() {
  const list = S.filtered.length ? S.filtered : S.entries;
  const pm = toPostman(list, S.fileName, $('#x-pm-mask').checked);
  download(baseName() + '.postman_collection.json', JSON.stringify(pm, null, 2), 'application/json');
  $('#dlg-export').close(); toast('Postman collection saved (' + list.length + ' requests)');
}
