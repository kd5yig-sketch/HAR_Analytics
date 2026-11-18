/* ---------- small helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k === 'style') { for (const [p, pv] of Object.entries(v)) el.style.setProperty(p, pv); }
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove('show'), 1600);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast('Copied to clipboard'); return; } catch (_) { /* fall back */ }
  const ta = h('textarea', { style: { position: 'fixed', opacity: '0' } }); ta.value = text;
  document.body.append(ta); ta.select();
  try { document.execCommand('copy'); toast('Copied to clipboard'); } catch (_) { toast('Copy failed'); }
  ta.remove();
}
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h('a', { href: url, download: name }); document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
// Render a long list a batch at a time: the first `n` items, then a "Show more" button.
function capped(list, render, n = 30) {
  const first = list.slice(0, n).map(render);
  if (list.length <= n) return first;
  const btn = h('button', { class: 'more-btn', text: 'Show ' + Math.min(n, list.length - n) + ' more (' + (list.length - n) + ' hidden)' });
  btn.onclick = () => btn.replaceWith(...[].concat(capped(list.slice(n), render, n)));
  return [...first, btn];
}
// Show a progress message and let the browser paint it before continuing.
async function stage(label) {
  const box = document.getElementById('loading');
  if (box) { box.classList.remove('hidden'); document.getElementById('loading-text').textContent = label; }
  await new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)));
}
function stageDone() { const box = document.getElementById('loading'); if (box) box.classList.add('hidden'); }
// Same for table rows: the "Show more" button sits in its own full-width row.
function cappedRows(list, render, n, cols) {
  const rows = list.slice(0, n).map(render);
  if (list.length <= n) return rows;
  const btn = h('button', { class: 'more-btn', text: 'Show ' + Math.min(n, list.length - n) + ' more (' + (list.length - n) + ' hidden)' });
  const tr = h('tr', { class: 'more-row' }, h('td', { colspan: cols }, btn));
  btn.onclick = () => tr.replaceWith(...cappedRows(list.slice(n), render, n, cols));
  return [...rows, tr];
}
