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
