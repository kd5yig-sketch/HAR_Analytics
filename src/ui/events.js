/* ---------- events ---------- */
$('#btn-open').onclick = $('#btn-open2').onclick = () => $('#file').click();
$('#file').onchange = ev => { readFile(ev.target.files[0]); ev.target.value = ''; };
$('#btn-compare').onclick = () => $('#file2').click();
$('#file2').onchange = ev => { const f = ev.target.files[0]; ev.target.value = ''; if (!f) return; const r = new FileReader(); r.onload = () => loadCompare(String(r.result), f.name); r.readAsText(f); };
$('#tabs').onclick = ev => { const b = ev.target.closest('button'); if (b && !b.disabled) show(b.dataset.view); };
$('#btn-theme').onclick = () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'light' : 'dark';
};
let dragDepth = 0;
window.addEventListener('dragenter', ev => { ev.preventDefault(); dragDepth++; document.body.classList.add('dragging'); });
window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; document.body.classList.remove('dragging'); } });
window.addEventListener('dragover', ev => ev.preventDefault());
window.addEventListener('drop', ev => {
  ev.preventDefault(); dragDepth = 0; document.body.classList.remove('dragging');
  const fs = ev.dataTransfer && ev.dataTransfer.files ? [...ev.dataTransfer.files] : [];
  if (fs.length >= 2 && S.view !== 'compare') { const rd = f => new Promise(res => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.readAsText(f); }); Promise.all([rd(fs[0]), rd(fs[1])]).then(async ([a, b]) => { await loadText(a, fs[0].name); loadCompare(b, fs[1].name); }); }
  else if (fs.length && S.view === 'compare' && S.entries.length) { const r = new FileReader(); r.onload = () => loadCompare(String(r.result), fs[0].name); r.readAsText(fs[0]); }
  else if (fs.length) readFile(fs[0]);
});

let qTimer;
$('#q').addEventListener('input', () => { clearTimeout(qTimer); qTimer = setTimeout(applyFilters, 120); });
['#f-status', '#f-domain', '#f-page', '#f-issues', '#f-deep'].forEach(s => $(s).addEventListener('change', applyFilters));
$('#type-chips').onclick = ev => {
  const c = ev.target.closest('.chip'); if (!c) return;
  const t = c.dataset.type;
  if (!t) S.types.clear(); else if (S.types.has(t)) S.types.delete(t); else S.types.add(t);
  syncChips(); applyFilters();
};
$('#thead').onclick = ev => {
  const d = ev.target.closest('[data-key]'); if (!d) return;
  const key = d.dataset.key;
  S.sort = { key, dir: S.sort.key === key ? -S.sort.dir : (['time', 'transfer', 'status'].includes(key) ? -1 : 1) };
  sortFiltered(); renderRows();
};
let raf = 0;
$('#rows').addEventListener('scroll', () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; renderRows(); }); });
window.addEventListener('resize', () => { if (S.view === 'requests') renderRows(); });
$('#rows').onclick = ev => { const r = ev.target.closest('.row'); if (r) select(S.filtered[+r.dataset.k]); };

document.addEventListener('keydown', ev => {
  const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement && document.activeElement.tagName);
  if ($('#dlg-export').open || $('#dlg-decode').open || $('#dlg-diff').open) return;
  if (ev.key === '/' && !typing && S.entries.length) { ev.preventDefault(); show('requests'); $('#q').focus(); return; }
  if (S.view !== 'requests') return;
  if (ev.key === 'Escape') { if (typing) document.activeElement.blur(); else select(null); return; }
  if (typing) return;
  if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp' || ev.key === 'j' || ev.key === 'k') {
    if (!S.filtered.length) return;
    ev.preventDefault();
    const k = S.filtered.indexOf(S.selected);
    const down = ev.key === 'ArrowDown' || ev.key === 'j';
    const n = k < 0 ? 0 : Math.max(0, Math.min(S.filtered.length - 1, k + (down ? 1 : -1)));
    select(S.filtered[n]);
  }
});

$('#btn-export').onclick = openExport;
$('#x-cancel').onclick = () => $('#dlg-export').close();
$('#x-csv').onclick = () => { exportCsv(); $('#dlg-export').close(); };
$('#x-har').onclick = downloadRedacted;
$('#x-bundle').onclick = downloadBundle;
$('#x-preview').onclick = previewRedaction;
for (const id of ['#x-params', '#x-pii', '#x-reqbody', '#x-resbody']) $(id).addEventListener('change', () => { if ($('#x-preview-out').childElementCount) previewRedaction(); });
$('#btn-settings').onclick = () => { renderSettings(); show('settings'); };
$('#settings-file').onchange = ev => { const f = ev.target.files[0]; ev.target.value = ''; if (f) importSettingsFile(f); };
loadStoredSettings();
$('#btn-settings').classList.toggle('on', settingsCount() > 0);
let decT; $('#dec-in').addEventListener('input', () => { clearTimeout(decT); decT = setTimeout(runDecode, 150); });
$('#dec-close').onclick = () => $('#dlg-decode').close();
$('#diff-with').addEventListener('change', renderDiff);
$('#diff-close').onclick = () => $('#dlg-diff').close();
