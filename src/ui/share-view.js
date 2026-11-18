/* ---------- notes and bookmarks ----------
   Per-request notes and stars, kept in memory and remembered in this browser
   for the same file (by name, size and first timestamp). */
S.notes = new Map();
function notesKey() { const e0 = S.entries[0]; return 'har-analytics.notes.' + shortHash(S.fileName + '|' + S.entries.length + '|' + (e0 ? e0.raw.startedDateTime : '')); }
function loadNotes() {
  S.notes = new Map();
  try { const raw = localStorage.getItem(notesKey()); if (raw) for (const [i, n] of JSON.parse(raw)) S.notes.set(+i, n); } catch (_) { /* storage unavailable */ }
}
function saveNotes() { try { const list = [...S.notes].filter(([, n]) => n.star || (n.text || '').trim()); if (list.length) localStorage.setItem(notesKey(), JSON.stringify(list)); else localStorage.removeItem(notesKey()); } catch (_) { /* storage unavailable */ } }
const noteOf = e => S.notes.get(e.i) || { star: false, text: '' };
function setNote(e, patch) { S.notes.set(e.i, { ...noteOf(e), ...patch }); saveNotes(); }
function notesControls(e) {
  const n = noteOf(e);
  const star = h('button', { class: 'icon star' + (n.star ? ' on' : ''), id: 'note-star', title: n.star ? 'Remove bookmark' : 'Bookmark this request', 'aria-pressed': n.star ? 'true' : 'false', text: n.star ? '★' : '☆' });
  star.onclick = () => { setNote(e, { star: !noteOf(e).star }); renderDetail(); renderRows(); };
  const ta = h('textarea', { id: 'note-text', class: 'note-text' + (n.text ? '' : ' hidden'), rows: 2, placeholder: 'Your note about this request (kept in this browser; included in the case bundle)' }, n.text || '');
  let t; ta.oninput = () => { clearTimeout(t); t = setTimeout(() => { setNote(e, { text: ta.value }); renderRows(); }, 250); };
  const btn = h('button', { id: 'note-btn', title: 'Add a note', text: n.text ? 'Note' : 'Add note' });
  btn.onclick = () => { ta.classList.toggle('hidden'); if (!ta.classList.contains('hidden')) ta.focus(); };
  return { star, btn, ta };
}
function notesMarkdown(mask) {
  const list = S.entries.filter(e => { const n = S.notes.get(e.i); return n && (n.star || (n.text || '').trim()); });
  if (!list.length) return '';
  const L = ['# Notes', '', 'Bookmarked and annotated requests from ' + S.fileName + '.', ''];
  for (const e of list) {
    const n = S.notes.get(e.i);
    L.push('## ' + (n.star ? '★ ' : '') + '#' + e.i + ' ' + e.method + ' ' + redactUrl(e.url) + ' → ' + (e.status || 'no response'), '');
    if ((n.text || '').trim()) L.push(n.text.trim(), '');
  }
  const md = scrub(L.join('\n'));
  return mask ? maskPii(md) : md;
}

/* ---------- export dialog: personal data, preview, bundle ---------- */
const exportOpts = () => ({ params: $('#x-params').checked, reqBody: $('#x-reqbody').checked, resBody: $('#x-resbody').checked, pii: $('#x-pii').checked });
function openExport() {
  $('#x-preview-out').replaceChildren();
  const { byKind } = scanPii(S.entries);
  const box = $('#x-pii-summary');
  box.replaceChildren(byKind.size
    ? h('div', null, h('b', { text: 'Personal data found: ' }), [...byKind].map(([k, v]) => PII_KINDS[k].label.toLowerCase() + ' ×' + v.count).join(', '), h('span', { class: 'muted', text: ' (e.g. ' + [...byKind.values()].flatMap(v => [...v.samples]).slice(0, 4).join(', ') + ')' }))
    : h('span', { class: 'muted', text: 'No personal data patterns found (emails, phone numbers, card numbers, SSNs, IBANs, client IPs).' }));
  $('#x-notes-count').textContent = [...S.notes.values()].filter(n => n.star || (n.text || '').trim()).length;
  $('#dlg-export').showModal();
}
function previewRedaction() {
  const red = buildRedacted(exportOpts()), groups = redactionDiff(S.har, red);
  const out = $('#x-preview-out');
  if (!groups.size) { out.replaceChildren(h('p', { class: 'note', text: 'Nothing would change with these options.' })); return; }
  const total = [...groups.values()].reduce((a, g) => a + g.count, 0);
  out.replaceChildren(h('p', { class: 'note', text: total + ' change' + (total > 1 ? 's' : '') + ' in ' + groups.size + ' categor' + (groups.size > 1 ? 'ies' : 'y') + '. Values shown are after redaction.' }),
    h('ul', { class: 'preview-list' }, [...groups].sort((a, b) => b[1].count - a[1].count).map(([label, g]) => h('li', null, h('details', null, h('summary', null, h('b', { text: label }), ' — ' + g.count),
      h('ul', null, g.examples.map(x => h('li', { class: 'mono', text: x })), g.count > g.examples.length ? h('li', { class: 'muted', text: '… and ' + (g.count - g.examples.length) + ' more' }) : null))))));
}
const baseName = () => S.fileName.replace(/\.(har|json)$/i, '');
function downloadRedacted() {
  const har = buildRedacted(exportOpts());
  download(baseName() + '-redacted.har', JSON.stringify(har, null, 2), 'application/json');
  $('#dlg-export').close(); toast('Redacted HAR saved');
}
async function downloadBundle() {
  const o = exportOpts(), har = buildRedacted(o), mask = s => (o.pii ? maskPii(s) : s);
  const { byKind } = scanPii(S.entries), notes = notesMarkdown(o.pii), groups = redactionDiff(S.har, har);
  const files = [
    { name: baseName() + '-redacted.har', data: JSON.stringify(har, null, 2) },
    { name: 'diagnosis.md', data: mask(diagReport()) },
    { name: 'authentication.md', data: mask(authReport()) },
    { name: 'requests.csv', data: mask(scrub(csvText(S.entries).split('\r\n').map((l, k) => k === 0 ? l : l.replace(/https?:\/\/[^,"]+/g, u => redactUrl(u))).join('\r\n'))) },
  ];
  if (notes) files.push({ name: 'notes.md', data: notes });
  const readme = ['# Case bundle: ' + S.fileName, '',
    '- Created: ' + new Date().toISOString() + ' with HAR Analytics (locally; nothing was uploaded)',
    '- Capture: ' + S.entries.length + ' requests starting ' + fmtDate(S.base),
    '- Diagnosis: ' + diagSummaryText(), '- Authentication: ' + verdictText(), '',
    '## Redaction applied to the HAR', '',
    '- Authorization, Cookie, Set-Cookie, API-key and CSRF headers and all cookie values masked',
    o.params ? '- Token-like URL / form parameters and JSON fields masked' : '- Token-like parameters NOT masked',
    o.reqBody ? '- Request bodies removed' : '- Request bodies kept',
    o.resBody ? '- Response bodies removed' : '- Response bodies kept',
    o.pii ? '- Personal data (emails, phone numbers, card numbers, SSNs, IBANs, client IPs) masked' : '- Personal data NOT masked',
    SETTINGS.redactPatterns.length ? '- ' + SETTINGS.redactPatterns.length + ' custom pattern(s) from settings masked' : '', '',
    'Changes: ' + ([...groups].map(([l, g]) => l + ' (' + g.count + ')').join('; ') || 'none'), '',
    '## Personal data found in the original capture', '', byKind.size ? [...byKind].map(([k, v]) => '- ' + PII_KINDS[k].label + ': ' + v.count).join('\n') : 'None found.', '',
    '## Files', '', ...files.map(f => '- ' + f.name)].filter(x => x !== '').join('\n') + '\n';
  files.unshift({ name: 'README.md', data: readme });
  await stage('Building the case bundle…');
  const zip = await makeZip(files);
  stageDone();
  download(baseName() + '-case.zip', zip, 'application/zip');
  $('#dlg-export').close(); toast('Case bundle saved');
}
