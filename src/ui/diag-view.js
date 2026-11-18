function dCard(v, inDetail) {
  const c0 = v.causes[0], fx = fixesOf(v);
  return h('div', { class: 'acard ' + (v.normal ? 'normal' : v.sev === 'error' ? 'fail' : v.sev === 'warn' ? 'recovered' : 'normal'), 'data-cause': c0 ? c0.id : '', 'data-cat': v.cat },
    h('div', { class: 'ahead' },
      h('span', { class: 'sev ' + (v.normal ? 'info' : v.sev), text: DCAT_LABEL[v.cat] }),
      h('b', { text: v.headline }),
      h('span', { class: 'spacer' }),
      v.e && !inDetail ? h('a', { href: '#', text: '#' + v.e.i + ' · +' + fmtMs(v.e.start), onclick: ev => { ev.preventDefault(); openRequest(v.e, 'diag'); } }) : null),
    v.e && !inDetail ? h('div', { class: 'aurl', text: v.e.method + ' ' + v.e.url }) : null,
    c0 ? causeBlock(c0) : null,
    v.causes.length > 1 ? h('details', { class: 'more' }, h('summary', { text: 'Other causes (' + (v.causes.length - 1) + ')' }), v.causes.slice(1).map(c => causeBlock(c, true))) : null,
    v.evidence.length ? h('div', { class: 'evi' }, h('div', { class: 'k', text: 'Evidence' }), h('ul', null, v.evidence.slice(0, 12).map(x => h('li', { text: x })))) : null,
    v.related.length && !inDetail ? h('div', { class: 'evi' }, h('div', { class: 'k', text: 'Related requests' }), h('div', { class: 'rel' }, v.related.slice(0, 40).map(x => stepLink(x)), v.related.length > 40 ? ' … +' + (v.related.length - 40) : null)) : null,
    fx.length ? h('div', { class: 'evi' }, h('div', { class: 'k', text: 'What to try' }), h('ul', null, fx.map(x => h('li', { text: x })))) : null);
}
function renderDiag() {
  const root = $('#view-diag');
  const real = D.events.filter(v => !v.normal), counts = diagCounts();
  const problems = real.filter(v => v.sev !== 'info').length;
  root.replaceChildren(h('div', { class: 'av' },
    h('div', { class: 'verdict ' + (real.some(v => v.sev === 'error') ? 'bad' : problems ? 'warn' : 'good') },
      h('div', { class: 'vt', text: problems ? problems + ' problem' + (problems > 1 ? 's' : '') + ' diagnosed' : '✓ No problems diagnosed' }),
      h('p', { text: diagSummaryText() }),
      h('div', { class: 'vbtns' },
        h('button', { id: 'diag-copy', onclick: () => copyText(diagReport()), text: 'Copy report' }),
        h('button', { id: 'diag-dl', onclick: () => download(S.fileName.replace(/\.(har|json)$/i, '') + '-diagnosis.md', diagReport(), 'text/markdown'), text: 'Download report' }),
        h('span', { class: 'muted', text: 'Covers everything except authentication, which has its own tab and report.' }))),
    D.error ? h('div', { class: 'anote', text: 'Some checks could not run: ' + D.error }) : null,
    h('div', { class: 'dnav' }, DCATS.map(([k, l]) => { const n = D.events.filter(v => v.cat === k).length, p = counts.get(k) || 0; return n ? h('a', { href: '#', class: 'mchip' + (p ? ' hot' : ''), onclick: ev => { ev.preventDefault(); const s = document.getElementById('dsec-' + k); if (s) s.scrollIntoView({ block: 'start' }); }, text: l + (p ? ' (' + p + ')' : ' (notes)') }) : null; })),
    DCATS.map(([k, l]) => {
      const list = D.events.filter(v => v.cat === k).sort((a, b) => (a.normal - b.normal) || dSevRank[a.sev] - dSevRank[b.sev] || ((a.e ? a.e.start : 0) - (b.e ? b.e.start : 0)));
      if (!list.length) return null;
      const main = list.filter(v => !v.normal && v.sev !== 'info'), notes = list.filter(v => v.normal || v.sev === 'info');
      return h('section', { id: 'dsec-' + k, class: 'dsec' }, h('h3', { text: l }),
        main.map(v => dCard(v)),
        notes.length ? h('details', { class: 'normals', open: main.length ? null : true }, h('summary', { text: (main.length ? 'Notes and harmless items' : 'Notes') + ' (' + notes.length + ')' }), notes.map(v => dCard(v))) : null);
    }),
    real.length ? null : h('p', { class: 'muted', text: 'Nothing to report.' })));
}
