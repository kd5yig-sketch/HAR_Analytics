/* ---------- sequence diagram (SVG) for a sign-in flow ---------- */
function sequenceSvg(flow) {
  const q = flowSequence(flow), colW = 190, left = 20, top = 16, headH = 44, rowH = 34, noteH = 22;
  const W = left * 2 + colW * q.parts.length, x = i => left + colW * i + colW / 2;
  const idx = new Map(q.parts.map((p, i) => [p.id, i]));
  const bodyH = q.msgs.length * rowH + 16, notesH = q.notes.length * noteH + (q.notes.length ? 12 : 0);
  const H = top + headH + bodyH + notesH + 10;
  const svg = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, width: W, class: 'seq', role: 'img', 'aria-label': 'Sequence diagram: ' + q.title, xmlns: SVGNS });
  svg.append(sv('title', null, q.title),
    sv('defs', null, sv('marker', { id: 'arr', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, sv('path', { d: 'M0 0 L10 5 L0 10 z', class: 'arrhead' })),
      sv('marker', { id: 'arrbad', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, sv('path', { d: 'M0 0 L10 5 L0 10 z', class: 'arrhead bad' }))));
  q.parts.forEach((p, i) => {
    svg.append(sv('line', { x1: x(i), x2: x(i), y1: top + headH, y2: top + headH + bodyH, class: 'life' }));
    svg.append(sv('rect', { x: x(i) - colW / 2 + 8, y: top, width: colW - 16, height: headH - 6, rx: 6, class: 'phead' }));
    svg.append(sv('text', { x: x(i), y: top + 16, 'text-anchor': 'middle', class: 'prole' }, p.label));
    if (p.host) svg.append(sv('text', { x: x(i), y: top + 31, 'text-anchor': 'middle', class: 'phost' }, p.host.length > 28 ? p.host.slice(0, 27) + '…' : p.host));
  });
  q.msgs.forEach((m, k) => {
    const y = top + headH + 22 + k * rowH, a = x(idx.get(m.from)), b = x(idx.get(m.to)), dir = b > a ? 1 : -1;
    const g = sv('g', { class: 'msg' + (m.bad ? ' bad' : '') + (m.dashed ? ' resp' : ''), tabindex: '0', role: 'button', 'data-i': String(m.e.i) },
      sv('title', null, '#' + m.e.i + ' ' + m.text + (m.step ? ' — ' + m.step : '') + '. Click to open the request.'),
      sv('line', { x1: a, x2: b - dir * 2, y1: y, y2: y, class: 'arrow', 'marker-end': m.bad ? 'url(#arrbad)' : 'url(#arr)' }),
      sv('text', { x: (a + b) / 2, y: y - 6, 'text-anchor': 'middle', class: 'mtext' }, (m.dashed ? '' : (k / 2 + 1) + '. ') + (m.text.length > 46 ? m.text.slice(0, 45) + '…' : m.text)));
    const go = () => openRequest(m.e, 'auth');
    g.addEventListener('click', go); g.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } });
    svg.append(g);
  });
  q.notes.forEach((n, k) => {
    const y = top + headH + bodyH + 8 + k * noteH;
    svg.append(sv('rect', { x: left, y, width: W - left * 2, height: noteH - 4, rx: 4, class: 'note' + (n.bad ? ' bad' : '') }));
    svg.append(sv('text', { x: left + 8, y: y + 13, class: 'ntext' + (n.bad ? ' bad' : '') }, n.text.length > 120 ? n.text.slice(0, 119) + '…' : n.text));
  });
  return svg;
}
// Standalone copy with the current theme's colours inlined, for download.
function standaloneSvg(svg) {
  const cs = getComputedStyle(document.documentElement), v = n => cs.getPropertyValue(n).trim();
  const css = `svg{background:${v('--panel')};font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.life{stroke:${v('--border')};stroke-dasharray:4 4}.phead{fill:${v('--panel-2')};stroke:${v('--border')}}
.prole{fill:${v('--text')};font-size:12px;font-weight:600}.phost{fill:${v('--muted')};font-size:10.5px}
.arrow{stroke:${v('--text')};stroke-width:1.4}.resp .arrow{stroke-dasharray:5 3}.arrhead{fill:${v('--text')}}
.bad .arrow{stroke:${v('--err')}}.arrhead.bad{fill:${v('--err')}}.mtext{fill:${v('--text')};font-size:11px}.bad .mtext{fill:${v('--err')}}
.note{fill:${v('--panel-2')}}.note.bad{fill:${v('--err-soft')}}.ntext{fill:${v('--text')};font-size:11px}.ntext.bad{fill:${v('--err')}}`;
  const copy = svg.cloneNode(true);
  copy.insertBefore(sv('style', null, css), copy.firstChild);
  copy.setAttribute('xmlns', SVGNS);
  return '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(copy);
}
function downloadFlowSvg(svg, name) { download(name + '.svg', standaloneSvg(svg), 'image/svg+xml'); }
function downloadFlowPng(svg, name) {
  const text = standaloneSvg(svg), w = +svg.getAttribute('width'), vb = svg.getAttribute('viewBox').split(' ').map(Number), scale = 2;
  const img = new Image();
  img.onload = () => {
    const c = document.createElement('canvas'); c.width = vb[2] * scale; c.height = vb[3] * scale;
    const ctx = c.getContext('2d'); ctx.scale(scale, scale); ctx.drawImage(img, 0, 0, vb[2], vb[3]);
    c.toBlob(b => { if (b) { const r = new FileReader(); r.onload = () => download(name + '.png', new Uint8Array(r.result), 'image/png'); r.readAsArrayBuffer(b); } else toast('PNG export is not available in this browser'); }, 'image/png');
  };
  img.onerror = () => toast('PNG export failed; use SVG');
  img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(text);
  void w;
}
function diagramBlock(flow) {
  const box = h('div', { class: 'seqbox hidden' });
  const name = 'sign-in-flow-' + (flow.idp || 'flow').replace(/[^\w.-]+/g, '_');
  const btn = h('button', { class: 'chip seq-toggle', text: 'Diagram' });
  btn.onclick = () => {
    if (!box.childElementCount) {
      const svg = sequenceSvg(flow);
      box.append(h('div', { class: 'seqscroll' }, svg), h('div', { class: 'vbtns' },
        h('button', { class: 'seq-svg', text: 'Download SVG', onclick: () => downloadFlowSvg(svg, name) }),
        h('button', { class: 'seq-png', text: 'Download PNG', onclick: () => downloadFlowPng(svg, name) }),
        h('button', { class: 'seq-mermaid', text: 'Copy as Mermaid', title: 'Mermaid text renders as a diagram in GitHub, GitLab, Azure DevOps, Notion and many wikis', onclick: () => copyText(flowMermaid(flow)) })));
    }
    box.classList.toggle('hidden'); btn.classList.toggle('on', !box.classList.contains('hidden'));
  };
  return [btn, box];
}
