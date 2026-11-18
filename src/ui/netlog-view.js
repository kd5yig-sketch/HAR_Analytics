/* ---------- NetLog view and per-request transport details ---------- */
function attachNetlogFile(f) {
  const r = new FileReader();
  r.onload = async () => {
    let log;
    try { log = parseNetLogText(String(r.result)); } catch (err) { toast('Not a NetLog: ' + err.message); return; }
    if (!isNetLog(log)) { toast(f.name + ' is not a Chrome NetLog'); return; }
    await stage('Matching the NetLog to this HAR…');
    const conv = netlogToHar(log), n = attachNetlog(conv.info, conv.har.log.entries);
    S.netlog = { ...conv.info, attachedName: f.name, matched: n };
    runDiagnostics();
    renderDiag(); renderNetlog(); renderOverview(); applyFilters();
    stageDone(); show('netlog');
    toast('NetLog attached: ' + n + ' of ' + S.entries.length + ' requests matched');
  };
  r.readAsText(f);
}
function certRows(certs) {
  return certs.map(c => {
    const L = c.leaf, when = (S.netlog && S.netlog.start) || Date.now(), expired = isFinite(L.notAfter) && L.notAfter < when;
    return h('tr', { class: c.flags.length || expired ? 'bad-row' : '' },
      h('td', null, h('b', { text: L.cn || L.subject }), h('div', { class: 'muted mono', text: L.sans.join(', ') })),
      h('td', { text: (L.issuerCn || L.issuer) + (L.selfSigned ? ' (self-signed)' : '') }),
      h('td', { class: expired ? 'errtxt' : '', text: fmtDate(L.notBefore).slice(0, 10) + ' → ' + fmtDate(L.notAfter).slice(0, 10) + (expired ? ' (expired)' : '') }),
      h('td', { class: c.flags.length ? 'errtxt' : '', text: c.flags.length ? c.flags.map(f => CERT_FLAG_TEXT[f] || f).join('; ') : 'OK' }));
  });
}
function renderNetlog() {
  const root = $('#view-netlog'), N = S.netlog;
  if (!N) {
    root.replaceChildren(h('div', { class: 'av' }, h('div', { class: 'verdict' }, h('div', { class: 'vt', text: 'Chrome NetLog' }),
      h('p', { text: 'A NetLog records what a HAR leaves out: DNS lookups, proxy decisions (including PAC scripts), every connection attempt, TLS versions, and the certificates Chrome received with every problem it found. Use it when requests fail with network or certificate errors, or when a HAR shows "(failed)" with no explanation.' }),
      h('ol', null, h('li', null, 'Open ', h('code', { text: 'chrome://net-export' }), ' (Edge: ', h('code', { text: 'edge://net-export' }), ') in a new tab.'), h('li', { text: 'Click “Start Logging to Disk”, choose where to save the file.' }), h('li', { text: 'Reproduce the problem in another tab, then click “Stop Logging”.' }), h('li', { text: 'Open the .json file here (like a HAR), or attach it to the HAR you have open.' })),
      h('div', { class: 'vbtns' }, S.entries.length ? h('button', { class: 'primary', id: 'nl-attach', onclick: () => $('#netlog-file').click(), text: 'Attach a NetLog to this HAR…' }) : null,
        h('span', { class: 'muted', text: 'NetLogs can contain URLs and host names; with “Include cookies and credentials” they also contain secrets. They never leave this computer here.' })))));
    return;
  }
  const dnsFail = N.dns.filter(d => d.error), certsBad = N.certs.filter(c => c.flags.length || (c.leaf && c.leaf.notAfter < (N.start || Date.now())));
  const proxies = new Map(); for (const d of N.details) { const p = d.proxy || 'unknown'; proxies.set(p, (proxies.get(p) || 0) + 1); }
  const socks = N.sockets.filter(s => s.attempts.length || s.tls || s.connect);
  root.replaceChildren(h('div', { class: 'av' },
    h('div', { class: 'verdict' + (dnsFail.length || certsBad.length || N.pacErrors.length ? ' bad' : '') },
      h('div', { class: 'vt', text: 'Chrome NetLog' + (N.attachedName ? ': ' + N.attachedName : '') }),
      h('p', { text: (N.attachedName ? 'Attached to this HAR: ' + N.matched + ' of ' + S.entries.length + ' requests matched. ' : '') + N.events.toLocaleString() + ' events, capture mode ' + (N.captureMode || 'unknown') + '. ' + N.dns.length + ' DNS lookups (' + dnsFail.length + ' failed), ' + N.certs.length + ' certificate checks (' + certsBad.length + ' with problems), ' + N.sockets.length + ' sockets.' }),
      N.truncated ? h('div', { class: 'anote', text: 'This NetLog was cut short (logging was not stopped cleanly, or Chrome crashed). Everything up to the cut was read.' }) : null,
      N.captureMode && /Default|ByteStreams/.test(N.captureMode) ? h('p', { class: 'muted', text: 'Cookies and credentials are not in this capture mode, which is the safe default.' }) : null),
    h('h3', { text: 'Certificates (' + N.certs.length + ')' }),
    N.certs.length ? h('div', { class: 'tscroll' }, h('table', { class: 'simple nlcerts' }, h('thead', null, h('tr', null, ['Certificate / names', 'Issuer', 'Valid', 'Chrome’s verdict'].map(x => h('th', { text: x })))), h('tbody', null, certRows(N.certs)))) : h('p', { class: 'muted', text: 'No certificate checks recorded.' }),
    h('h3', { text: 'DNS lookups (' + N.dns.length + ')' }),
    N.dns.length ? h('table', { class: 'simple' }, h('colgroup', null, h('col'), h('col', { style: { width: '90px' } }), h('col')), h('thead', null, h('tr', null, h('th', { text: 'Host' }), h('th', { class: 'num', text: 'Time' }), h('th', { text: 'Result' }))),
      h('tbody', null, cappedRows([...N.dns].sort((a, b) => !!b.error - !!a.error || b.ms - a.ms), d => h('tr', { class: d.error ? 'bad-row' : '' }, h('td', { class: 'url', text: d.host }), h('td', { class: 'num', text: fmtMs(d.ms) }), h('td', { class: d.error ? 'errtxt' : 'mono', text: d.error || d.addresses.join(', ') || 'resolved' })), 50, 3))) : h('p', { class: 'muted', text: 'No DNS lookups recorded (answers may have come from Chrome’s cache).' }),
    h('h3', { text: 'Proxy decisions' }),
    h('ul', { class: 'klist' }, [...proxies].map(([p, n]) => h('li', null, h('b', { class: 'mono', text: p }), ' — ' + n + ' request' + (n > 1 ? 's' : '')))),
    N.pacErrors.length ? h('div', null, h('h4', { text: 'PAC script messages' }), h('ul', { class: 'klist' }, N.pacErrors.map(p => h('li', { class: p.kind === 'error' ? 'errtxt' : '', text: p.kind + (p.line != null ? ' (line ' + p.line + ')' : '') + ': ' + p.message })))) : null,
    h('h3', { text: 'Connections (' + socks.length + ')' }),
    h('table', { class: 'simple' }, h('thead', null, h('tr', null, ['Socket', 'Remote', 'Attempts', 'TLS'].map(x => h('th', { text: x })))),
      h('tbody', null, cappedRows(socks, s => h('tr', { class: s.connect && s.connect.error ? 'bad-row' : '' },
        h('td', { class: 'mono', text: String(s.id) + (s.inUse > 1 ? ' (reused ' + (s.inUse - 1) + '×)' : '') }),
        h('td', { class: 'mono', text: s.remote || (s.addresses || []).join(', ') }),
        h('td', { class: 'mono', text: s.attempts.map(a => a.address + (a.error ? ' ✗ ' + a.error.replace('net::', '') : ' ✓')).join('; ') || (s.connect && !s.connect.error ? 'connected' : '') }),
        h('td', { class: s.tls && s.tls.error ? 'errtxt' : '', text: s.tls ? (s.tls.error || [s.tls.version, s.tls.cipher, s.tls.alpn, s.tls.resumed ? 'resumed' : ''].filter(Boolean).join(' · ') || 'handshake done') : '—' })), 60, 4)))));
}
function transportDetail(e) {
  const nl = e.raw._netlog || (e.netlogLink && e.netlogLink._netlog);
  if (!nl) return [h('p', { class: 'note', text: 'No NetLog information for this request.' })];
  const out = [h('h4', { text: 'Route' }), kvList([['Proxy', nl.proxy || 'unknown'], ['DNS', nl.dns ? (nl.dns.error || nl.dns.addresses.join(', ') || 'resolved') + ' in ' + fmtMs(nl.dns.ms) : 'not looked up (cached or reused connection)']])];
  if (nl.sockets.length) {
    out.push(h('h4', { text: 'Connections' }));
    for (const s of nl.sockets) out.push(kvList([['Socket', String(s.id)], ['Remote', s.remote || '—'], ['Attempts', s.attempts.map(a => a.address + (a.error ? ' ✗ ' + a.error : ' ✓')).join('; ') || '—'], ['TLS', s.tls ? (s.tls.error || [s.tls.version, s.tls.cipher, s.tls.alpn].filter(Boolean).join(' · ') || 'done') : '—']]));
  }
  if (nl.cert && nl.cert.leaf) {
    const { facts } = certFacts(nl.cert, e.u ? e.u.hostname : e.host, entryTime(e));
    out.push(h('h4', { text: 'Certificate' }), h('ul', { class: 'klist' }, facts.map(f => h('li', { text: f }))));
    if (nl.cert.chain.length > 1) out.push(h('p', { class: 'note', text: 'Chain: ' + nl.cert.chain.map(c => c.cn || c.subject).join(' → ') }));
  }
  return out;
}
