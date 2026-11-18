/* ---------- sign-in flows as sequence diagrams ----------
   A shared model (participants, messages, notes) rendered as SVG in the
   browser and as Mermaid text in Markdown reports. */
function flowRole(flow, host) {
  if (host === flow.idp) return flow.kind === 'saml' ? 'Identity provider' : flow.kind === 'windows' ? 'Server' : 'Identity provider';
  if (flow.kind === 'saml') return 'Service provider';
  if (flow.kind === 'windows') return 'Server';
  return 'App';
}
function stepFailed(e) {
  return e.status === 0 || e.status >= 400 || !!(e.auth && e.auth.event && !e.auth.event.normal) || !!(e.flagged) || !!(e.saml && e.saml.failed);
}
function flowSequence(flow) {
  const parts = [{ id: 'B', host: '', label: 'Browser' }], byHost = new Map();
  const pid = host => { if (!byHost.has(host)) { const id = 'P' + byHost.size; byHost.set(host, id); parts.push({ id, host, label: flowRole(flow, host) }); } return byHost.get(host); };
  if (flow.idp && flow.kind !== 'windows') pid(flow.idp);
  const msgs = [];
  const drawn = new Set();
  for (const s of flow.steps) {
    if (drawn.has(s.e)) continue; // several steps can describe one request (e.g. an authorize call that redirects back)
    drawn.add(s.e);
    const e = s.e, to = pid(e.host), path = e.u ? e.u.pathname : e.url;
    msgs.push({ from: 'B', to, text: e.method + ' ' + (path.length > 48 ? path.slice(0, 47) + '…' : path), e, step: s.label });
    let back = e.status ? e.status + (e.statusText ? ' ' + e.statusText : '') : 'no response' + (e.error ? ' (' + e.error.replace(/^net::/, '') + ')' : '');
    if (e.redirectTarget) { try { const t = new URL(e.redirectTarget); back += ' → ' + t.host + t.pathname.slice(0, 32); } catch (_) { /* bad URL */ } }
    const ev = e.auth && e.auth.event && !e.auth.event.normal ? e.auth.event : null;
    if (ev && ev.causes[0]) back += ': ' + ev.causes[0].title.slice(0, 60);
    msgs.push({ from: to, to: 'B', text: back, e, dashed: true, bad: stepFailed(e) });
  }
  const notes = flow.checks.filter(c => c.ok === false).map(c => ({ text: '✗ ' + c.label, bad: true }));
  const okNotes = flow.checks.filter(c => c.ok === true).map(c => ({ text: '✓ ' + c.label, bad: false }));
  return { title: flow.title + (flow.idp ? ' — ' + flow.idp : ''), parts, msgs, notes: [...notes, ...okNotes] };
}
function flowMermaid(flow) {
  const q = flowSequence(flow), clean = s => String(s).replace(/[;#\n]/g, ' ').replace(/https?:\/\/\S+/g, u => redactUrl(u));
  const L = ['sequenceDiagram', '  autonumber'];
  for (const p of q.parts) L.push('  participant ' + p.id + ' as ' + clean(p.label + (p.host ? ' (' + p.host + ')' : '')));
  for (const m of q.msgs) L.push('  ' + m.from + (m.bad ? '--x' : m.dashed ? '-->>' : '->>') + m.to + ': ' + clean(m.text));
  const last = q.parts[q.parts.length - 1].id;
  for (const n of q.notes.filter(n => n.bad)) L.push('  Note over B,' + last + ': ' + clean(n.text));
  return L.join('\n');
}
