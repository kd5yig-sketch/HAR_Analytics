/* ---------- Authentication view ---------- */
function causeBlock(c, minor) {
  return h('div', { class: 'cause' + (minor ? ' minor' : ''), 'data-cause': c.id },
    h('div', { class: 'ct' }, h('span', { class: 'conf ' + c.conf, text: CONF_LABEL[c.conf] }), h('span', { text: c.title })),
    c.detail ? h('p', { text: c.detail }) : null);
}
function eventCard(v, inDetail) {
  const c0 = v.causes[0], fx = fixesOf(v);
  return h('div', { class: 'acard ' + (v.normal ? 'normal' : v.recovered ? 'recovered' : 'fail'), 'data-cause': c0 ? c0.id : '' },
    h('div', { class: 'ahead' },
      h('span', { class: 'sev ' + (v.normal ? 'info' : v.recovered ? 'warn' : 'error'), text: v.kind }),
      h('b', { text: v.headline }),
      v.recovered ? h('span', { class: 'okchip', text: 'succeeded later (#' + v.recovered.i + ')' }) : null,
      h('span', { class: 'spacer' }),
      inDetail ? null : h('a', { href: '#', text: '#' + v.e.i + ' · +' + fmtMs(v.e.start), onclick: ev => { ev.preventDefault(); openRequest(v.e, 'auth'); } })),
    inDetail ? null : h('div', { class: 'aurl', text: v.e.method + ' ' + v.e.url }),
    h('div', { class: 'kv2' }, h('span', { class: 'k', text: 'Credentials sent' }), h('span', { text: v.sent }),
      v.expected ? [h('span', { class: 'k', text: 'Server asked for' }), h('span', { text: v.expected })] : null),
    c0 ? causeBlock(c0) : null,
    v.causes.length > 1 ? h('details', { class: 'more' }, h('summary', { text: 'Other possible causes (' + (v.causes.length - 1) + ')' }), v.causes.slice(1).map(c => causeBlock(c, true))) : null,
    v.evidence.length ? h('div', { class: 'evi' }, h('div', { class: 'k', text: 'Evidence' }), h('ul', null, v.evidence.map(x => h('li', { text: x })))) : null,
    fx.length ? h('div', { class: 'evi' }, h('div', { class: 'k', text: 'What to try' }), h('ul', null, fx.map(x => h('li', { text: x })))) : null);
}
function stepLink(e) { return h('a', { href: '#', text: '#' + e.i, onclick: ev => { ev.preventDefault(); openRequest(e, 'auth'); } }); }
function flowCard(f) {
  const bad = f.checks.some(c => c.ok === false), [dbtn, dbox] = diagramBlock(f);
  return h('div', { class: 'acard flow' + (bad ? ' fail' : '') },
    h('div', { class: 'ahead' }, h('span', { class: 'sev ' + (bad ? 'error' : 'info'), text: f.kind === 'saml' ? 'SAML' : f.kind === 'windows' ? 'Windows' : 'OAuth' }), h('b', { text: f.title }),
      h('span', { class: 'muted', text: [f.idp, f.client_id ? 'client ' + f.client_id : ''].filter(Boolean).join(' · ') }), h('span', { class: 'spacer' }), dbtn),
    dbox,
    h('ol', { class: 'steps' }, f.steps.map(s => h('li', null, stepLink(s.e), ' ', s.label))),
    f.checks.length ? h('ul', { class: 'checks' }, f.checks.map(c => h('li', { class: c.ok === true ? 'ok' : c.ok === false ? 'bad' : 'info' },
      h('span', { class: 'ic', text: c.ok === true ? '✓' : c.ok === false ? '✗' : 'i' }), h('span', { text: c.label }), c.detail ? h('span', { class: 'muted', text: ' — ' + c.detail }) : null))) : null);
}
function renderAuth() {
  const root = $('#view-auth');
  if (A.error) { root.replaceChildren(h('div', { class: 'av' }, h('p', { class: 'note', text: 'The authentication analysis failed: ' + A.error }))); return; }
  const fails = A.events.filter(v => !v.normal), normals = A.events.filter(v => v.normal);
  fails.sort((a, b) => (!!a.recovered - !!b.recovered) || a.e.start - b.e.start);
  const toks = [...A.tokens.values()];
  root.replaceChildren(h('div', { class: 'av' },
    h('div', { class: 'verdict ' + (fails.some(v => !v.recovered) ? 'bad' : fails.length ? 'warn' : 'good') },
      h('div', { class: 'vt', text: fails.length ? fails.length + ' authentication failure' + (fails.length > 1 ? 's' : '') : '✓ No authentication failures' }),
      h('p', { text: verdictText() }),
      h('div', { class: 'vbtns' },
        h('button', { id: 'auth-copy', onclick: () => copyText(authReport()), text: 'Copy report' }),
        h('button', { id: 'auth-dl', onclick: () => download(S.fileName.replace(/\.(har|json)$/i, '') + '-auth-report.md', authReport(), 'text/markdown'), text: 'Download report' }),
        h('span', { class: 'muted', text: 'The report leaves out tokens, passwords, cookie values and keys.' }))),
    A.notes.map(n => h('div', { class: 'anote', text: n })),
    h('h3', { text: 'Failures' }),
    fails.length ? capped(fails, v => eventCard(v)) : h('p', { class: 'muted', text: 'None.' }),
    normals.length ? h('details', { class: 'normals' }, h('summary', { text: 'Normal challenge steps (' + normals.length + ')' }), capped(normals, v => eventCard(v))) : null,
    h('h3', { text: 'Sign-in flows' }),
    A.flows.length ? capped(A.flows, flowCard) : h('p', { class: 'muted', text: 'No OAuth / OpenID Connect, SAML, NTLM or Kerberos exchanges found.' }),
    h('h3', { text: 'Authentication methods by host' }),
    A.hosts.size ? h('table', { class: 'simple' }, h('colgroup', null, h('col', { style: { width: '34%' } }), h('col')),
      h('thead', null, h('tr', null, h('th', { text: 'Host' }), h('th', { text: 'Methods (requests)' }))),
      h('tbody', null, [...A.hosts].map(([host, m]) => h('tr', null, h('td', { class: 'url', text: host }), h('td', null, [...m].map(([k, n]) => h('span', { class: 'mchip', text: k + ' (' + n + ')' }))))))) : h('p', { class: 'muted', text: 'No credentials found in this HAR.' }),
    h('h3', { text: 'Tokens' }),
    toks.length ? h('table', { class: 'simple tokens' },
      h('colgroup', null, h('col', { style: { width: '150px' } }), h('col', { style: { width: '80px' } }), h('col'), h('col'), h('col'), h('col', { style: { width: '170px' } }), h('col', { style: { width: '110px' } })),
      h('thead', null, h('tr', null, ['Token', 'Kind', 'Issuer', 'Audience', 'Scopes / roles', 'Expires', 'Used'].map(x => h('th', { text: x })))),
      h('tbody', null, toks.map(t => {
        const p = t.jwt && t.jwt.payload, expiredUses = p && p.exp ? t.uses.filter(e => p.exp * 1000 <= entryTime(e)).length : 0;
        return h('tr', null, h('td', { class: 'mono', text: t.fp }), h('td', { text: [...t.kinds].join(' / ') || 'sent' + (t.jwt ? '' : ' (opaque)') }),
          h('td', { text: p ? p.iss || '' : '' }), h('td', { text: p ? [].concat(p.aud || []).join(', ') : '' }), h('td', { text: p ? [...scopesOf(p)].join(' ') : '' }),
          h('td', { text: p && p.exp ? fmtDate(p.exp * 1000) : '' }),
          h('td', null, t.uses.length + '×', expiredUses ? h('span', { class: 'errtxt', text: ' (' + expiredUses + ' after expiry)' }) : null));
      }))) : h('p', { class: 'muted', text: 'No tokens found.' })));
}

/* ---------- Auth tab in the request details ---------- */
const hasAuthInfo = e => !!(e.auth || e.oauthRole || e.saml);
function claimsKv(jwt, e) {
  if (jwt.encrypted) return h('p', { class: 'note', text: 'Encrypted JWT (JWE): its claims cannot be read without the key. alg ' + jwt.header.alg + ', enc ' + jwt.header.enc + '.' });
  const rows = [['header.alg', jwt.header.alg], jwt.header.typ ? ['header.typ', jwt.header.typ] : null, jwt.header.kid ? ['header.kid', jwt.header.kid] : null];
  for (const [k, v] of Object.entries(jwt.payload || {})) {
    let s = typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (/^(exp|iat|nbf|auth_time)$/.test(k) && typeof v === 'number') { const d = v * 1000 - entryTime(e); s = fmtDate(v * 1000) + '  (' + fmtDelta(d) + (d >= 0 ? ' after' : ' before') + ' this request)'; }
    rows.push([k, s]);
  }
  return kvList(rows.filter(Boolean));
}
function authDetail(e) {
  const out = [], a = e.auth || { creds: [], ch: [], pch: [] };
  if (a.event) out.push(eventCard(a.event, true));
  out.push(h('h4', { text: 'Credentials sent' }));
  if (!a.creds.length) out.push(h('p', { class: 'note', text: 'None (no Authorization or Proxy-Authorization header, API key or session cookie).' }));
  for (const c of a.creds) {
    out.push(h('p', { class: 'credl', text: c.label }));
    const rows = [['Method', c.method]];
    if (c.user != null) rows.push(['User', c.user]);
    if (c.pwLen != null) rows.push(['Password', c.pwLen ? c.pwLen + ' characters (not shown)' : 'empty']);
    if (c.neg && c.neg.ntlm) { const n = c.neg.ntlm; rows.push(['NTLM message', 'type ' + n.type]); if (n.type === 3) rows.push(['Domain', n.domain || '(none)'], ['User', n.user || '(anonymous)'], ['Workstation', n.workstation || ''], ['Response', n.version + ' (' + n.ntLen + ' bytes)']); }
    if (c.aws) rows.push(['Access key', maskId(c.aws.key)], ['Date', c.aws.date || ''], ['Region', c.aws.region || ''], ['Service', c.aws.service || '']);
    if (c.presign) rows.push(['Signed', fmtDate(c.presign.signed)], ['Valid until', fmtDate(c.presign.expires)]);
    if (c.sas) rows.push(['Permissions', c.sas.perms], ['Valid from', fmtDate(c.sas.start)], ['Valid until', fmtDate(c.sas.expiry)]);
    out.push(kvList(rows));
    if (c.jwt) { out.push(h('p', { class: 'note', text: 'Decoded token claims (the signature is not verified):' })); out.push(claimsKv(c.jwt, e)); }
  }
  if (a.ch.length || a.pch.length) { out.push(h('h4', { text: 'Server challenge' })); for (const c of a.ch) out.push(h('p', { class: 'mono', text: 'WWW-Authenticate: ' + challengeText(c) })); for (const c of a.pch) out.push(h('p', { class: 'mono', text: 'Proxy-Authenticate: ' + challengeText(c) })); }
  if (e.oauthRole === 'token' && e.tokenReq) {
    out.push(h('h4', { text: 'OAuth token request' }));
    out.push(kvList(Object.entries(e.tokenReq).map(([k, v]) => [k, SECRET_FIELD.test(k) ? fp(v) + ' (hidden)' : typeof v === 'object' ? JSON.stringify(v) : v])));
  }
  if (e.oauthRole === 'authorize') { out.push(h('h4', { text: 'OAuth authorization request' })); out.push(kvList([...e.u.searchParams].map(([k, v]) => [k, v]))); }
  if (e.flow) out.push(h('h4', { text: 'Part of this sign-in flow' }), flowCard(e.flow));
  if (e.saml) {
    const i = e.saml.info;
    out.push(h('h4', { text: 'SAML response' }), kvList([['Status', i.status + (i.subStatus ? ' / ' + i.subStatus : '')], ['Message', i.message], ['Issuer', i.issuer], ['NameID', i.nameId], ['Destination', i.destination], ['InResponseTo', i.inResponseTo], ['Audience', i.audiences.join(', ')], ['Valid', fmtDate(i.notBefore) + ' → ' + fmtDate(i.notOnOrAfter)], ['Signed', i.signed ? 'yes' : 'no'], ['Encrypted assertion', i.encrypted ? 'yes' : 'no']].filter(r => r[1])));
  }
  return out;
}

/* ======================================================================
   Diagnostics: CORS, network/TLS errors, server and gateway errors,
   rate limiting and retries, hidden failures and API errors, redirects,
   WebSockets/SSE, hangs, caching/CDN, page-load performance, security.
   Each check turns evidence in the HAR into an event with ranked causes.
   ====================================================================== */
