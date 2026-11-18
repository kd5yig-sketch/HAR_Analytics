/* ---------- copy a request as code ----------
   Each builder replays the request as recorded: method, URL, headers and body.
   Headers that tools set themselves (Host, Content-Length, HTTP/2 pseudo
   headers, Connection, Accept-Encoding) are left out. */
function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
const SKIP_COPY_HEADER = /^(:.*|content-length|host|connection|accept-encoding|keep-alive|transfer-encoding|upgrade|te)$/i;
function copyParts(e) {
  const r = e.raw.request || {}, pd = r.postData;
  const headers = (r.headers || []).filter(x => !SKIP_COPY_HEADER.test(String(x.name))).map(x => [String(x.name), String(x.value ?? '')]);
  let body = null, form = null;
  if (pd && pd.text != null && pd.text !== '') body = String(pd.text);
  else if (pd && Array.isArray(pd.params) && pd.params.length) form = pd.params.map(p => [p.name, p.value || '']);
  return { method: e.method, url: e.url, headers, body, form, mime: pd ? pd.mimeType || '' : '' };
}
function toCurl(e) {
  const c = copyParts(e), parts = ['curl ' + shq(c.url)];
  if (c.method !== 'GET' && !(c.method === 'POST' && (c.body != null || c.form))) parts.push('-X ' + c.method);
  for (const [n, v] of c.headers) parts.push('-H ' + shq(n + ': ' + v));
  if (c.body != null) parts.push('--data-raw ' + shq(c.body));
  else if (c.form) for (const [k, v] of c.form) parts.push('--data-urlencode ' + shq(k + '=' + v));
  parts.push('--compressed');
  return parts.join(' \\\n  ');
}
function toFetch(e) {
  const c = copyParts(e), h = {}, notes = [];
  for (const [n, v] of c.headers) { if (/^(cookie|user-agent|origin|referer|sec-.*)$/i.test(n)) notes.push(n); h[n] = v; }
  const opts = ['  method: ' + JSON.stringify(c.method) + ','];
  if (c.headers.length) opts.push('  headers: ' + JSON.stringify(h, null, 2).replace(/\n/g, '\n  ') + ',');
  if (c.body != null) opts.push('  body: ' + JSON.stringify(c.body) + ',');
  else if (c.form) opts.push('  body: new URLSearchParams(' + JSON.stringify(c.form) + '),');
  return (notes.length ? '// Browsers do not let scripts set ' + [...new Set(notes)].join(', ') + '; they work when run with Node 18+.\n' : '') +
    'const response = await fetch(' + JSON.stringify(c.url) + ', {\n' + opts.join('\n') + '\n});\nconsole.log(response.status, await response.text());';
}
function psq(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }
function toPowerShell(e) {
  const c = copyParts(e), lines = ['$headers = @{'];
  let ct = '', ua = '';
  for (const [n, v] of c.headers) { if (/^content-type$/i.test(n)) ct = v; else if (/^user-agent$/i.test(n)) ua = v; else lines.push('  ' + psq(n) + ' = ' + psq(v)); }
  lines.push('}');
  const args = ['-Uri ' + psq(c.url), '-Method ' + c.method, '-Headers $headers'];
  if (ua) args.push('-UserAgent ' + psq(ua));
  if (ct) args.push('-ContentType ' + psq(ct));
  if (c.body != null) args.push('-Body ' + psq(c.body));
  else if (c.form) args.push('-Body ' + psq(new URLSearchParams(c.form).toString()));
  args.push('-UseBasicParsing');
  return lines.join('\n') + '\n$response = Invoke-WebRequest ' + args.join(' `\n  ') + '\n$response.StatusCode\n$response.Content';
}
function pyStr(s) { return JSON.stringify(String(s)); }
function toPython(e) {
  const c = copyParts(e), L = ['import requests', '', 'response = requests.request(', '    ' + pyStr(c.method) + ',', '    ' + pyStr(c.url) + ','];
  if (c.headers.length) { L.push('    headers={'); for (const [n, v] of c.headers) L.push('        ' + pyStr(n) + ': ' + pyStr(v) + ','); L.push('    },'); }
  if (c.body != null) L.push('    data=' + pyStr(c.body) + '.encode("utf-8"),');
  else if (c.form) { L.push('    data={'); for (const [k, v] of c.form) L.push('        ' + pyStr(k) + ': ' + pyStr(v) + ','); L.push('    },'); }
  L.push(')', 'print(response.status_code)', 'print(response.text)');
  return L.join('\n');
}
function toHttpie(e) {
  const c = copyParts(e), parts = ['http'];
  if (c.body != null) parts.push('--raw ' + shq(c.body));
  else if (c.form) parts.push('--form');
  parts.push(c.method, shq(c.url));
  for (const [n, v] of c.headers) parts.push(shq(n + ':' + v));
  if (c.form) for (const [k, v] of c.form) parts.push(shq(k + '=' + v));
  return parts.join(' \\\n  ');
}
function toWget(e) {
  const c = copyParts(e), parts = ['wget --quiet --output-document=- --method=' + c.method];
  for (const [n, v] of c.headers) parts.push('--header=' + shq(n + ': ' + v));
  if (c.body != null) parts.push('--body-data=' + shq(c.body));
  else if (c.form) parts.push('--body-data=' + shq(new URLSearchParams(c.form).toString()));
  parts.push(shq(c.url));
  return (/%2[1-9a-c]|%3[a-f]|%40/i.test(c.url) ? '# Note: wget decodes some percent-encoded characters in the URL (for example %27 becomes \')\n' : '') + parts.join(' \\\n  ');
}
const COPY_FORMATS = [['url', 'URL', e => e.url], ['curl', 'cURL (bash)', toCurl], ['fetch', 'JavaScript fetch', toFetch], ['powershell', 'PowerShell', toPowerShell], ['python', 'Python requests', toPython], ['httpie', 'HTTPie', toHttpie], ['wget', 'wget', toWget]];

// Postman collection v2.1 for a list of requests. With maskSecrets, credentials
// become collection variables ({{authorization}}, {{cookie}}, …) instead of values.
function toPostman(list, name, maskSecrets = true) {
  const vars = new Map();
  const v = (key, sample) => { if (!vars.has(key)) vars.set(key, sample); return '{{' + key + '}}'; };
  const item = list.map(e => {
    const c = copyParts(e);
    const header = c.headers.filter(([n]) => !/^(user-agent|sec-|origin|referer)/i.test(n)).map(([n, val]) => {
      if (maskSecrets && /^authorization$/i.test(n)) { const sp = val.indexOf(' '); return { key: n, value: (sp > 0 ? val.slice(0, sp + 1) : '') + v('token', '') }; }
      if (maskSecrets && SENSITIVE_HEADER.test(n)) return { key: n, value: v(n.toLowerCase().replace(/[^a-z0-9]+/g, '_'), '') };
      return { key: n, value: val };
    });
    let url = c.url; if (maskSecrets) url = redactUrl(url).replace(/\[REDACTED\]/g, () => v('secret_param', ''));
    let u = null; try { u = new URL(url.replace(/\{\{|\}\}/g, '')); } catch (_) { /* keep raw */ }
    const req = { method: c.method, header, url: u ? { raw: url, protocol: u.protocol.replace(':', ''), host: u.hostname.split('.'), ...(u.port ? { port: u.port } : {}), path: u.pathname.split('/').filter(Boolean), ...(u.search ? { query: url.split('?')[1].split('#')[0].split('&').map(p => { const i = p.indexOf('='); return { key: decodeURIComponentSafe(i < 0 ? p : p.slice(0, i)), value: i < 0 ? '' : p.slice(i + 1) }; }) } : {}) } : url };
    if (c.body != null) req.body = { mode: 'raw', raw: maskSecrets ? redactBodyText(c.body, c.mime) : c.body, ...(/json/i.test(c.mime) || /^\s*[[{]/.test(c.body) ? { options: { raw: { language: 'json' } } } : {}) };
    else if (c.form) req.body = { mode: 'urlencoded', urlencoded: c.form.map(([k, val]) => ({ key: k, value: maskSecrets && isSensitiveName(k) ? v('secret_param', '') : val })) };
    return { name: '#' + e.i + ' ' + c.method + ' ' + (u ? u.pathname : c.url).slice(0, 80), request: req };
  });
  return {
    info: { name: name, description: 'Exported from ' + name + ' by HAR Analytics.' + (maskSecrets ? ' Credentials were replaced by collection variables; fill them in before sending.' : ''), schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
    item, variable: [...vars].map(([key, value]) => ({ key, value, type: 'string' })),
  };
}
