const DCATS = [
  ['rules', 'Your rules'], ['cors', 'CORS'], ['network', 'Network & TLS errors'], ['server', 'Server & gateway errors'], ['ratelimit', 'Rate limiting & retries'],
  ['hidden', 'Hidden failures & API errors'], ['redirect', 'Redirects'], ['realtime', 'WebSockets & streaming'], ['hang', 'Hangs & incomplete requests'],
  ['cache', 'Caching & CDN'], ['perf', 'Page-load performance'], ['security', 'Security hygiene'],
];
const DCAT_LABEL = Object.fromEntries(DCATS);
const D = { events: [], error: '' };
const C = (conf, id, title, detail, fixes) => ({ conf, id, title, detail: detail || '', fixes: fixes || [] });
const resH = e => (e.raw.response || {}).headers || [];
const reqH = e => (e.raw.request || {}).headers || [];
const isOk = e => e.status >= 200 && e.status < 400;
const isFail = e => e.status === 0 || e.status >= 400;
function dAdd(cat, sev, e, headline, causes, evidence, related, extra) {
  causes = (causes || []).filter(Boolean).sort((a, b) => CONF_ORDER[a.conf] - CONF_ORDER[b.conf]);
  const v = { cat, sev, e: e || null, headline, causes, evidence: (evidence || []).filter(Boolean), related: [...new Set((related || []).filter(x => x && x !== e))], normal: false, ...(extra || {}) };
  D.events.push(v);
  for (const x of [v.e, ...v.related]) if (x) (x.diag || (x.diag = [])).push(v);
  return v;
}
const sevOf = causes => causes.some(c => c.conf === 'high') ? 'error' : causes.some(c => c.conf === 'likely') ? 'warn' : 'info';
function jsonOf(e) {
  if ('_json' in e) return e._json;
  e._json = null; e._jsonBad = false;
  const c = (e.raw.response || {}).content || {};
  if (c.size > 5e6) return null;
  const t = bodyText(c);
  if (t && /^\s*[[{]/.test(t)) { try { e._json = JSON.parse(t); } catch (_) { e._jsonBad = true; } }
  else if (t && /json/i.test(e.mime) && c.encoding !== 'base64' && t.trim()) e._jsonBad = true;
  return e._json;
}
function reqBodyText(e) { const pd = (e.raw.request || {}).postData; return pd && pd.text != null ? String(pd.text) : ''; }
function median(a) { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y); return s[s.length >> 1]; }
function stackTrace(text) {
  if (!text) return null;
  const t = text.slice(0, 200000);
  const lang = /Traceback \(most recent call last\)/.test(t) ? 'Python' : /(\\n|\n)(\\t|\s)*at [\w$.<>[\]`]+ ?\([^)]*\.java:\d+\)/.test(t) ? 'Java' : /\.cs:line \d+/.test(t) ? '.NET' : /(\\n|\n)(\\t|\s)*at [\w$.<>]+ \((\/|[A-Za-z]:\\|node:|file:)[^)]*:\d+:\d+\)/.test(t) ? 'Node.js' : /Stack trace:(\\n|\n)#0 |PHP (Fatal|Parse) error|Fatal error: .* on line \d+/.test(t) ? 'PHP' : /\.rb:\d+:in `/.test(t) ? 'Ruby' : /goroutine \d+ \[running\]/.test(t) ? 'Go' : null;
  if (!lang) return null;
  const m = /\b((?:[a-z_]\w*\.)*[A-Z][\w$]*(?:Exception|Error))\b(?::|\s-)?[ \t]*([^\n<]{0,240})/.exec(t) || /(Fatal error: [^\n<]{0,160})/.exec(t) || /(panic: [^\n<]{0,160})/.exec(t);
  const msg = m && m[2] ? m[2].split(/\\n|\\t|\\r/)[0].replace(/\\"/g, '"').replace(/["',}\]\s]+$/, '').slice(0, 160).trim() : '';
  return { lang, summary: m ? m[1] + (msg ? ': ' + msg : '') : lang + ' stack trace' };
}

/* ---------- CORS ---------- */
const corsList = v => String(v || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
function findActual(pre) { const m = hdr(reqH(pre), 'access-control-request-method').toUpperCase(); return sameUrl(pre).find(x => x !== pre && x.start >= pre.start && x.start - pre.start < 10000 && x.method === m && noQuery(x.url) === noQuery(pre.url)) || null; }
function findPreflight(e) { return sameUrl(e).filter(x => x !== e && x.method === 'OPTIONS' && x.start <= e.start && e.start - x.start < 10000 && noQuery(x.url) === noQuery(e.url) && hdr(reqH(x), 'access-control-request-method').toUpperCase() === e.method).pop() || null; }
function diagCors() {
  for (const e of S.entries) {
    if (!e.u) continue;
    const RQ = reqH(e), RS = resH(e), origin = hdr(RQ, 'origin'), mode = hdr(RQ, 'sec-fetch-mode').toLowerCase();
    if (!origin) continue;
    const isPre = e.method === 'OPTIONS' && !!hdr(RQ, 'access-control-request-method');
    if (!isPre) {
      if (mode === 'navigate' || mode === 'no-cors' || mode === 'same-origin' || mode === 'websocket' || e.type === 'doc' || e.type === 'ws') continue;
      if (!mode && !['xhr', 'font'].includes(e.type)) continue;
      if (origin !== 'null' && origin === e.u.origin) continue;
      if (e.status >= 300 && e.status < 400) continue;
    }
    if (e.auth && e.auth.event && !e.auth.event.normal && (isPre || e.status === 401 || e.status === 403)) continue; // explained by the Authentication analysis
    const actual = isPre ? findActual(e) : e;
    const credentialed = !!(actual && (hdr(reqH(actual), 'cookie') || ((actual.raw.request || {}).cookies || []).length));
    const acao = hdrAll(RS, 'access-control-allow-origin'), acaoV = acao.join(', '), acac = /^true$/i.test(hdr(RS, 'access-control-allow-credentials'));
    const causes = [], ev = ['Origin: ' + origin, acao.length ? 'Access-Control-Allow-Origin: ' + acaoV : 'No Access-Control-Allow-Origin header in the response'];
    if (acac) ev.push('Access-Control-Allow-Credentials: true');
    if (credentialed) ev.push('The request carried cookies (credentials mode "include").');
    if (e.status === 0) {
      if (isPre) causes.push(C('likely', 'cors_preflight_failed', 'The preflight failed without a response', e.error ? 'Error: ' + e.error : 'No response was recorded.', []));
      else {
        const pre = findPreflight(e);
        if (pre && pre.diag && pre.diag.some(v => v.cat === 'cors')) continue;
        if (netCode(e) && !/^(FAILED)$/.test(netCode(e))) continue; // a real network error, handled by the network decoder
        causes.push(C(pre ? 'likely' : 'possible', 'cors_blocked', 'The cross-origin request got no usable response, probably blocked by CORS', 'Browsers do not record the CORS reason in a HAR. ' + (pre ? 'Its preflight (#' + pre.i + ') looked fine. ' : '') + 'The DevTools Console shows the exact message.', ['Look in the Console for "has been blocked by CORS policy" for this URL.']));
      }
    } else {
      if (isPre && (e.status < 200 || e.status >= 300)) causes.push(C('high', 'cors_preflight_status', 'The preflight returned HTTP ' + e.status + ' instead of 2xx', e.status >= 300 && e.status < 400 ? 'Preflight requests must not be redirected.' : 'Browsers require the OPTIONS preflight to succeed (200 or 204) before they send the real request.' + (e.status === 404 || e.status === 405 ? ' The server or gateway does not handle OPTIONS for this path.' : ''), ['Answer OPTIONS for this path with 204 and the Access-Control-Allow-* headers, without requiring authentication.']));
      if (!acao.length) causes.push(C('high', 'cors_no_acao', 'The ' + (isPre ? 'preflight response' : 'response') + ' has no Access-Control-Allow-Origin header', 'The page at ' + origin + ' is not allowed to read it.' + (e.status >= 400 ? ' Error responses often skip the CORS middleware, which hides the real HTTP ' + e.status + ' error behind a CORS message.' : ''), ['Return Access-Control-Allow-Origin: ' + origin + ' (or * when no cookies are involved) on every response, including errors.']));
      else if (acao.length > 1 || acaoV.includes(',')) causes.push(C('high', 'cors_multi_acao', 'Access-Control-Allow-Origin has more than one value', '"' + acaoV + '". Only one origin (or *) is allowed. This usually means both the application and a proxy add the header.', ['Add the header in one place only: the application or the proxy/gateway.']));
      else {
        const a = acao[0].trim();
        if (a === '*' && credentialed) causes.push(C('high', 'cors_wildcard_credentials', 'Access-Control-Allow-Origin is * but the request carries cookies', 'With credentials the wildcard is not allowed: the server must echo the exact origin and send Access-Control-Allow-Credentials: true.', ['Echo the request Origin (checked against an allow list) instead of *, and add Vary: Origin.']));
        else if (a !== '*' && a !== origin) {
          const cached = hdr(RS, 'age') || /hit/i.test(hdr(RS, 'x-cache') + ' ' + hdr(RS, 'cf-cache-status'));
          causes.push(C('high', 'cors_origin_mismatch', 'Access-Control-Allow-Origin is "' + a + '" but the page origin is "' + origin + '"', (cached ? 'This response came from a cache (' + [hdr(RS, 'age') ? 'Age: ' + hdr(RS, 'age') : '', hdr(RS, 'x-cache'), hdr(RS, 'cf-cache-status')].filter(Boolean).join(', ') + ') and was probably cached for a page on another origin' + (/origin/i.test(hdr(RS, 'vary')) ? '' : ', because Vary: Origin is missing') + '. ' : '') + (origin === 'null' ? 'Browsers send Origin: null after a cross-origin redirect, from sandboxed iframes and from file:// pages.' : 'Origins must match exactly: scheme, host and port.'), ['Echo the allowed request origin exactly, and add Vary: Origin so caches keep one copy per origin.']));
        }
        if (credentialed && !acac) causes.push(C('high', 'cors_no_credentials', 'The request carries cookies but the response lacks Access-Control-Allow-Credentials: true', 'Without it the browser hides the response from the page.', ['Send Access-Control-Allow-Credentials: true together with a specific origin (not *).']));
        if (a !== '*' && !/origin/i.test(hdr(RS, 'vary')) && !isPre && !causes.length) causes.push(C('possible', 'cors_no_vary', 'Access-Control-Allow-Origin echoes the origin but Vary: Origin is missing', 'A CDN or browser cache may later serve this response to a page on another origin, which then fails CORS.', ['Add Vary: Origin.']));
      }
      if (isPre && e.status >= 200 && e.status < 300) {
        const reqM = hdr(RQ, 'access-control-request-method').toUpperCase(), allowM = corsList(hdr(RS, 'access-control-allow-methods')).map(x => x.toUpperCase());
        if (!['GET', 'HEAD', 'POST'].includes(reqM) && !allowM.includes(reqM) && !(allowM.includes('*') && !credentialed)) causes.push(C('high', 'cors_method', 'The preflight does not allow the ' + reqM + ' method', 'Access-Control-Allow-Methods: ' + (hdr(RS, 'access-control-allow-methods') || '(missing)') + '.', ['Add ' + reqM + ' to Access-Control-Allow-Methods.']));
        const want = corsList(hdr(RQ, 'access-control-request-headers')), allowH = corsList(hdr(RS, 'access-control-allow-headers'));
        const missing = want.filter(x => !allowH.includes(x) && !(allowH.includes('*') && !credentialed && x !== 'authorization'));
        if (missing.length) causes.push(C('high', 'cors_headers', 'The preflight does not allow the request header' + (missing.length > 1 ? 's ' : ' ') + missing.join(', '), 'The page wants to send: ' + want.join(', ') + '. Access-Control-Allow-Headers: ' + (hdr(RS, 'access-control-allow-headers') || '(missing)') + '.' + (missing.includes('authorization') && allowH.includes('*') ? ' The * wildcard never covers Authorization; it must be listed by name.' : ''), ['Add ' + missing.join(', ') + ' to Access-Control-Allow-Headers.']));
        if (/^true$/i.test(hdr(RQ, 'access-control-request-private-network')) && !/^true$/i.test(hdr(RS, 'access-control-allow-private-network'))) causes.push(C('high', 'cors_pna', 'Private Network Access was not granted', 'A public website (' + origin + ') is calling a private or local address (' + e.u.host + '). Chrome requires the preflight response to include Access-Control-Allow-Private-Network: true.', ['Return Access-Control-Allow-Private-Network: true on the preflight, or serve the page from the private network.']));
      }
      if (isPre) {
        const reqM = hdr(RQ, 'access-control-request-method').toUpperCase();
        if (actual) ev.push('Actual request: #' + actual.i + ' ' + actual.method + ' → ' + (actual.status || 'no response'));
        else if (causes.length) ev.push('The actual ' + reqM + ' request is not in the HAR: the browser never sent it.');
      }
      if (origin === 'null' && e.redirectFrom) ev.push('This request followed a cross-origin redirect from #' + e.redirectFrom.i + ', which makes the browser send Origin: null.');
    }
    if (!causes.length) continue;
    causes.sort((x, y) => CONF_ORDER[x.conf] - CONF_ORDER[y.conf]);
    dAdd('cors', sevOf(causes), e, (isPre ? 'CORS preflight failed' : 'CORS check failed') + ': ' + causes[0].title, causes, ev, isPre && actual ? [actual] : []);
  }
}

/* ---------- Network and TLS errors ---------- */
const NET_ERR = {
  NAME_NOT_RESOLVED: ['error', 'DNS lookup failed', 'The host name could not be resolved: a typo, a domain that no longer exists, an internal name used outside the corporate network or VPN, or a DNS server problem.', ['Check the host name and run nslookup / dig for it on the same machine.', 'If it is an internal name, connect to the VPN or corporate network.']],
  NAME_RESOLUTION_FAILED: ['error', 'DNS resolution failed', 'The DNS server could not be reached or returned an error.', ['Check the DNS server settings and network connection.']],
  DNS_TIMED_OUT: ['error', 'DNS lookup timed out', 'The DNS server did not answer in time.', ['Check the DNS server and network.']],
  INTERNET_DISCONNECTED: ['error', 'The computer was offline', 'The operating system reported no network connection.', ['Check the network connection.']],
  NETWORK_CHANGED: ['error', 'The network changed during the request', 'The network switched (Wi-Fi change, VPN connecting or disconnecting, docking), which kills open connections.', ['Retry; if it keeps happening, look at VPN or Wi-Fi stability.']],
  NETWORK_IO_SUSPENDED: ['warn', 'The computer went to sleep', 'Network activity was suspended (sleep or hibernation) during the request.', []],
  NETWORK_ACCESS_DENIED: ['error', 'Network access was denied', 'A firewall, antivirus or operating-system policy blocked the browser from connecting.', ['Check local firewall / antivirus / endpoint-protection rules.']],
  ADDRESS_UNREACHABLE: ['error', 'No route to the server', 'The IP address is unreachable from this network (routing, VPN split tunnel, or a firewall).', ['Check routing / VPN and whether the server is up.']],
  CONNECTION_REFUSED: ['error', 'Connection refused', 'Nothing is listening on that host and port, or a firewall actively rejected the connection. Typical: the service is down or restarting, wrong port, or the app only listens on localhost.', ['Check the service is running and listening on the expected port, and that firewalls allow it.']],
  CONNECTION_RESET: ['error', 'Connection reset', 'The connection was abruptly closed: a firewall, proxy or intrusion-prevention system cut it, the server crashed, or TLS inspection interfered.', ['Check firewall / proxy / IPS logs, and server logs for crashes at this time.']],
  CONNECTION_CLOSED: ['error', 'The server closed the connection without a response', 'Often a proxy or load-balancer timeout, a crash while processing, or a keep-alive connection closed by the server just as the browser reused it.', ['Check server and proxy logs; align keep-alive timeouts (server longer than the client/proxy).']],
  CONNECTION_ABORTED: ['error', 'Connection aborted', 'The connection was aborted, typically because no ACK came back (network or firewall).', []],
  CONNECTION_TIMED_OUT: ['error', 'Connection timed out', 'The TCP connection could not be established: the host is down, a firewall silently drops the packets, or the route is broken.', ['Check that the host is up and reachable on that port from this network.']],
  TIMED_OUT: ['error', 'The request timed out', 'The operation took too long: the server never answered, or the network stalled.', ['Check server-side processing time and network stability.']],
  EMPTY_RESPONSE: ['error', 'The server sent nothing back', 'The connection closed without a single byte of response: a crash, a proxy timeout, or a port that speaks a different protocol (for example HTTP to an HTTPS port).', ['Check server logs; verify the scheme and port.']],
  SSL_PROTOCOL_ERROR: ['error', 'TLS handshake failed', 'The secure connection could not be set up: the port does not speak TLS, a proxy interfered, or the server’s TLS configuration is broken.', ['Test with openssl s_client -connect host:443 -servername host.']],
  SSL_VERSION_OR_CIPHER_MISMATCH: ['error', 'No common TLS version or cipher', 'The server only offers TLS versions or ciphers the browser no longer accepts (for example TLS 1.0/1.1 or RC4).', ['Enable TLS 1.2 and 1.3 with modern ciphers on the server.']],
  SSL_OBSOLETE_VERSION: ['error', 'The server uses an obsolete TLS version', 'TLS 1.0 and 1.1 are no longer accepted by browsers.', ['Enable TLS 1.2 / 1.3.']],
  SSL_UNRECOGNIZED_NAME_ALERT: ['error', 'The server does not recognize this host name (SNI)', 'The TLS server has no certificate configured for this name.', ['Add the host name to the server or load-balancer TLS configuration.']],
  CERT_DATE_INVALID: ['error', 'The server certificate has expired (or is not valid yet)', 'Either the certificate really expired, or this computer’s clock is wrong.', ['Renew the certificate; check the client clock.']],
  CERT_AUTHORITY_INVALID: ['error', 'The certificate is not trusted', 'Self-signed, issued by a private CA that is not installed, missing an intermediate certificate, or replaced by a TLS-inspection proxy (Zscaler, Netskope, antivirus) whose root is not trusted.', ['Install the full chain on the server (leaf + intermediates), or install the private / inspection CA root on the client.']],
  CERT_COMMON_NAME_INVALID: ['error', 'The certificate does not match the host name', 'The host is not listed in the certificate’s Subject Alternative Names (wrong certificate, a wildcard that does not cover this level, or access by IP address).', ['Use a certificate that covers this exact host name.']],
  CERT_REVOKED: ['error', 'The certificate was revoked', '', ['Install a new certificate.']],
  CERT_WEAK_SIGNATURE_ALGORITHM: ['error', 'The certificate uses a weak signature (SHA-1)', '', ['Reissue the certificate with SHA-256.']],
  CERTIFICATE_TRANSPARENCY_REQUIRED: ['error', 'The certificate is not logged in Certificate Transparency', '', ['Reissue the certificate from a public CA that logs to CT.']],
  CERT_INVALID: ['error', 'The certificate is invalid', '', ['Check the certificate and chain.']],
  CERT_KNOWN_INTERCEPTION_BLOCKED: ['error', 'A known TLS-interception certificate was blocked', 'The browser blocks certificates from known interception software.', ['Remove or update the interception software.']],
  SSL_PINNED_KEY_NOT_IN_CERT_CHAIN: ['error', 'Certificate pinning failed', 'The certificate chain does not contain a pinned key, typically because a TLS-inspection proxy re-signed it.', []],
  BAD_SSL_CLIENT_AUTH_CERT: ['error', 'The client certificate was rejected', 'See the Authentication tab.', []],
  SSL_CLIENT_AUTH_CERT_NEEDED: ['error', 'The server requires a client certificate', 'See the Authentication tab.', []],
  PROXY_CONNECTION_FAILED: ['error', 'Could not connect to the proxy', 'The configured proxy is down or unreachable.', ['Check the proxy / PAC settings.']],
  TUNNEL_CONNECTION_FAILED: ['error', 'The proxy refused to open a tunnel', 'The proxy rejected the CONNECT request: the destination is blocked by policy, the proxy needs authentication, or the port is not allowed.', ['Ask IT to allow the destination, or configure proxy authentication.']],
  PROXY_CERTIFICATE_INVALID: ['error', 'The proxy’s certificate is invalid', '', []],
  PROXY_AUTH_UNSUPPORTED: ['error', 'The proxy uses an authentication method the browser cannot do', '', []],
  MANDATORY_PROXY_CONFIGURATION_FAILED: ['error', 'The required proxy configuration failed', 'The PAC file or proxy settings enforced by policy could not be applied.', []],
  PAC_SCRIPT_FAILED: ['error', 'The proxy auto-config (PAC) script failed', '', ['Check the PAC file URL and script.']],
  BLOCKED_BY_CLIENT: ['warn', 'Blocked by a browser extension', 'An ad blocker, privacy or security extension blocked this request. This is common for analytics, tracking and ad URLs, and sometimes breaks apps that depend on them.', ['Retest with extensions disabled (or in a private window).']],
  BLOCKED_BY_ADMINISTRATOR: ['error', 'Blocked by an administrator policy', 'A browser policy (URLBlocklist) blocked this URL.', ['Ask IT about the browser policy.']],
  BLOCKED_BY_RESPONSE: ['error', 'Blocked by the response’s cross-origin policy', 'Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy or X-Frame-Options / frame-ancestors forbid using this response here.', ['Adjust Cross-Origin-Resource-Policy (for example cross-origin) on the resource, or the embedding policy on the page.']],
  BLOCKED_BY_CSP: ['error', 'Blocked by Content-Security-Policy', 'The page’s CSP does not allow loading this URL.', ['Add the source to the matching CSP directive (script-src, connect-src, img-src…).']],
  BLOCKED_BY_ORB: ['warn', 'Blocked by Opaque Response Blocking', 'A cross-origin no-cors request (for example an <img> or <script>) received HTML, JSON or similar, which the browser blocks.', ['Make sure the URL returns the expected content type, or use fetch with CORS.']],
  ABORTED: ['harmless', 'Cancelled by the browser', 'The request was cancelled: the page navigated away, a newer request replaced it, the user stopped loading, or the code aborted it. Usually harmless.', []],
  FAILED: ['warn', 'Generic network failure', 'Chrome uses this for many problems, most often CORS. Check the Console for details.', ['Check the DevTools Console for this request.']],
  HTTP2_PROTOCOL_ERROR: ['error', 'HTTP/2 protocol error', 'The HTTP/2 stream was broken: often a proxy or server bug, response headers that are too large, or a response that violates HTTP/2 rules.', ['Check proxy / server logs; test with HTTP/1.1 to confirm.']],
  HTTP2_PING_FAILED: ['error', 'HTTP/2 connection lost (ping failed)', '', []],
  HTTP2_SERVER_REFUSED_STREAM: ['error', 'The HTTP/2 server refused the stream', 'The server is at its concurrent-stream limit or shutting down.', []],
  SPDY_PROTOCOL_ERROR: ['error', 'HTTP/2 protocol error', 'The HTTP/2 stream was broken (proxy or server bug, or oversized headers).', []],
  QUIC_PROTOCOL_ERROR: ['error', 'HTTP/3 (QUIC) failed', 'The QUIC connection over UDP broke. Firewalls that block or mangle UDP port 443 are a common cause.', ['Allow UDP 443, or disable QUIC to confirm.']],
  INCOMPLETE_CHUNKED_ENCODING: ['error', 'The response was cut off mid-stream', 'The server or a proxy stopped sending before the end (crash, timeout while streaming, or a buffering limit).', ['Check server and proxy logs and streaming timeouts.']],
  CONTENT_LENGTH_MISMATCH: ['error', 'The response body is shorter than its Content-Length', 'The download was truncated.', ['Check server / proxy logs; look for gzip or proxy buffering bugs.']],
  CONTENT_DECODING_FAILED: ['error', 'The response could not be decompressed', 'Content-Encoding says gzip/br but the body is not, often double compression by app and proxy.', ['Compress in one place only.']],
  RESPONSE_HEADERS_TOO_BIG: ['error', 'The response headers are too large', 'Usually caused by too many or too large Set-Cookie headers.', ['Reduce cookie count and size.']],
  RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH: ['error', 'The response has conflicting Content-Length headers', '', ['Fix the server / proxy so only one Content-Length is sent.']],
  RESPONSE_HEADERS_MULTIPLE_LOCATION: ['error', 'The response has several Location headers', '', []],
  RESPONSE_HEADERS_MULTIPLE_CONTENT_DISPOSITION: ['error', 'The response has several Content-Disposition headers', '', []],
  TOO_MANY_REDIRECTS: ['error', 'Too many redirects (redirect loop)', 'See the Redirects section for the loop.', []],
  UNSAFE_PORT: ['error', 'The browser blocks this port', 'Browsers refuse to connect to some ports (for example 25, 110, 6000).', ['Use a standard web port.']],
  INVALID_REDIRECT: ['error', 'The redirect target is invalid', '', []],
  UNSAFE_REDIRECT: ['error', 'The redirect target is not allowed', '', []],
  CACHE_MISS: ['harmless', 'Not available in the cache', 'Usually from back/forward navigation of a page that was POSTed. Harmless.', []],
  INSECURE_RESPONSE: ['error', 'The response was insecure', '', []],
  HTTP_RESPONSE_CODE_FAILURE: ['warn', 'Chrome treated the HTTP error status as a failure', 'Typically for downloads or subresources returning an error page.', []],
  ADDRESS_INVALID: ['error', 'Invalid address', '', []],
  SOCKET_NOT_CONNECTED: ['error', 'The socket was not connected', '', []],
};
const NET_ALIAS = { NS_ERROR_UNKNOWN_HOST: 'NAME_NOT_RESOLVED', NS_ERROR_CONNECTION_REFUSED: 'CONNECTION_REFUSED', NS_ERROR_NET_TIMEOUT: 'TIMED_OUT', NS_ERROR_NET_RESET: 'CONNECTION_RESET', NS_ERROR_NET_INTERRUPT: 'CONNECTION_CLOSED', NS_BINDING_ABORTED: 'ABORTED', NS_ERROR_ABORT: 'ABORTED', NS_ERROR_OFFLINE: 'INTERNET_DISCONNECTED', SEC_ERROR_EXPIRED_CERTIFICATE: 'CERT_DATE_INVALID', SEC_ERROR_UNKNOWN_ISSUER: 'CERT_AUTHORITY_INVALID', MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT: 'CERT_AUTHORITY_INVALID', SSL_ERROR_BAD_CERT_DOMAIN: 'CERT_COMMON_NAME_INVALID', NS_ERROR_PROXY_CONNECTION_REFUSED: 'PROXY_CONNECTION_FAILED', NS_ERROR_CORRUPTED_CONTENT: 'CONTENT_DECODING_FAILED', NS_ERROR_NET_PARTIAL_TRANSFER: 'CONTENT_LENGTH_MISMATCH', SSL_ERROR_NO_CYPHER_OVERLAP: 'SSL_VERSION_OR_CIPHER_MISMATCH' };
function netCode(e) {
  const m = /\b(?:net::)?ERR_([A-Z0-9_]+)|\b(NS_[A-Z_]+|SEC_ERROR_[A-Z_]+|SSL_ERROR_[A-Z_]+|MOZILLA_PKIX_ERROR_[A-Z_]+)\b/.exec(e.error || '');
  if (!m) return '';
  return m[1] || NET_ALIAS[m[2]] || m[2];
}
const isPending = e => e.status === 0 && !e.error && !resH(e).length && e.timings.wait === 0 && e.timings.receive === 0;
function diagNetwork() {
  const failed = S.entries.filter(e => e.status === 0), groups = new Map();
  for (const e of failed) {
    if (e.auth && e.auth.event && !e.auth.event.normal) continue;
    if (e.diag && e.diag.some(v => v.cat === 'cors')) continue;
    if (/^wss?:/.test(e.url) || e.type === 'ws') continue;
    const code = netCode(e);
    if (!code && isPending(e)) continue;
    const key = (code || '?') + '|' + e.host;
    if (!groups.has(key)) groups.set(key, { code, host: e.host, list: [] });
    groups.get(key).list.push(e);
  }
  for (const g of groups.values()) {
    const info = NET_ERR[g.code], n = g.list.length, first = g.list[0], last = g.list[n - 1];
    const hostOk = idx().okHosts.has(g.host);
    const ev = [g.code ? 'Browser error: ' + (first.error || g.code) : 'No error text was recorded.', n > 1 ? n + ' requests to ' + g.host + ' failed this way between +' + fmtMs(first.start) + ' and +' + fmtMs(last.start) + '.' : '', g.host ? (hostOk ? 'Other requests to ' + g.host + ' succeeded, so the host was reachable at other times.' : 'No request to ' + g.host + ' succeeded in this capture.') : ''];
    if (/^CERT_|^SSL_/.test(g.code) && g.host) ev.push('Inspect the certificate with: openssl s_client -connect ' + (first.u ? first.u.hostname + ':' + (first.u.port || 443) : g.host) + ' -servername ' + (first.u ? first.u.hostname : g.host));
    let causes, sev, normal = false, title;
    if (info) { const [kind, t, d, f] = info; title = t; causes = [C(kind === 'harmless' ? 'high' : 'high', 'net_' + g.code, t, d, f)]; sev = kind === 'harmless' ? 'info' : kind; normal = kind === 'harmless'; }
    else { title = g.code ? 'Network error ' + g.code : 'Failed without a response'; causes = [C('possible', 'net_unknown', title, g.code ? 'This error code is not in the built-in list.' : 'The HAR does not say why. Common reasons: blocked by CORS or an extension, the page navigated away, or a network failure.', ['Check the DevTools Console and Network tab for this request.'])]; sev = 'warn'; }
    dAdd('network', sev, first, title + (g.host ? ' — ' + g.host : '') + (n > 1 ? ' (' + n + ' requests)' : ''), causes, ev, g.list, { normal, code: g.code });
  }
  // Several hosts failing at the same time with no success in between = the client's network dropped.
  const bad = failed.filter(e => /INTERNET_DISCONNECTED|NETWORK_CHANGED|NETWORK_IO_SUSPENDED|TIMED_OUT|CONNECTION_RESET|CONNECTION_CLOSED|ADDRESS_UNREACHABLE|NAME_NOT_RESOLVED|NAME_RESOLUTION_FAILED|DNS_TIMED_OUT|QUIC_PROTOCOL_ERROR/.test(netCode(e))).sort((a, b) => a.start - b.start);
  for (let i = 0; i < bad.length;) {
    let j = i; while (j + 1 < bad.length && bad[j + 1].start - bad[i].start <= 15000) j++;
    const win = bad.slice(i, j + 1), hosts = new Set(win.map(x => x.host));
    const ok = idx().okStarts, at = lowerBound(ok, win[0].start), okInside = at < ok.length && ok[at] <= win[win.length - 1].start + 1;
    if (hosts.size >= 3 && !okInside) {
      dAdd('network', 'error', win[0], 'Network outage: ' + win.length + ' requests to ' + hosts.size + ' hosts failed within ' + fmtDelta(win[win.length - 1].start - win[0].start), [C('high', 'net_outage', 'The client’s network connection dropped', 'Requests to unrelated hosts (' + [...hosts].slice(0, 5).join(', ') + ') failed at the same time and nothing succeeded in between, so the problem is on the client side (Wi-Fi, VPN, proxy, or local firewall), not on any one server.', ['Check the Wi-Fi / VPN / proxy at ' + fmtDate(entryTime(win[0])) + '.'])], [], win);
      i = j + 1;
    } else i++;
  }
}

/* ---------- Server and gateway errors ---------- */
function whoAnswered(e) {
  const H = resH(e), st = e.status, server = hdr(H, 'server'), via = hdr(H, 'via'), xc = hdr(H, 'x-cache');
  const body = (bodyText((e.raw.response || {}).content || {}) || '').slice(0, 30000), ev = [];
  for (const n of ['server', 'via', 'x-cache', 'cf-ray', 'x-amzn-errortype', 'x-amz-apigw-id', 'x-amz-cf-id', 'x-azure-ref', 'x-served-by', 'x-vercel-error', 'x-envoy-upstream-service-time', 'x-kong-upstream-latency', 'x-powered-by']) { const v = hdr(H, n); if (v) ev.push(n + ': ' + v); }
  const title = (/<title[^>]*>([^<]{1,150})</i.exec(body) || [])[1];
  if (title) ev.push('Error page title: "' + htmlDecode(title) + '"');
  const R = (layer, t, d, f, conf) => ({ layer, title: t, detail: d, fixes: f || [], ev, conf: conf || 'high' });
  const not = ' This response was generated by the ' + '%L' + ', not by your application.';
  const gen = (layer, t, d, f) => R(layer, t, d + not.replace('%L', layer), f);
  if (/cloudflare/i.test(server) || hdr(H, 'cf-ray')) {
    const CF = { 520: ['the origin returned an empty or unexpected response', 'Cloudflare reached the origin but got nothing usable (crash, empty reply, or oversized headers).'], 521: ['the origin refused the connection', 'The web server behind Cloudflare is down, or its firewall blocks Cloudflare’s IP ranges.'], 522: ['the connection to the origin timed out', 'Cloudflare could not open a TCP connection to the origin (overloaded, firewall dropping Cloudflare IPs, wrong origin IP).'], 523: ['the origin is unreachable', 'DNS or routing to the origin is broken.'], 524: ['the origin took longer than 100 s to respond', 'Cloudflare connected, but the origin did not send a response within Cloudflare’s 100-second limit.'], 525: ['the TLS handshake with the origin failed', 'The origin’s TLS setup does not work with the zone’s SSL mode.'], 526: ['the origin’s certificate is invalid', 'In Full (strict) mode the origin certificate must be valid and match the host.'], 530: ['an origin DNS error (1xxx)', 'See the 1xxx code on the error page.'] };
    const cfc = (/Error (1\d{3})/.exec(body) || [])[1];
    if (CF[st]) return gen('Cloudflare edge', 'Cloudflare: ' + CF[st][0], CF[st][1], ['Check the origin server and its logs at this time; 52x errors are between Cloudflare and your origin.']);
    if (cfc) return gen('Cloudflare edge', 'Cloudflare error ' + cfc, 'Cloudflare 1xxx errors come from Cloudflare configuration, firewall rules or DNS.', ['Look up Cloudflare error ' + cfc + '.']);
  }
  if (/awselb/i.test(server)) {
    const M = { 502: 'the target returned an invalid response or closed the connection (app crashed, keep-alive timeout shorter than the load balancer’s, or headers too large)', 503: 'no healthy targets are registered in the target group', 504: 'the target did not respond before the load balancer’s idle timeout (60 s by default)', 500: 'the load balancer hit an internal error (for example an authentication action or a Lambda target error)' };
    if (M[st]) return gen('AWS load balancer (ALB/ELB)', 'AWS load balancer: ' + M[st], 'Check target health and the target’s logs.', ['Check target-group health checks and target logs; make the app’s keep-alive timeout longer than the load balancer’s idle timeout.']);
  }
  const et = hdr(H, 'x-amzn-errortype');
  if (et || hdr(H, 'x-amz-apigw-id')) {
    if (/IntegrationTimeout/i.test(et) || (st === 504 && /timed out/i.test(body))) return gen('AWS API Gateway', 'API Gateway: the backend integration timed out (29 s limit)', 'API Gateway stops waiting for the integration (Lambda / HTTP backend) after 29 seconds by default.', ['Make the backend faster, or move long work to an asynchronous job.']);
    if (st === 502) return gen('AWS API Gateway', 'API Gateway: the backend returned a malformed or failed response', 'For Lambda proxy integrations this usually means the function threw, timed out, or returned something other than {statusCode, headers, body}.', ['Check the Lambda / backend logs for this request ID.']);
    if (st >= 500) return gen('AWS API Gateway', 'API Gateway error ' + (et || st), '', ['Check API Gateway execution logs.']);
  }
  if (/cloudfront/i.test(via + ' ' + xc) || hdr(H, 'x-amz-cf-id')) {
    const M = { 502: 'CloudFront could not connect to the origin, or the origin’s TLS failed', 503: 'the origin or a Lambda@Edge function could not handle the request (capacity or function error)', 504: 'the origin did not respond in time (30 s origin response timeout by default)' };
    if (M[st]) return gen('Amazon CloudFront', 'CloudFront: ' + M[st], '', ['Check the origin and CloudFront origin settings (protocol, port, timeout).']);
  }
  if (/Microsoft-Azure-Application-Gateway/i.test(server)) return gen('Azure Application Gateway', 'Azure Application Gateway: ' + (st === 502 ? 'the backend pool is unhealthy, or the backend did not answer within the request timeout (20 s by default)' : 'HTTP ' + st), '', ['Check backend health in the Application Gateway and the backend’s logs.']);
  if (hdr(H, 'x-azure-ref') && st >= 500 && !/Microsoft-IIS|Kestrel/i.test(server)) return gen('Azure Front Door', 'Azure Front Door: ' + (st === 504 || st === 503 ? 'the origin did not respond within the origin response timeout (60 s by default)' : 'HTTP ' + st + ' between Front Door and the origin'), '', ['Check origin health and Front Door origin settings.']);
  const iis = /HTTP Error (5\d\d)\.(\d+)/.exec(body);
  if (iis || /Microsoft-IIS/i.test(server)) {
    const sub = iis ? iis[1] + '.' + iis[2] : '';
    const M = { '502.3': 'IIS Application Request Routing / ASP.NET Core Module: the backend timed out or refused the connection', '502.5': 'the ASP.NET Core process failed to start', '500.30': 'the ASP.NET Core app failed to start (in-process)', '500.31': 'the ASP.NET Core runtime could not be found', '500.19': 'the web.config configuration is invalid', '503.0': 'the application pool is stopped or overloaded', '500.0': 'an unhandled application error' };
    if (M[sub]) return R('IIS', 'IIS ' + sub + ': ' + M[sub], 'Check the Windows event log and the app’s stdout log.', ['Check the Application event log and enable stdoutLogEnabled for ASP.NET Core.']);
    if (st === 503) return R('IIS', 'IIS 503: the application pool is stopped, crashed repeatedly (rapid-fail protection), or the queue is full', '', ['Check the app pool state and the Windows event log.']);
  }
  if (/nginx/i.test(server) || /<center>nginx/i.test(body)) {
    const M = { 502: 'nginx could not get a valid response from the upstream application (down, crashed, or refused the connection)', 504: 'the upstream application did not respond within proxy_read_timeout (60 s by default)', 503: 'a limit_req / limit_conn rate limit or a maintenance rule rejected the request', 500: 'nginx hit an internal error (often a rewrite loop or permissions)' };
    if (M[st]) return gen('nginx (reverse proxy)', 'nginx: ' + M[st], '', ['Check the nginx error.log and the upstream application’s logs at this time.']);
  }
  if (/envoy/i.test(server) || /upstream connect error|no healthy upstream|upstream request timeout/i.test(body)) {
    const reason = /upstream request timeout/i.test(body) ? 'the upstream did not respond within the route timeout (15 s by default)' : /no healthy upstream/i.test(body) ? 'no healthy upstream instances are available' : /upstream connect error/i.test(body) ? 'it could not connect to the upstream (' + ((/reset reason: ([^\n<]+)/i.exec(body) || [])[1] || 'connection failure') + ')' : 'HTTP ' + st;
    return gen('Envoy / service mesh', 'Envoy: ' + reason, 'Envoy (Istio, Consul, Gloo, Contour, AWS App Mesh…) generated this response.', ['Check the destination service’s pods / health and the mesh route timeout.']);
  }
  if (/No server is available to handle this request|The server didn't respond in time/i.test(body)) return gen('HAProxy', 'HAProxy: ' + (st === 503 ? 'no backend server is available' : 'the backend did not respond in time (timeout server)'), '', ['Check HAProxy backend health and timeouts.']);
  if (/Apache/i.test(server) && /Proxy Error/i.test(body)) return gen('Apache (mod_proxy)', 'Apache mod_proxy could not get a valid response from the backend', '', ['Check the Apache error_log and the backend.']);
  if (/AkamaiGHost/i.test(server) || (/Reference\s*#/i.test(body) && st >= 500)) return gen('Akamai edge', 'Akamai could not get a valid response from the origin', '', ['Look up the reference number with Akamai and check the origin.']);
  if (/varnish/i.test(via) || /Guru Meditation|Backend fetch failed/i.test(body) || /^cache-/i.test(hdr(H, 'x-served-by'))) return gen('Varnish / Fastly cache', 'Varnish / Fastly: the backend fetch failed', '', ['Check origin health and the CDN’s backend timeouts.']);
  if (/Google Frontend|^gfe|^GSE$/i.test(server) || /google/i.test(via)) return gen('Google Cloud load balancer', 'Google Cloud load balancer: ' + (st === 504 ? 'the backend did not respond within the backend service timeout (30 s by default)' : st === 502 ? 'the backend is unhealthy or closed the connection' : 'HTTP ' + st), '', ['Check backend service health and timeout.']);
  if (/heroku/i.test(via) || /herokucdn|Application error[\s\S]{0,300}heroku/i.test(body)) return gen('Heroku router', 'Heroku router: ' + (st === 503 ? 'the app crashed (H10) or timed out after 30 s (H12)' : 'HTTP ' + st), '', ['Run heroku logs --tail and look for the H-code.']);
  const ve = hdr(H, 'x-vercel-error');
  if (ve) return gen('Vercel', 'Vercel: ' + ve, /TIMEOUT/.test(ve) ? 'The serverless function exceeded its maximum duration.' : '', ['Check the function logs in Vercel.']);
  if (/kong/i.test(server + ' ' + via)) return gen('Kong gateway', 'Kong: ' + (st === 503 ? 'no healthy upstream targets' : st === 504 ? 'the upstream timed out' : 'the upstream returned an error'), '', ['Check the Kong upstream / target health.']);
  const trace = stackTrace(body);
  if (trace) { ev.push(trace.lang + ' exception: ' + trace.summary); return R('application', 'The application crashed: ' + trace.summary, 'The response contains a ' + trace.lang + ' stack trace, so the error came from the application code.', ['Look at the application logs for this exception.']); }
  const err = errorInfo(e), msg = msgOf(err);
  if (msg) ev.push('Server said: "' + msg.slice(0, 200) + '"');
  return R('application', 'The application returned HTTP ' + st + (msg ? ': ' + msg.slice(0, 120) : ''), 'No proxy, gateway or CDN signature was found, so the error most likely came from the application itself (or a proxy that passes responses through unchanged).', ['Check the application logs at ' + fmtDate(entryTime(e)) + '.'], 'possible');
}
const KNOWN_TIMEOUTS = [[15000, 'Envoy / Istio default route timeout (15 s)'], [20000, 'Azure Application Gateway default request timeout (20 s)'], [29000, 'AWS API Gateway integration timeout (29 s)'], [30000, '30 s: Heroku router, Google Cloud load balancer, CloudFront origin timeout and many HTTP clients'], [60000, '60 s: nginx proxy_read_timeout, AWS ALB/ELB idle timeout and many proxies'], [100000, 'Cloudflare proxy read timeout (100 s)'], [230000, 'Azure App Service front-end timeout (230 s)']];
function diagServer() {
  const groups = new Map();
  for (const e of S.entries) {
    if (e.status < 500 || (e.auth && e.auth.event && !e.auth.event.normal)) continue;
    const w = whoAnswered(e), key = e.host + '|' + e.status + '|' + w.title;
    if (!groups.has(key)) groups.set(key, { w, list: [] });
    groups.get(key).list.push(e);
  }
  for (const { w, list } of groups.values()) {
    const e = list[0], n = list.length;
    const ev = [...w.ev];
    if (n > 1) ev.unshift(n + ' requests to ' + e.host + ' failed the same way.');
    const ra = hdr(resH(e), 'retry-after'); if (ra) ev.push('Retry-After: ' + ra);
    dAdd('server', 'error', e, e.status + ' from ' + w.layer + (n > 1 ? ' (' + n + ' requests)' : '') + ' — ' + e.host, [C(w.conf, 'server_' + w.layer.replace(/\W+/g, '_').toLowerCase(), w.title, w.detail, w.fixes)], ev, list, { layer: w.layer });
  }
  // Timeout clusters: failures that all took (almost) the same time point to a fixed timeout somewhere.
  const cands = S.entries.filter(e => (([408, 499, 502, 503, 504, 522, 524].includes(e.status)) || (e.status === 0 && /TIMED_OUT|EMPTY_RESPONSE|CONNECTION_CLOSED|CONNECTION_RESET|INCOMPLETE_CHUNKED/.test(netCode(e)))) && e.time >= 5000).sort((a, b) => a.time - b.time);
  const used = new Set();
  for (let i = 0; i < cands.length; i++) {
    if (used.has(cands[i])) continue;
    const cl = cands.filter(x => !used.has(x) && x.time >= cands[i].time && x.time <= cands[i].time * 1.05);
    const med = median(cl.map(x => x.time));
    const known = KNOWN_TIMEOUTS.find(([ms]) => Math.abs(med - ms) <= ms * 0.05);
    if (cl.length < 2 && !known) continue;
    cl.forEach(x => used.add(x));
    dAdd('server', 'error', cl[0], (cl.length > 1 ? cl.length + ' requests failed after ~' : 'Request failed after ') + fmtMs(med) + ' — a fixed timeout', [C(cl.length >= 3 || known ? 'high' : 'likely', 'timeout_cluster', 'A timeout of about ' + fmtMs(med) + ' in a proxy, gateway or client cut ' + (cl.length > 1 ? 'these requests' : 'this request') + ' off', (known ? 'This matches ' + known[1] + '. ' : '') + 'Requests that fail after the same duration are hitting a configured timeout, not a random network problem. The backend kept working (or was stuck) longer than the layer in front of it was willing to wait.', ['Find which layer has a ' + fmtMs(med) + ' timeout (see the gateway identified above) and make the backend respond faster, stream progress, or move the work to a background job.'])], cl.map(x => '#' + x.i + ' ' + x.method + ' ' + x.host + x.path.slice(0, 80) + ' → ' + (x.status || netCode(x)) + ' after ' + fmtMs(x.time)), cl);
  }
}

/* ---------- Rate limiting and retries ---------- */
function parseRetryAfter(v, e) { if (!v) return NaN; if (/^\d+$/.test(v.trim())) return +v * 1000; const d = Date.parse(v); return isNaN(d) ? NaN : d - entryTime(e); }
function diagRateLimit() {
  for (const e of S.entries) {
    const H = resH(e), ra = hdr(H, 'retry-after');
    const limited = e.status === 429 || (e.status === 503 && ra) || /^0$/.test(hdr(H, 'x-ratelimit-remaining') || hdr(H, 'ratelimit-remaining')) && e.status >= 400;
    if (!limited) continue;
    const ev = [], wait = parseRetryAfter(ra, e);
    for (const n of ['retry-after', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset', 'ratelimit-policy', 'ratelimit', 'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset', 'x-ms-ratelimit-remaining-subscription-reads', 'x-ms-ratelimit-remaining-subscription-writes']) { const v = hdr(H, n); if (v) ev.push(n + ': ' + v); }
    const hl = idx().byHost.get(e.host) || [], recent = hl.slice(lowerBound(hl, e.start - 60000, x => x.start), lowerBound(hl, e.start + 0.001, x => x.start));
    ev.push(recent.length + ' requests to ' + e.host + ' in the 60 s up to this one (' + recent.filter(x => x.u && x.u.pathname === e.u.pathname).length + ' to this path).');
    const msg = msgOf(errorInfo(e)); if (msg) ev.push('Server said: "' + msg.slice(0, 200) + '"');
    const causes = [C('high', 'rate_limited', 'The server is rate limiting this client' + (isFinite(wait) ? ' and asked it to wait ' + fmtDelta(wait) : ''), 'HTTP ' + e.status + ' means too many requests in a time window (per user, API key, IP or tenant).', ['Slow down: honor Retry-After, add exponential backoff with jitter, batch or cache requests, or ask for a higher quota.'])];
    const next = sameUrl(e).find(x => x !== e && x.start > e.start && x.method === e.method && noQuery(x.url) === noQuery(e.url));
    if (next && isFinite(wait) && next.start - e.start < wait - 500) causes.push(C('high', 'retry_too_early', 'The client retried after ' + fmtDelta(next.start - e.start) + ', before Retry-After (' + fmtDelta(wait) + ') had passed', 'Retrying early keeps the client throttled.', ['Wait at least the Retry-After time before retrying.']));
    dAdd('ratelimit', 'error', e, (e.status === 429 ? '429 Too Many Requests' : e.status + ' with Retry-After') + ' — ' + e.host, causes, ev, next ? [next] : []);
  }
  // Retry storms and tight polling loops
  // Repeats spread over separate page loads are reloads, not retries: count attempts within one page load.
  const docStarts = S.entries.filter(e => e.type === 'doc' && !isFail(e)).map(e => e.start).sort((a, b) => a - b);
  const loadOf = e => e.type === 'doc' ? -1 : e.pageref + '#' + lowerBound(docStarts, e.start + 1);
  const byKey = new Map();
  for (const e of S.entries) { const k = e.method + ' ' + noQuery(e.url); if (!byKey.has(k)) byKey.set(k, []); byKey.get(k).push(e); }
  for (const [k, all] of byKey) {
    if (all.length < 4 || /^(css|js|img|font|media)$/.test(all[0].type)) continue; // static assets are re-fetched by the browser, not retried by the app
    const loads = new Map(); for (const e of all) { const l = loadOf(e); if (!loads.has(l)) loads.set(l, []); loads.get(l).push(e); }
    const list = [...loads.values()].sort((a, b) => b.length - a.length)[0];
    if (list.length < 4) continue;
    list.sort((a, b) => a.start - b.start);
    const fails = list.filter(isFail);
    const gaps = list.slice(1).map((x, i) => x.start - list[i].start);
    if (fails.length >= 3 && list[list.length - 1].start - list[0].start <= 120000 && !(fails.every(x => x.status === 401 || x.status === 403))) {
      const g = gaps.filter((_, i) => isFail(list[i]));
      const growing = g.length >= 2 && g.every((x, i) => i === 0 || x >= g[i - 1] * 1.4);
      const constant = g.length >= 2 && Math.max(...g) <= Math.min(...g) * 1.3 + 50;
      dAdd('ratelimit', growing ? 'warn' : 'error', fails[0], 'Retry ' + (growing ? 'loop' : 'storm') + ': ' + k.slice(0, 120) + ' requested ' + list.length + ' times (' + fails.length + ' failed)', [C(growing ? 'likely' : 'high', growing ? 'retry_backoff' : 'retry_storm', growing ? 'The client retries with backoff, but the request keeps failing' : 'The client retries ' + (constant ? 'at a fixed interval (' + fmtMs(median(g)) + ')' : 'rapidly') + ' without backing off', 'Statuses: ' + list.map(x => x.status || netCode(x) || 'failed').join(', ') + '. Gaps between attempts: ' + gaps.map(fmtMs).join(', ') + '.', growing ? ['Fix the underlying failure; the retries themselves look reasonable.'] : ['Use exponential backoff with jitter and a retry limit; do not retry 4xx errors except 408/429.'])], [], list);
    } else if (list.length >= 20 && fails.length === 0 && median(gaps) < 2000) {
      dAdd('ratelimit', 'info', list[0], 'Tight polling: ' + k.slice(0, 120) + ' requested ' + list.length + ' times, every ' + fmtMs(median(gaps)), [C('possible', 'polling', 'The page polls this URL very often', 'This load can trigger rate limits and wastes battery and bandwidth.', ['Poll less often, use long polling, Server-Sent Events or WebSockets, or cache the result.'])], [], list);
    }
  }
}

/* ---------- Hidden failures and API errors ---------- */
const GRPC = { 1: 'CANCELLED', 2: 'UNKNOWN', 3: 'INVALID_ARGUMENT', 4: 'DEADLINE_EXCEEDED', 5: 'NOT_FOUND', 6: 'ALREADY_EXISTS', 7: 'PERMISSION_DENIED', 8: 'RESOURCE_EXHAUSTED', 9: 'FAILED_PRECONDITION', 10: 'ABORTED', 11: 'OUT_OF_RANGE', 12: 'UNIMPLEMENTED', 13: 'INTERNAL', 14: 'UNAVAILABLE', 15: 'DATA_LOSS', 16: 'UNAUTHENTICATED' };
const JSONRPC = { '-32700': 'Parse error: the server could not parse the JSON', '-32600': 'Invalid request object', '-32601': 'Method not found', '-32602': 'Invalid params', '-32603': 'Internal error' };
const API_STATUS = {
  400: ['Bad Request', 'The server rejected the request data (missing or invalid fields, bad JSON, wrong format).'],
  404: ['Not Found', 'The URL does not exist on the server.'],
  405: ['Method Not Allowed', 'The URL exists but does not accept this HTTP method.'],
  406: ['Not Acceptable', 'The server cannot produce a format listed in the Accept header.'],
  409: ['Conflict', 'The request conflicts with the current state (duplicate, or edited by someone else).'],
  410: ['Gone', 'The resource was removed permanently.'],
  412: ['Precondition Failed', 'An If-Match / If-Unmodified-Since condition failed: the resource changed since the client last read it.'],
  413: ['Content Too Large', 'The request body is larger than the server or a proxy allows.'],
  414: ['URI Too Long', 'The URL is too long (often a huge query string).'],
  415: ['Unsupported Media Type', 'The server does not accept the request body’s Content-Type.'],
  422: ['Unprocessable Content', 'The request was well-formed but failed validation.'],
  428: ['Precondition Required', 'The server requires a conditional request (If-Match).'],
  431: ['Request Header Fields Too Large', 'The request headers are too large, usually too many or too large cookies.'],
};
function fieldErrors(j) {
  const out = [];
  const push = (f, m) => { if (m != null && out.length < 8) out.push((f ? f + ': ' : '') + (typeof m === 'object' ? JSON.stringify(m) : String(m))); };
  if (!j || typeof j !== 'object') return out;
  const arr = Array.isArray(j.errors) ? j.errors : Array.isArray(j.detail) ? j.detail : Array.isArray(j['invalid-params']) ? j['invalid-params'] : Array.isArray(j.violations) ? j.violations : null;
  if (arr) for (const x of arr) { if (x && typeof x === 'object') push(x.field || x.path || x.param || x.name || x.propertyPath || (Array.isArray(x.loc) ? x.loc.join('.') : x.loc) || x.pointer || (x.source && (x.source.pointer || x.source.parameter)), x.message || x.msg || x.reason || x.detail || x.title || x.code); else push('', x); }
  else if (j.errors && typeof j.errors === 'object') for (const [k, v] of Object.entries(j.errors)) push(k, Array.isArray(v) ? v.join(', ') : v);
  return out;
}
function looksJson(t) { if (!t || !/^\s*[[{]/.test(t)) return false; try { JSON.parse(t); return true; } catch (_) { return false; } }
// Cookies that CDNs, bot managers and load balancers add at the edge: expected on cached responses.
const CDN_COOKIE = /^(__cf_bm|_cfuvid|__cfduid|cf_clearance|__cflb|__cfruid|AWSALB\w*|AWSELB\w*|incap_ses_\w+|visid_incap_\w+|nlbi_\w+|ak_bmsc|bm_sv|bm_sz|bm_mi|_abck|akavpau_\w+|TS01\w*|BIGipServer\w*|ROUTEID|SERVERID)$/;
function diagHidden() {
  const sameFail = new Map(); // one event per status + method + URL; repeats become related requests
  for (const e of S.entries) {
    if (!e.u) continue;
    const H = resH(e), RQ = reqH(e), st = e.status;
    const authed = e.auth && e.auth.event && !e.auth.event.normal;
    // JavaScript bugs visible in the URL
    const segs = e.u.pathname.split('/');
    const badSeg = segs.find(s => /^(undefined|null|NaN|%5Bobject%20Object%5D|\[object Object\])$/i.test(decodeURIComponentSafe(s)));
    const badQ = [...e.u.searchParams].find(([, v]) => /^(undefined|NaN|\[object Object\])$/.test(v));
    if (badSeg || badQ) dAdd('hidden', 'error', e, 'JavaScript bug: "' + (badSeg ? decodeURIComponentSafe(badSeg) : badQ[1]) + '" in the URL', [C('high', 'js_undefined_url', 'The URL was built from a missing or wrong value', (badSeg ? 'The path contains "' + decodeURIComponentSafe(badSeg) + '"' : 'The parameter ' + badQ[0] + '=' + badQ[1]) + ': the code concatenated a variable that was undefined, null or an object.' + (st >= 400 ? ' The server answered ' + st + '.' : ''), ['Find the code that builds this URL and check the variable before using it.'])], ['URL: ' + e.url]);
    // gRPC-web
    const gs = hdr(H, 'grpc-status');
    if (gs && gs !== '0') dAdd('hidden', 'error', e, 'gRPC error ' + (GRPC[gs] || gs) + (st === 200 ? ' inside an HTTP 200 response' : ''), [C('high', 'grpc_' + (GRPC[gs] || gs).toLowerCase(), 'gRPC status ' + gs + ' (' + (GRPC[gs] || 'unknown') + ')' + (hdr(H, 'grpc-message') ? ': ' + decodeURIComponentSafe(hdr(H, 'grpc-message')) : ''), 'gRPC reports errors in the grpc-status header, so HTTP still shows 200.', [])], ['grpc-status: ' + gs, hdr(H, 'grpc-message') ? 'grpc-message: ' + hdr(H, 'grpc-message') : '']);
    if (st >= 200 && st < 300) {
      const j = jsonOf(e), reqText = reqBodyText(e);
      const isGql = /graphql/i.test(e.url) || /"query"\s*:\s*"\s*(query|mutation|subscription|\{)/.test(reqText);
      if (j && isGql && Array.isArray(j.errors) && j.errors.length) {
        const codes = j.errors.map(x => x && x.extensions && (x.extensions.code || x.extensions.classification)).filter(Boolean);
        const apq = codes.includes('PERSISTED_QUERY_NOT_FOUND') || j.errors.some(x => /PersistedQueryNotFound/.test(x && x.message));
        const retried = apq && sameUrl(e).some(x => x.start > e.start && x.start - e.start < 5000 && noQuery(x.url) === noQuery(e.url) && /"query"/.test(reqBodyText(x)));
        const op = (/"operationName"\s*:\s*"([^"]+)"/.exec(reqText) || [])[1] || e.u.searchParams.get('operationName') || '';
        const msgs = j.errors.slice(0, 4).map(x => (x && x.message ? x.message : JSON.stringify(x)) + (x && x.path ? ' (at ' + [].concat(x.path).join('.') + ')' : ''));
        const hint = codes.includes('UNAUTHENTICATED') ? ' UNAUTHENTICATED means the token or session was missing or invalid.' : codes.includes('FORBIDDEN') ? ' FORBIDDEN means the user lacks permission for a field or operation.' : codes.includes('GRAPHQL_VALIDATION_FAILED') ? ' The query does not match the server’s schema (a client/server version mismatch?).' : codes.includes('BAD_USER_INPUT') ? ' An argument value was invalid.' : codes.includes('INTERNAL_SERVER_ERROR') ? ' A resolver threw an exception on the server.' : '';
        dAdd('hidden', apq && retried ? 'info' : 'error', e, 'GraphQL ' + (op ? 'operation ' + op + ' ' : '') + 'returned ' + j.errors.length + ' error' + (j.errors.length > 1 ? 's' : '') + ' inside an HTTP 200', [C('high', apq ? 'graphql_apq' : 'graphql_errors', apq ? 'Persisted query not found' + (retried ? '; the client then sent the full query (normal)' : '') : 'The GraphQL server reported errors' + (codes.length ? ' (' + [...new Set(codes)].join(', ') + ')' : ''), apq ? 'Automatic persisted queries first send only a hash; this miss is expected on the first run.' : 'GraphQL returns HTTP 200 even when operations fail, so these errors are easy to miss in the Network tab.' + hint + (j.data == null ? ' No data was returned.' : ' Partial data was returned.'), apq ? [] : ['Fix the errors listed in the evidence; check resolver logs on the server.'])], msgs.map(m => 'Error: ' + m), [], { normal: apq && retried });
      } else if (j && j.jsonrpc && j.error && typeof j.error === 'object') {
        dAdd('hidden', 'error', e, 'JSON-RPC error ' + j.error.code + ' inside an HTTP 200', [C('high', 'jsonrpc_error', (JSONRPC[String(j.error.code)] || 'JSON-RPC error ' + j.error.code) + (j.error.message ? ': ' + j.error.message : ''), 'JSON-RPC reports errors in the body with HTTP 200.', [])], j.error.data ? ['data: ' + JSON.stringify(j.error.data).slice(0, 300)] : []);
      } else if (j && !Array.isArray(j) && !isGql && (j.success === false || j.ok === false || /^(error|fail(ed|ure)?)$/i.test(String(j.status || j.result || '')) || (typeof j.error === 'string' && j.error && !j.data) || (j.error && typeof j.error === 'object' && !Array.isArray(j.error) && Object.keys(j.error).length && !j.data))) {
        const info = {}; collectErr(j, info, 0);
        dAdd('hidden', 'error', e, 'The API reported a failure inside an HTTP ' + st + ' response', [C('likely', 'body_failure', 'The response body says the operation failed' + (msgOf(info) ? ': ' + msgOf(info).slice(0, 160) : ''), 'The HTTP status is ' + st + ', so the failure does not show up as an error in the Network tab or in monitoring.', ['Have the API return a 4xx/5xx status for failures, and make the client check the body.'])], ['Body: ' + JSON.stringify(j).slice(0, 300)]);
      }
      // HTML where JSON was expected
      const accept = hdr(RQ, 'accept'), text = (e.type === 'xhr') ? (bodyText((e.raw.response || {}).content || {}) || '') : '';
      if (e.type === 'xhr' && !authed && /^\s*<(!doctype|html|head|body)/i.test(text) && (/json/i.test(accept) || /\/api\//i.test(e.url) || /json/i.test(hdr(RQ, 'content-type'))) && !(errorInfo(e).loginForm)) {
        const title = (/<title[^>]*>([^<]{1,120})</i.exec(text) || [])[1];
        dAdd('hidden', 'error', e, 'An API call received an HTML page instead of JSON', [C('high', 'html_not_json', 'The server returned an HTML page' + (title ? ' ("' + htmlDecode(title) + '")' : ''), 'The client expected data (' + (accept ? 'Accept: ' + accept : 'API URL') + ') but got HTML. This is the classic cause of "Unexpected token < in JSON". Usually a single-page-app server, CDN or proxy rewrites unknown routes to index.html, the API path or base URL is wrong, or a proxy/maintenance page answered.', ['Check the API base URL and the proxy / CDN routing rules for this path, and make unknown API routes return a JSON 404.'])], ['Content-Type: ' + (hdr(H, 'content-type') || e.mime)]);
      }
      if (e._jsonBad && /json/i.test(e.mime)) {
        const cl = +hdr(H, 'content-length'), size = ((e.raw.response || {}).content || {}).size || 0;
        dAdd('hidden', 'error', e, 'The response claims to be JSON but cannot be parsed', [C(cl && size && size < cl ? 'high' : 'likely', 'bad_json', cl && size && size < cl ? 'The JSON was truncated (' + fmtBytes(size) + ' of ' + fmtBytes(cl) + ')' : 'The JSON body is malformed', 'Clients will fail to parse it. Causes: truncated output (crash or timeout while writing), debugging output or a warning printed before the JSON, or a byte-order mark.', ['Look at the start and end of the body in the Response tab.'])], []);
      }
    }
    // API client errors
    if (API_STATUS[st] && !authed && (e.type === 'xhr' || /json|xml/i.test(e.mime) || st !== 404) && !(st === 404 && /favicon|apple-touch-icon|robots\.txt|\.map$/i.test(e.url))) {
      const [name, base] = API_STATUS[st], err = errorInfo(e), j = jsonOf(e), msg = msgOf(err), causes = [], ev = [];
      const fe = fieldErrors(j);
      if (fe.length) ev.push(...fe.map(x => 'Field error: ' + x));
      if (j && (j.type || j.title) && /problem\+json/i.test(e.mime)) ev.push('Problem details: ' + [j.title, j.detail, j.type].filter(Boolean).join(' — '));
      if (msg) ev.push('Server said: "' + msg.slice(0, 240) + '"');
      const rct = hdr(RQ, 'content-type'), rb = reqBodyText(e);
      if (rb && looksJson(rb) && rct && !/json/i.test(rct)) causes.push(C('high', 'req_json_wrong_type', 'The body is JSON but was sent as Content-Type: ' + rct, 'Servers parse the body according to Content-Type, so they see garbage or nothing. fetch() sends strings as text/plain unless you set the header.', ['Send Content-Type: application/json with JSON bodies.']));
      if (rb && /json/i.test(rct) && /^\s*[[{]/.test(rb) && !looksJson(rb)) causes.push(C('high', 'req_bad_json', 'The request body is not valid JSON', 'Content-Type says JSON, but the body does not parse.', ['Build the body with JSON.stringify().']));
      if (rb && /json/i.test(rct) && !/^\s*[[{"]/.test(rb) && /^[\w.%-]+=/.test(rb)) causes.push(C('high', 'req_form_as_json', 'A form-encoded body was sent as Content-Type: application/json', '', ['Send JSON.stringify(data), or use Content-Type: application/x-www-form-urlencoded.']));
      if (rb && /^\[object Object\]$/.test(rb.trim())) causes.push(C('high', 'req_object_object', 'The request body is literally "[object Object]"', 'An object was sent without JSON.stringify().', ['Serialize the body with JSON.stringify().']));
      if (st === 415) causes.push(C('high', 'unsupported_type', 'The server does not accept Content-Type: ' + (rct || '(none)'), base, ['Send the body in a format the API documents (usually application/json).']));
      if (st === 413) causes.push(C('high', 'too_large', 'The request body (' + fmtBytes(((e.raw.request || {}).bodySize > 0 ? e.raw.request.bodySize : rb.length)) + ') is larger than allowed', base + ' Typical limits: nginx client_max_body_size 1 MB, many gateways 6–10 MB.', ['Raise the body-size limit on every layer (proxy, gateway, app), or upload large files directly to storage.']));
      if (st === 405) causes.push(C('high', 'method_not_allowed', e.method + ' is not allowed here' + (hdr(H, 'allow') ? '; allowed: ' + hdr(H, 'allow') : ''), base, ['Use one of the allowed methods, or check the route definition.']));
      if (st === 404 && e.u) {
        const hints = [];
        if (/\/\//.test(e.u.pathname)) hints.push('the path contains "//" (a base URL with a trailing slash joined to a path with a leading slash)');
        if (/^(localhost|127\.|0\.0\.0\.0)/.test(e.u.hostname)) hints.push('the request went to ' + e.u.host + ' (a development URL left in the configuration?)');
        if (/\/api\/api\//i.test(e.u.pathname)) hints.push('"/api" appears twice in the path');
        causes.push(C(hints.length ? 'high' : 'likely', 'api_not_found', 'The API endpoint does not exist: ' + e.method + ' ' + e.u.pathname, hints.length ? 'Likely because ' + hints.join('; ') + '.' : 'A wrong base URL or path, a missing version prefix, a route not deployed yet, or a resource ID that does not exist.', ['Compare the URL with the API documentation and the server’s route list.']));
      }
      if (/Missing Authentication Token/.test(msg) && hdr(H, 'x-amzn-errortype')) causes.push(C('high', 'apigw_no_route', 'API Gateway: no route matches this method and path', '"Missing Authentication Token" from AWS API Gateway usually means the resource or method does not exist (or the stage is missing from the URL), not an authentication problem.', ['Check the URL, stage name and HTTP method against the API definition.']));
      if (st === 412) causes.push(C('high', 'precondition', 'The resource changed since it was read', 'If-Match: ' + (hdr(RQ, 'if-match') || '(none)') + '. ' + base, ['Re-read the resource to get the current ETag and retry.']));
      if (st === 431) causes.push(C('high', 'headers_too_large', 'The request headers are too large', 'Cookie header size: ' + fmtBytes(hdr(RQ, 'cookie').length) + '. ' + base, ['Delete unneeded cookies for this domain.']));
      if (!causes.length) causes.push(C(fe.length || msg ? 'likely' : 'possible', 'http_' + st, name + (msg ? ': ' + msg.slice(0, 160) : ''), base, fe.length ? ['Fix the fields listed in the evidence.'] : []));
      const fk = st + ' ' + e.method + ' ' + noQuery(e.url), prev = sameFail.get(fk);
      if (prev) { prev.related.push(e); (e.diag || (e.diag = [])).push(prev); continue; }
      sameFail.set(fk, dAdd('hidden', st >= 500 ? 'error' : st === 404 && e.type !== 'xhr' ? 'warn' : 'error', e, st + ' ' + name + ' — ' + e.method + ' ' + e.host + e.u.pathname.slice(0, 80), causes, ev));
    }
  }
  for (const v of sameFail.values()) if (v.related.length) v.headline += ' (' + (v.related.length + 1) + ' requests)';
}
function decodeURIComponentSafe(s) { try { return decodeURIComponent(s); } catch (_) { return s; } }

/* ---------- Redirects ---------- */
function diagRedirect() {
  const seenLoop = new Set();
  for (const e of S.entries) {
    if (e.redirectFrom || !e.redirectTo || seenLoop.has(e)) continue;
    const chain = [e]; let c = e;
    while (c.redirectTo && chain.length < 40) { c = c.redirectTo; chain.push(c); if (chain.filter(x => x.url === c.url).length > 1) break; }
    const urls = chain.map(x => x.url), dup = urls.find((u, i) => urls.indexOf(u) !== i);
    if (dup || chain.length >= 12) {
      chain.forEach(x => seenLoop.add(x));
      for (let x = chain[chain.length - 1], n = 0; x && n < 100; x = x.redirectTo, n++) seenLoop.add(x);
      const pairs = chain.slice(1).map((x, i) => [chain[i], x]), pat = [];
      if (pairs.some(([a, b]) => a.u && b.u && a.u.protocol !== b.u.protocol && a.u.host === b.u.host)) pat.push(C('high', 'loop_scheme', 'The redirects flip between http and https', 'Typical when TLS ends at a load balancer or CDN: the app sees plain HTTP, redirects to https, and the proxy forwards the https request as http again. The app must trust X-Forwarded-Proto (or the CDN must use HTTPS to the origin, e.g. Cloudflare "Full" instead of "Flexible").', ['Configure the app to honor X-Forwarded-Proto from the proxy, or make the proxy talk HTTPS to the origin.']));
      if (pairs.some(([a, b]) => a.u && b.u && a.u.host !== b.u.host && a.u.host.replace(/^www\./, '') === b.u.host.replace(/^www\./, ''))) pat.push(C('high', 'loop_www', 'The redirects flip between www and non-www', 'Two layers (DNS/CDN rule and app setting) disagree about the canonical host.', ['Pick one canonical host and redirect in one place only.']));
      if (pairs.some(([a, b]) => a.u && b.u && a.u.host === b.u.host && a.u.pathname.replace(/\/$/, '') === b.u.pathname.replace(/\/$/, '') && a.u.pathname !== b.u.pathname)) pat.push(C('high', 'loop_slash', 'The redirects flip between a trailing slash and none', 'Server/framework and proxy disagree about trailing slashes.', ['Make the trailing-slash rule consistent in one layer.']));
      if (chain.some(x => x.u && LOGIN_RE.test(x.u.pathname))) {
        pat.push(C('likely', 'loop_login', 'The app and its sign-in page send the user back and forth', 'Sign-in succeeds, but the app does not see the session afterwards, so it starts sign-in again.', ['Check that the session cookie set during sign-in is stored and sent back (see below).']));
        for (const x of chain) for (const sc of setCookiesOf(x)) {
          const later = chain.find(y => y.start > x.start && cookieApplies(sc, y));
          if (later && !requestCookies(later).has(sc.name)) { const why = cookieWhyNotSent(sc, later); pat.push(C(why.conf, 'loop_cookie_' + why.id, 'Cookie "' + sc.name + '" set by #' + x.i + ' was not sent by #' + later.i + ': ' + why.short, why.text, why.fixes)); }
        }
      }
      if (!pat.length) pat.push(C('likely', 'loop_generic', 'The server keeps redirecting to URLs it has already visited', 'Compare the URLs in the evidence to see which rule fires repeatedly.', []));
      dAdd('redirect', 'error', e, 'Redirect loop' + (dup ? '' : ' (' + chain.length + ' hops)') + ' starting at ' + e.host, pat, chain.map(x => '#' + x.i + ' ' + (x.status || 'failed') + ' ' + x.url.slice(0, 160)), chain);
    }
  }
  for (const e of S.entries) {
    const t = e.redirectTarget ? (() => { try { return new URL(e.redirectTarget); } catch (_) { return null; } })() : null;
    if (t && e.u && e.u.protocol === 'https:' && t.protocol === 'http:' && !/^(localhost|127\.)/.test(t.hostname) && !seenLoop.has(e)) dAdd('redirect', 'error', e, 'HTTPS downgraded to HTTP by a redirect', [C('high', 'downgrade', 'An HTTPS request was redirected to plain HTTP', e.url + ' → ' + e.redirectTarget + '. The traffic after the redirect is unencrypted, Secure cookies are not sent, and browsers may block it as mixed content. This often comes from an app behind a TLS-terminating proxy building absolute URLs from the HTTP request it sees.', ['Generate redirects with https (trust X-Forwarded-Proto), and enable HSTS.'])], []);
    if (e.method === 'POST' && e.redirectTo && [301, 302, 303].includes(e.status) && e.redirectTo.method === 'GET') {
      if (e.status === 303) continue;
      dAdd('redirect', 'warn', e, 'A POST was redirected with ' + e.status + ' and became a GET', [C('likely', 'post_redirect', 'The request body was dropped by the redirect', 'Browsers turn POST into GET when following 301/302 redirects, so the data never reaches ' + e.redirectTo.url.slice(0, 120) + '. Common causes: posting to http:// or a URL without a trailing slash, which the server redirects.', ['POST directly to the final URL, or redirect with 307/308 which keep the method and body.'])], [], [e.redirectTo]);
    }
  }
  for (const e of S.entries) if (netCode(e) === 'TOO_MANY_REDIRECTS' && !(e.diag || []).some(v => v.cat === 'redirect')) dAdd('redirect', 'error', e, 'The browser gave up: too many redirects', [C('high', 'too_many_redirects', 'Redirect loop (net::ERR_TOO_MANY_REDIRECTS)', 'The individual redirects may not be in the HAR. Typical causes are http/https or www/non-www rules that fight each other, or a sign-in loop because a cookie is not kept.', ['Open the URL with curl -IL to see the redirect chain.'])], []);
}

/* ---------- WebSockets and streaming ---------- */
function diagRealtime() {
  const wsList = S.entries.filter(e => e.type === 'ws' || /^wss?:/i.test(e.url) || /websocket/i.test(hdr(reqH(e), 'upgrade')));
  const end = S.entries.reduce((a, x) => Math.max(a, x.start + x.time), 0);
  const wsFailSeen = new Map();
  for (const e of wsList) {
    const st = e.status, H = resH(e), RQ = reqH(e);
    if (st !== 101) { const k = noQuery(e.url) + '|' + st; const prev = wsFailSeen.get(k); if (prev) { prev.related.push(e); (e.diag || (e.diag = [])).push(prev); prev.headline = prev.headline.replace(/( \(\d+ attempts\))?$/, ' (' + (prev.related.length + 1) + ' attempts)'); continue; } }
    if (st === 101) {
      const msgs = e.raw._webSocketMessages || [];
      if (msgs.length) {
        const t = msgs.map(m => m.time * 1000).sort((a, b) => a - b), last = t[t.length - 1], closedAt = (S.base || 0) + e.start + e.time;
        const idle = closedAt - last, received = msgs.filter(m => m.type === 'receive').length;
        if (received === 0) dAdd('realtime', 'warn', e, 'WebSocket open but the server never sent a message', [C('likely', 'ws_silent', 'No messages were received on this WebSocket', msgs.length + ' message(s) sent, none received: the server is not subscribed/authorized for this client, or the client never sent the expected handshake message.', [])], []);
        if (e.start + e.time < end - 1000 && idle > 20000) {
          const known = KNOWN_TIMEOUTS.find(([ms]) => Math.abs(idle - ms) <= ms * 0.1);
          dAdd('realtime', 'warn', e, 'WebSocket closed after ' + fmtDelta(idle) + ' without traffic', [C(known ? 'high' : 'likely', 'ws_idle', 'An idle timeout closed the WebSocket', 'The last message was ' + fmtDelta(idle) + ' before the connection ended' + (known ? ', matching ' + known[1] : '') + '. Proxies and load balancers close connections that are quiet for too long.', ['Send a ping / heartbeat message more often than the shortest idle timeout (for example every 25 s), and reconnect automatically.'])], []);
        }
      }
    } else {
      const M = {
        0: ['The WebSocket connection failed before an HTTP response', 'See the network error (if any). Corporate proxies that do not support WebSockets, and TLS inspection, are common causes.'],
        200: ['The server answered the upgrade with a normal 200 response', 'Something in front of the app (proxy, CDN, or the app’s router) does not support WebSockets on this path, or stripped the Upgrade / Connection headers.'],
        400: ['The WebSocket handshake was rejected as malformed (400)', 'Usually a proxy stripped the Upgrade / Connection headers, the Sec-WebSocket-Version is unsupported, or the server expected a different path or query (for example a missing token).'],
        401: ['The WebSocket handshake needs authentication (401)', 'Browsers cannot set an Authorization header on WebSockets; servers usually expect a cookie, a token in the query string, or a subprotocol.'],
        403: ['The server refused the WebSocket (403)', 'Most often the server’s Origin check rejects ' + (hdr(RQ, 'origin') || 'this origin') + ', or authentication failed.'],
        404: ['The WebSocket path does not exist (404)', 'Wrong URL, or the WebSocket endpoint is not routed through the proxy.'],
        426: ['The server requires a different protocol version (426)', ''],
        502: ['A proxy could not upgrade the connection (502)', 'The proxy does not forward WebSockets. For nginx you need proxy_http_version 1.1 and proxy_set_header Upgrade $http_upgrade / Connection "upgrade".'],
        503: ['The WebSocket backend is unavailable (503)', ''], 504: ['The WebSocket upgrade timed out at a proxy (504)', ''],
      };
      const m = M[st] || ['The WebSocket handshake failed with HTTP ' + st, ''];
      wsFailSeen.set(noQuery(e.url) + '|' + st, null);
      const wv = dAdd('realtime', 'error', e, 'WebSocket connection failed — ' + e.host, [C('high', 'ws_' + st, m[0], m[1], ['Check that every proxy / load balancer / CDN between client and server supports and forwards WebSocket upgrades.'])], [e.error ? 'Browser error: ' + e.error : '', hdr(RQ, 'sec-websocket-protocol') ? 'Requested subprotocol: ' + hdr(RQ, 'sec-websocket-protocol') : '', hdr(H, 'server') ? 'server: ' + hdr(H, 'server') : '']);
      wsFailSeen.set(noQuery(e.url) + '|' + st, wv);
    }
  }
  const byUrl = new Map();
  for (const e of wsList) { const k = noQuery(e.url); if (!byUrl.has(k)) byUrl.set(k, []); byUrl.get(k).push(e); }
  const sse = S.entries.filter(e => /text\/event-stream/i.test(e.mime + ' ' + hdr(reqH(e), 'accept')));
  for (const e of sse) {
    const k = 'sse ' + noQuery(e.url); if (!byUrl.has(k)) byUrl.set(k, []); byUrl.get(k).push(e);
    if (e.status !== 200 && e.status !== 0) dAdd('realtime', 'error', e, 'Server-Sent Events stream failed with HTTP ' + e.status, [C('high', 'sse_status', 'The event stream returned ' + e.status, 'EventSource only accepts 200 with Content-Type: text/event-stream; anything else makes it retry and eventually fail.', [])], []);
    else if (e.status === 200) {
      const H = resH(e), causes = [];
      if (hdr(H, 'content-encoding')) causes.push(C('likely', 'sse_compressed', 'The event stream is compressed (' + hdr(H, 'content-encoding') + ')', 'Compression buffers output, so events can arrive late or in bursts.', ['Disable compression for text/event-stream.']));
      if (/nginx/i.test(hdr(H, 'server')) && !/^no$/i.test(hdr(H, 'x-accel-buffering'))) causes.push(C('possible', 'sse_buffering', 'nginx may be buffering the event stream', 'Without X-Accel-Buffering: no (or proxy_buffering off), nginx holds events until its buffer fills.', ['Send X-Accel-Buffering: no from the app, or set proxy_buffering off for this location.']));
      if (causes.length) dAdd('realtime', 'warn', e, 'Server-Sent Events may be delayed by buffering', causes, []);
    }
  }
  for (const [k, list] of byUrl) {
    if (list.length < 3) continue;
    list.sort((a, b) => a.start - b.start);
    const gaps = list.slice(1).map((x, i) => x.start - list[i].start);
    dAdd('realtime', 'warn', list[0], (k.startsWith('sse ') ? 'EventSource' : 'WebSocket') + ' reconnected ' + list.length + ' times — ' + (list[0].host), [C('likely', 'reconnect_loop', 'The connection keeps dropping and reconnecting', 'Connections were opened ' + list.length + ' times; gaps: ' + gaps.map(fmtMs).join(', ') + '. Statuses: ' + list.map(x => x.status || 'failed').join(', ') + '.', ['Look at why each connection ends (statuses above, idle timeouts, server restarts) and use backoff between reconnects.'])], [], list);
  }
}

/* ---------- Hangs and incomplete requests ---------- */
function diagHang() {
  const pending = S.entries.filter(isPending);
  if (pending.length) dAdd('hang', 'warn', pending[0], pending.length + ' request' + (pending.length > 1 ? 's' : '') + ' never finished', [C('likely', 'pending', 'No response had arrived when the HAR was saved', 'The browser was still waiting. If the user reported a hang, start here: the server or a proxy never answered, or these are long-polling / streaming requests that are expected to stay open.', ['Check the server for these requests at ' + fmtDate(entryTime(pending[0])) + '; look for blocked threads, locks or slow dependencies.'])], pending.map(x => '#' + x.i + ' ' + x.method + ' ' + x.url.slice(0, 160) + ' (started +' + fmtMs(x.start) + ')'), pending);
  for (const e of S.entries) {
    if (!isOk(e) || e.type === 'ws' || /event-stream/i.test(e.mime) || /poll|subscribe|stream|events|notifications\/wait|\/live/i.test(e.url)) continue;
    const t = e.timings;
    if (e.time > 30000) {
      const phases = [['queued', t.blocked], ['DNS', t.dns], ['connect', t.connect], ['waiting for the server', t.wait], ['downloading', t.receive]].sort((a, b) => b[1] - a[1]);
      dAdd('hang', 'warn', e, 'Very slow request: ' + fmtMs(e.time) + ' — ' + e.method + ' ' + e.host + e.path.slice(0, 80), [C('likely', 'very_slow', 'Most of the time (' + fmtMs(phases[0][1]) + ') was spent ' + phases[0][0], phases[0][0] === 'waiting for the server' ? 'The server took this long to start answering: slow queries, locks, or a slow downstream call.' : phases[0][0] === 'downloading' ? 'The response arrived slowly: a large body, a slow network, or a server streaming slowly.' : 'The browser could not even start the request quickly.', [])], []);
    } else if (t.receive > 5000) {
      const kbps = e.contentSize / (t.receive / 1000) / 1024;
      if (kbps < 100) dAdd('hang', 'warn', e, 'Slow download: ' + fmtBytes(e.contentSize) + ' in ' + fmtMs(t.receive) + ' (' + kbps.toFixed(1) + ' KB/s)', [C('likely', 'slow_download', 'The response trickled in at ' + kbps.toFixed(1) + ' KB/s', 'Either the network is slow or congested, or the server generates/streams the body slowly.', ['Compare with other downloads in this HAR: if all are slow it is the network, if only this one it is the server.'])], []);
    }
  }
  const sorted = S.entries.filter(e => !isPending(e)).sort((a, b) => a.start - b.start), gaps = [];
  let busyUntil = sorted.length ? sorted[0].start + sorted[0].time : 0;
  for (let i = 1; i < sorted.length; i++) {
    const g = sorted[i].start - busyUntil;
    if (g > 5000) gaps.push({ g, before: sorted[i - 1], after: sorted[i] });
    busyUntil = Math.max(busyUntil, sorted[i].start + sorted[i].time);
  }
  gaps.sort((a, b) => b.g - a.g).slice(0, 3).forEach(x => dAdd('hang', 'info', x.after, 'Nothing happened on the network for ' + fmtDelta(x.g), [C('possible', 'quiet_gap', 'No requests between #' + x.before.i + ' and #' + x.after.i, 'Either the user was idle, or the page was busy in JavaScript, waiting on a timer, or waiting for something that is not in this HAR (a popup, another tab, a service worker). If the user reported a freeze at this point, profile the page with the Performance panel.', [])], [], [x.before]));
}

/* ---------- Caching and CDN ---------- */
function cacheStatus(e) {
  const H = resH(e), v = (hdr(H, 'cf-cache-status') || hdr(H, 'x-cache') || hdr(H, 'x-cache-status') || hdr(H, 'x-proxy-cache') || hdr(H, 'cdn-cache') || hdr(H, 'x-vercel-cache') || hdr(H, 'x-nf-cache-status')).toUpperCase();
  if (!v) return null;
  if (/HIT/.test(v)) return 'HIT';
  if (/BYPASS|DYNAMIC|PASS|UNCACHEABLE|ERROR|NONE/.test(v)) return 'BYPASS';
  if (/MISS|EXPIRED|REVALIDATED|STALE|UPDATING/.test(v)) return 'MISS';
  return null;
}
function parseCC(v) {
  const o = {}; v = String(v || '').toLowerCase();
  for (const part of v.split(',')) { const [k, val] = part.trim().split('='); if (k) o[k] = val == null ? true : val.replace(/"/g, ''); }
  return { maxAge: o['max-age'] != null ? +o['max-age'] : NaN, sMaxAge: o['s-maxage'] != null ? +o['s-maxage'] : NaN, noStore: !!o['no-store'], noCache: !!o['no-cache'], private: !!o.private, public: !!o.public, immutable: !!o.immutable, raw: v };
}
const FINGERPRINT = /[.\-_](?=[0-9a-f]*\d)[0-9a-f]{4,}\.(m?js|css|woff2?|ttf|png|jpe?g|gif|svg|webp|avif)$|[.\-_][A-Za-z0-9_-]{8,}\.(m?js|css)$/;
function diagCache() {
  const stat = S.entries.filter(e => e.status === 200 && !e.fromCache && ['js', 'css', 'img', 'font'].includes(e.type) && e.u);
  const byHost = new Map();
  for (const e of stat) { if (!byHost.has(e.host)) byHost.set(e.host, []); byHost.get(e.host).push(e); }
  for (const [host, list] of byHost) {
    const st = list.map(cacheStatus).filter(Boolean);
    if (list.length >= 4 && st.length >= list.length * 0.6) {
      const hits = st.filter(x => x === 'HIT').length;
      if (hits / st.length < 0.3) {
        const reasons = new Map(), bump = (k, e) => { if (!reasons.has(k)) reasons.set(k, []); reasons.get(k).push(e); };
        for (const e of list) {
          const H = resH(e), cc = parseCC(hdr(H, 'cache-control'));
          if (hdrAll(H, 'set-cookie').length) bump('setcookie', e);
          if (cc.noStore || cc.private) bump('private', e);
          else if (cc.noCache || cc.maxAge === 0 || cc.sMaxAge === 0) bump('nocache', e);
          if (/(^|,)\s*(\*|cookie|user-agent)\s*(,|$)/i.test(hdr(H, 'vary'))) bump('vary', e);
          if ([...e.u.searchParams.values()].some(v => /^\d{10,13}$/.test(v))) bump('buster', e);
        }
        const R = { setcookie: ['Responses set cookies', 'Most CDNs refuse to cache responses with Set-Cookie.', 'Do not set cookies on static assets (serve them from a cookieless path or domain).'], private: ['Cache-Control is private or no-store', 'Shared caches must not store these.', 'Send Cache-Control: public, max-age=… for static assets.'], nocache: ['Cache-Control is no-cache or max-age=0', 'The CDN must revalidate every time.', 'Give static assets a real max-age.'], vary: ['Vary: Cookie, User-Agent or *', 'This splits or disables the cache.', 'Only vary on headers that really change the asset (usually Accept-Encoding).'], buster: ['URLs carry a timestamp-like query value', 'Every request has a new URL, so nothing is reused.', 'Use a content hash in the file name instead of a timestamp.'] };
        const causes = [...reasons].sort((a, b) => b[1].length - a[1].length).map(([k, es]) => C('high', 'cdn_' + k, R[k][0] + ' (' + es.length + ' of ' + list.length + ')', R[k][1], [R[k][2]]));
        if (!causes.length) causes.push(C('possible', 'cdn_cold', 'The CDN cache was cold', 'Nothing in the responses prevents caching. These may simply be the first requests after a deploy or purge, or the assets are rarely requested at this edge location.', ['Reload and capture again: the second load should show HITs.']));
        dAdd('cache', 'warn', list[0], 'The CDN served only ' + hits + ' of ' + st.length + ' static assets from cache — ' + host, causes, ['Cache status: ' + ['HIT', 'MISS', 'BYPASS'].map(k => k + ' ' + st.filter(x => x === k).length).join(', ')], list);
      }
    }
    const shortHashed = list.filter(e => FINGERPRINT.test(e.u.pathname) && (() => { const cc = parseCC(hdr(resH(e), 'cache-control')); return cc.noCache || cc.noStore || !(cc.maxAge >= 604800); })());
    if (shortHashed.length >= 3) dAdd('cache', 'info', shortHashed[0], shortHashed.length + ' fingerprinted assets on ' + host + ' are cached for less than a week', [C('possible', 'hashed_short', 'Files with a content hash in their name never change, so they can be cached for a year', 'Example: ' + shortHashed[0].u.pathname.slice(0, 100) + ' has Cache-Control: ' + (hdr(resH(shortHashed[0]), 'cache-control') || '(none)') + '.', ['Serve fingerprinted files with Cache-Control: public, max-age=31536000, immutable.'])], [], shortHashed);
    const longPlain = list.filter(e => ['js', 'css'].includes(e.type) && !FINGERPRINT.test(e.u.pathname) && !e.u.search && (() => { const cc = parseCC(hdr(resH(e), 'cache-control')); return cc.immutable || cc.maxAge >= 2592000; })());
    if (longPlain.length) dAdd('cache', 'warn', longPlain[0], longPlain.length + ' script/style file' + (longPlain.length > 1 ? 's' : '') + ' without a version in the name cached for 30+ days — ' + host, [C('likely', 'stale_assets', 'Users may keep old JavaScript or CSS after a deploy', 'These URLs do not change between releases but are cached for a long time, so browsers keep using the old version (a common cause of "it works after a hard refresh").', ['Add a content hash to the file names, or shorten max-age for unversioned files.'])], longPlain.map(x => x.u.pathname + ' — ' + hdr(resH(x), 'cache-control')), longPlain);
  }
  for (const e of S.entries.filter(x => x.type === 'doc' && x.status === 200)) {
    const H = resH(e), cc = parseCC(hdr(H, 'cache-control')), age = +hdr(H, 'age') || 0;
    if (!cc.noCache && !cc.noStore && !cc.private && (cc.immutable || cc.maxAge > 600 || cc.sMaxAge > 600)) dAdd('cache', 'warn', e, 'The HTML page is cacheable for ' + fmtDelta((cc.sMaxAge > cc.maxAge ? cc.sMaxAge : cc.maxAge || 0) * 1000) + ' — ' + e.host, [C('likely', 'html_cached', 'Visitors can get a stale page after a deploy', 'Cache-Control: ' + cc.raw + (age ? '; this copy is ' + fmtDelta(age * 1000) + ' old (Age)' : '') + '. Old HTML may also reference script files that no longer exist.', ['Serve HTML with Cache-Control: no-cache (or a short max-age) and cache the hashed assets instead.'])], []);
  }
  for (const e of S.entries) {
    const H = resH(e), sc = hdrAll(H, 'set-cookie').filter(x => !/bytes were stripped/i.test(x) && !CDN_COOKIE.test(x.split('=')[0].trim()));
    if (!sc.length) continue;
    const cs = cacheStatus(e), age = +hdr(H, 'age') || 0, cc = parseCC(hdr(H, 'cache-control'));
    if ((cs === 'HIT' || age > 0) && !cc.private && !cc.noStore) dAdd('cache', 'error', e, 'A response with Set-Cookie was served from a shared cache', [C('high', 'cached_cookie', 'Other visitors may receive this user’s cookie (' + sc.map(x => x.split('=')[0]).join(', ') + ')', 'The response came from a CDN or proxy cache (' + (cs ? 'cache status ' + cs : '') + (age ? ' Age: ' + age : '') + ') and still carries Set-Cookie. If the cookie is a session, users can be logged in as each other.', ['Mark responses that set cookies as Cache-Control: private, or strip Set-Cookie at the CDN for cacheable content.'])], ['Cache-Control: ' + (cc.raw || '(none)')]);
  }
  const reval = S.entries.filter(e => e.status === 304);
  if (reval.length >= 10) dAdd('cache', 'info', reval[0], reval.length + ' requests were revalidated (304 Not Modified)', [C('possible', 'revalidation', 'The browser checks with the server instead of using its cache', 'Each 304 is a full round trip with no content. The resources are probably served with no-cache, max-age=0, or no Cache-Control.', ['Give static assets a max-age (with fingerprinted names) so the browser can skip the round trip.'])], [], reval);
  const sw = S.entries.filter(e => (e.raw.response || {})._fetchedViaServiceWorker || e.raw._fetchedViaServiceWorker || /serviceworker/i.test(String(e.raw._fromCache || '')));
  if (sw.length) dAdd('cache', 'info', sw[0], sw.length + ' response' + (sw.length > 1 ? 's were' : ' was') + ' served by a service worker', [C('possible', 'service_worker', 'A service worker answered these requests', 'Service workers can serve stale content or hide network errors. If users see old content, update or unregister the service worker (DevTools → Application → Service workers).', [])], [], sw);
}

/* ---------- Page-load performance ---------- */
function initiatorParent(e, byUrl) {
  const init = e.raw._initiator; if (!init) return null;
  const url = init.url || (init.stack && init.stack.callFrames && init.stack.callFrames[0] && init.stack.callFrames[0].url) || (init.stack && init.stack.parent && init.stack.parent.callFrames && init.stack.parent.callFrames[0] && init.stack.parent.callFrames[0].url);
  if (!url) return null;
  const c = (byUrl.get(url) || []).filter(x => x.start <= e.start && x !== e);
  return c.length ? c[c.length - 1] : null;
}
function diagPerf() {
  const docs = S.entries.filter(e => e.type === 'doc' && e.status === 200);
  const page = S.pages[0], doc = (page && docs.find(d => d.url === page.title)) || docs[0];
  if (!doc) return;
  const t = doc.timings;
  let chainStart = doc, redirectCost = 0;
  while (chainStart.redirectFrom) { chainStart = chainStart.redirectFrom; redirectCost += chainStart.time; }
  if (t.wait > 800 || redirectCost > 500) {
    const causes = [];
    if (t.wait > 800) causes.push(C(t.wait > 1800 ? 'high' : 'likely', 'doc_ttfb', 'The server took ' + fmtMs(t.wait) + ' to start sending the page', 'Nothing can render until the HTML arrives. Typical causes: server-side rendering doing slow database or API calls, no page caching, or a cold start.', ['Cache the page (CDN or server), speed up the slow data calls, or stream the HTML early.']));
    if (redirectCost > 500) causes.push(C('likely', 'doc_redirects', 'Redirects before the page cost ' + fmtMs(redirectCost), 'Each redirect is a full round trip before the real page can load.', ['Link to the final URL directly.']));
    dAdd('perf', 'warn', doc, 'Slow start: the page HTML arrived after ' + fmtMs(doc.start - chainStart.start + t.blocked + t.dns + t.connect + t.send + t.wait), causes, ['DNS ' + fmtMs(t.dns) + ', connect ' + fmtMs(t.tcp) + ', TLS ' + fmtMs(t.ssl) + ', waiting ' + fmtMs(t.wait) + ', download ' + fmtMs(t.receive)]);
  }
  const docEnd = doc.start + doc.time, dcl = page && page.pageTimings && page.pageTimings.onContentLoad > 0 ? (Date.parse(page.startedDateTime) - S.base) + page.pageTimings.onContentLoad : null;
  const blocking = S.entries.filter(e => ['css', 'js'].includes(e.type) && e.start >= doc.start && e.start < docEnd + 2000 && (dcl == null || e.start < dcl) && ((e.raw._initiator && e.raw._initiator.type === 'parser' && e.raw._initiator.url === doc.url) || (!e.raw._initiator && /^(VeryHigh|High)$/.test(e.raw._priority || ''))) && !/async|defer/.test(String(e.raw._initiator && e.raw._initiator.type)));
  if (blocking.length) {
    const lastEnd = Math.max(...blocking.map(x => x.start + x.time)), delay = lastEnd - docEnd;
    if (delay > 500) {
      const worst = [...blocking].sort((a, b) => (b.start + b.time) - (a.start + a.time)).slice(0, 5);
      dAdd('perf', delay > 1500 ? 'warn' : 'info', worst[0], blocking.length + ' render-blocking scripts/styles delay the first paint by up to ' + fmtMs(delay), [C('likely', 'render_blocking', 'The browser must download these before it can render', 'Stylesheets and synchronous scripts referenced in the HTML block rendering. The slowest finished ' + fmtMs(delay) + ' after the HTML.', ['Inline critical CSS, add defer/async to scripts, preload key resources, and remove unused CSS/JS.'])], worst.map(x => '#' + x.i + ' ' + x.host + x.path.slice(0, 90) + ' — ' + fmtMs(x.time) + (x.host !== doc.host ? ' (third party)' : '')), worst);
    }
  }
  const byUrl = new Map(); for (const e of S.entries) { if (!byUrl.has(e.url)) byUrl.set(e.url, []); byUrl.get(e.url).push(e); }
  const depth = new Map(), parent = new Map();
  const dep = e => { if (depth.has(e)) return depth.get(e); depth.set(e, 1); const p = initiatorParent(e, byUrl); parent.set(e, p); const d = p ? dep(p) + 1 : 1; depth.set(e, d); return d; };
  let deepest = null;
  for (const e of S.entries) { const d = dep(e); if (d >= 4 && (!deepest || (e.start + e.time) > (deepest.start + deepest.time) && d >= depth.get(deepest))) deepest = e; }
  if (deepest) {
    const chain = []; for (let x = deepest; x && chain.length < 12; x = parent.get(x)) chain.unshift(x);
    dAdd('perf', 'info', deepest, 'Request chain ' + chain.length + ' levels deep (' + fmtMs(deepest.start + deepest.time - chain[0].start) + ')', [C('possible', 'request_chain', 'Each request is only discovered after the previous one finished', 'Long dependency chains (HTML → script → data → script…) add up round trips.', ['Preload or prefetch resources deeper in the chain, or bundle / inline them.'])], chain.map(x => '#' + x.i + ' ' + x.host + x.path.slice(0, 90) + ' (+' + fmtMs(x.start) + ', ' + fmtMs(x.time) + ')'), chain);
  }
  const site = siteOf(doc.u ? doc.u.hostname : ''), third = S.entries.filter(e => e.u && (isFirstParty(e.u.host) === null ? siteOf(e.u.hostname) !== site : !isFirstParty(e.u.host)));
  const totalBytes = S.entries.reduce((a, e) => a + e.transfer, 0), thirdBytes = third.reduce((a, e) => a + e.transfer, 0);
  if (third.length >= 10 && (thirdBytes > totalBytes * 0.3 || third.length > S.entries.length * 0.4)) {
    const hosts = new Map(); for (const e of third) { const x = hosts.get(e.host) || { n: 0, b: 0, t: 0 }; x.n++; x.b += e.transfer; x.t += e.time; hosts.set(e.host, x); }
    dAdd('perf', 'info', third[0], 'Third parties: ' + third.length + ' requests (' + Math.round(third.length / S.entries.length * 100) + '%), ' + fmtBytes(thirdBytes) + ' (' + Math.round(thirdBytes / Math.max(1, totalBytes) * 100) + '%)', [C('possible', 'third_party', 'A large share of the page comes from other companies’ servers', 'Third-party scripts (analytics, ads, chat, A/B testing) add requests, bytes and main-thread work you do not control.', ['Remove unused tags, load them after the page is interactive, or self-host critical ones.'])], [...hosts].sort((a, b) => b[1].t - a[1].t).slice(0, 6).map(([hh, x]) => hh + ': ' + x.n + ' requests, ' + fmtBytes(x.b)), []);
  }
  const perHost = new Map(); for (const e of S.entries) { if (!perHost.has(e.host)) perHost.set(e.host, []); perHost.get(e.host).push(e); }
  for (const [host, list] of perHost) {
    const h2 = list.some(e => e.status > 0 && /^(h2|h3|http\/2|http\/3)/i.test(e.httpVersion)), newConn = list.filter(e => e.timings.connect > 0);
    if (h2 && newConn.length >= 4) dAdd('perf', 'warn', newConn[0], newConn.length + ' new connections to ' + host + ' despite HTTP/2', [C('likely', 'no_reuse', 'Connections are not being reused', 'HTTP/2 should carry all requests over one connection. Causes: the server or a proxy closes connections (Connection: close, very short keep-alive), credentialed and anonymous requests (crossorigin attributes) using separate connections, or a certificate that prevents connection coalescing.', ['Check keep-alive / idle timeouts on the server and proxies.'])], [], newConn);
    const queued = list.filter(e => e.status > 0 && e.timings.blocked > 100), h1 = list.some(e => e.status > 0 && /^http\/1/i.test(e.httpVersion));
    if (!h2 && h1 && list.length >= 10 && queued.length >= 6) dAdd('perf', 'warn', queued[0], queued.length + ' requests to ' + host + ' waited in the browser queue (HTTP/1.1)', [C('likely', 'h1_queue', 'The HTTP/1.1 connection limit is slowing this host down', 'Browsers open at most 6 HTTP/1.1 connections per host; the rest wait. Total queueing: ' + fmtMs(queued.reduce((a, e) => a + e.timings.blocked, 0)) + '.', ['Enable HTTP/2 or HTTP/3 on this host, or reduce the number of requests.'])], [], queued);
  }
  const bigImgs = S.entries.filter(e => e.type === 'img' && e.contentSize > 300 * 1024 && e.contentSize <= 1048576);
  if (bigImgs.length) dAdd('perf', 'info', bigImgs[0], bigImgs.length + ' image' + (bigImgs.length > 1 ? 's' : '') + ' over 300 KB', [C('possible', 'big_images', 'Large images slow down the page on mobile connections', '', ['Resize to the displayed size, use WebP/AVIF, and lazy-load images below the fold.'])], bigImgs.map(x => x.u.pathname.slice(0, 100) + ' — ' + fmtBytes(x.contentSize)), bigImgs);
  if (totalBytes > 5 * 1048576 || S.entries.length > 200) dAdd('perf', 'info', doc, 'Heavy page: ' + S.entries.length + ' requests, ' + fmtBytes(totalBytes), [C('possible', 'heavy_page', 'The page downloads a lot', 'Typical fast pages stay under 2–3 MB and about 100 requests.', ['See Largest transfers on the Overview tab.'])], []);
}

/* ---------- Security hygiene ---------- */
function diagSecurity() {
  const urlSecrets = new Map();
  for (const e of S.entries) {
    if (!e.u) continue;
    if (e.u.username || e.u.password) dAdd('security', 'error', e, 'Credentials embedded in a URL', [C('high', 'url_userinfo', 'The URL contains a user name and password (user:pass@host)', 'URLs are logged by proxies and servers and kept in browser history.', ['Send credentials in a header instead.'])], []);
    if (/^PrivateToken\b/i.test(hdr(resH(e), 'www-authenticate'))) continue; // a Privacy Pass challenge nonce, not a secret
    const isCallback = e.oauthRole || [...e.u.searchParams.keys()].includes('state');
    for (const [k, v] of e.u.searchParams) {
      if (!v || v.length < 8 || /^\[?redacted/i.test(v)) continue;
      if (/^(code|state|nonce|session_state)$/i.test(k) && isCallback) continue;
      if (/^x-amz-|^(sig|se|sp|sv|st|spr|srt|ss|skoid|sktid)$/i.test(k)) continue; // signed-URL parameters are meant to be in the URL
      if (/^(samlrequest|samlresponse|relaystate)$/i.test(k)) continue;
      if (!isSensitiveName(k)) continue;
      const key = k.toLowerCase(); if (!urlSecrets.has(key)) urlSecrets.set(key, []); urlSecrets.get(key).push(e);
    }
  }
  for (const [k, list] of urlSecrets) {
    const pw = /pass|pwd|secret/i.test(k);
    dAdd('security', pw ? 'error' : 'warn', list[0], (pw ? 'A password or secret' : 'A token or key') + ' is sent in the URL ("' + k + '", ' + list.length + ' request' + (list.length > 1 ? 's' : '') + ')', [C(pw ? 'high' : 'likely', 'secret_in_url', 'Secrets in query strings leak', 'URLs end up in server and proxy logs, browser history, analytics and the Referer header sent to other sites.', ['Send the value in an Authorization header or a POST body instead.'])], list.slice(0, 5).map(x => '#' + x.i + ' ' + x.host + x.u.pathname.slice(0, 80) + '?' + k + '=…'), list);
  }
  const insecure = S.entries.filter(e => e.u && e.u.protocol === 'http:' && !/^(localhost|127\.|\[::1\])/.test(e.u.hostname) && (hdr(reqH(e), 'cookie') || hdr(reqH(e), 'authorization') || /pass(word)?|pwd/i.test(reqBodyText(e))));
  if (insecure.length) dAdd('security', 'error', insecure[0], insecure.length + ' request' + (insecure.length > 1 ? 's' : '') + ' sent cookies, credentials or passwords over plain HTTP', [C('high', 'cleartext_creds', 'Sensitive data travelled unencrypted', 'Anyone on the network path (public Wi-Fi, ISP, proxy) can read and reuse it.', ['Serve the site over HTTPS only, redirect HTTP to HTTPS, mark cookies Secure, and enable HSTS.'])], insecure.map(x => '#' + x.i + ' ' + x.method + ' ' + x.url.slice(0, 120)), insecure);
  const docHosts = new Map();
  for (const e of S.entries.filter(x => x.type === 'doc' && x.status === 200 && x.u && x.u.protocol === 'https:')) if (!docHosts.has(e.host)) docHosts.set(e.host, e);
  for (const [host, e] of docHosts) {
    const H = resH(e), missing = [];
    const hsts = hdr(H, 'strict-transport-security'), ma = +(/max-age=(\d+)/i.exec(hsts) || [])[1];
    if (!hsts) missing.push('Strict-Transport-Security (HSTS)'); else if (ma < 15552000) missing.push('a longer HSTS max-age (currently ' + fmtDelta(ma * 1000) + ')');
    if (!/nosniff/i.test(hdr(H, 'x-content-type-options'))) missing.push('X-Content-Type-Options: nosniff');
    const csp = hdr(H, 'content-security-policy');
    if (!csp) missing.push('Content-Security-Policy');
    if (!/frame-ancestors/i.test(csp) && !hdr(H, 'x-frame-options')) missing.push('clickjacking protection (frame-ancestors or X-Frame-Options)');
    if (missing.length) dAdd('security', 'info', e, 'Security headers missing on ' + host, [C('possible', 'sec_headers', 'The page is missing: ' + missing.join(', '), 'These headers protect against protocol downgrades, MIME sniffing, injected scripts and clickjacking.', ['Add the missing headers at the web server, CDN or app.'])], []);
  }
  const seen = new Set();
  for (const e of S.entries) for (const c of setCookiesOf(e)) {
    if (!SESSION_COOKIE.test(c.name) || seen.has(c.name + '|' + e.host) || c.value === '') continue;
    seen.add(c.name + '|' + e.host);
    if (c.sameSite === 'none' && !c.secure) dAdd('security', 'error', e, 'Cookie "' + c.name + '" is SameSite=None without Secure', [C('high', 'cookie_none_insecure', 'Browsers reject this cookie', 'SameSite=None cookies must also be Secure, so the browser never stores it.', ['Add Secure (and serve over HTTPS).'])], ['Set-Cookie: ' + c.name + '=…; ' + setCookieSummary(c)]);
    else if (!c.httpOnly) dAdd('security', 'warn', e, 'Session cookie "' + c.name + '" is readable by JavaScript (no HttpOnly)', [C('likely', 'cookie_no_httponly', 'Any injected script can steal this session cookie', '', ['Add HttpOnly to session cookies.'])], ['Set-Cookie: ' + c.name + '=…; ' + setCookieSummary(c)]);
  }
  for (const e of S.entries) {
    const ct = hdr(reqH(e), 'content-type'), body = reqBodyText(e);
    if (!/csp-report|reports\+json/i.test(ct) && !/"csp-report"|"type"\s*:\s*"csp-violation"/.test(body)) continue;
    let reps = []; try { const j = JSON.parse(body); reps = (Array.isArray(j) ? j : [j]).map(r => r['csp-report'] || r.body || r).filter(Boolean); } catch (_) { /* unreadable */ }
    for (const r of reps.slice(0, 5)) {
      const blocked = r['blocked-uri'] || r.blockedURL || '', dir = r['effective-directive'] || r.effectiveDirective || r['violated-directive'] || r.violatedDirective || '';
      dAdd('security', 'warn', e, 'Content-Security-Policy blocked ' + (blocked || 'something') + (dir ? ' (' + dir + ')' : ''), [C('high', 'csp_violation', 'The page’s CSP blocked a resource', 'Blocked resources do not appear as failed requests: the browser never sends them, so this report is the only trace in the HAR. Page: ' + (r['document-uri'] || r.documentURL || '?') + '.', ['If the resource is legitimate, add its origin to the ' + (dir || 'matching') + ' directive; otherwise find what injected it.'])], [r['original-policy'] || r.originalPolicy ? 'Policy: ' + String(r['original-policy'] || r.originalPolicy).slice(0, 300) : '']);
    }
  }
  const traces = S.entries.filter(e => e.status >= 400 && stackTrace(bodyText((e.raw.response || {}).content || {})));
  if (traces.length) dAdd('security', 'warn', traces[0], traces.length + ' error response' + (traces.length > 1 ? 's expose' : ' exposes') + ' a stack trace', [C('likely', 'stack_trace', 'Internal details are shown to users', 'Stack traces reveal file paths, library versions and code structure that help attackers.', ['Disable detailed errors in production; log them server-side instead.'])], traces.slice(0, 5).map(x => '#' + x.i + ' ' + stackTrace(bodyText((x.raw.response || {}).content || {})).summary), traces);
  const ver = new Map();
  for (const e of S.entries) for (const n of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) { const v = hdr(resH(e), n); if (v && /\d+\.\d+/.test(v)) ver.set(e.host + '|' + n, [e, n + ': ' + v]); }
  if (ver.size) { const list = [...ver.values()]; dAdd('security', 'info', list[0][0], 'Software versions disclosed in ' + list.length + ' header' + (list.length > 1 ? 's' : ''), [C('possible', 'version_disclosure', 'Response headers reveal exact software versions', 'This makes it easier to look up known vulnerabilities.', ['Remove version numbers from Server / X-Powered-By headers.'])], list.map(x => x[0].host + ' — ' + x[1]), list.map(x => x[0])); }
}

/* ---------- run ---------- */
const FINDING_CATS = new Set(['rules', 'cors', 'hidden', 'ratelimit', 'redirect', 'realtime', 'hang', 'security', 'cache']);
function runDiagnostics() {
  D.events = []; D.error = '';
  for (const e of S.entries) { e.diag = null; delete e._json; }
  const steps = [diagRules, diagCors, diagNetwork, diagNetlog, diagServer, diagRateLimit, diagHidden, diagRedirect, diagRealtime, diagHang, diagCache, diagPerf, diagSecurity, diagPii];
  const errs = [];
  for (const f of steps) { try { f(); } catch (err) { errs.push(f.name + ': ' + ((err && err.message) || err)); } }
  D.error = errs.join('; ');
  if (SETTINGS.ignoreHosts.length) D.events = D.events.filter(v => !(v.e && isIgnoredHost(v.e.host)) || v.cat === 'rules');
  for (const v of D.events) {
    if (v.normal || !v.e) continue;
    if (FINDING_CATS.has(v.cat) && v.sev !== 'info') { const code = v.cat === 'cors' ? 'cors' : 'diag_' + v.cat, f = { code, sev: v.sev === 'error' ? 'error' : 'warn', e: v.e, detail: v.headline }; v.e.findings.push(f); S.findings.push(f); }
    if (v.cat === 'network') for (const x of [v.e, ...v.related]) for (const f of x.findings) if (f.code === 'failed') f.detail = (v.causes[0] ? v.causes[0].title : '') + (v.code ? ' (' + v.code + ')' : '');
    if (v.cat === 'server' && v.layer) for (const x of [v.e, ...v.related]) for (const f of x.findings) if (f.code === 'server_error' && !f.detail.includes(' — from ')) f.detail += ' — from ' + v.layer;
  }
  S.findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
}

/* ---------- Diagnose view ---------- */
const dSevRank = { error: 0, warn: 1, info: 2 };
function diagCounts() { const m = new Map(); for (const v of D.events) if (!v.normal && v.sev !== 'info') m.set(v.cat, (m.get(v.cat) || 0) + 1); return m; }
function diagSummaryText() {
  const counts = diagCounts();
  if (!counts.size) return 'No CORS, network, server, API, redirect, caching, real-time, hang or security problems found. Informational notes may be listed below.';
  return [...counts].sort((a, b) => b[1] - a[1]).map(([k, n]) => DCAT_LABEL[k] + ': ' + n).join(' · ');
}
function diagReport() {
  const L = ['# Diagnosis report', '', '- File: ' + S.fileName, '- Captured: ' + fmtDate(S.base) + ', ' + S.entries.length + ' requests', '- Generated locally by HAR Analytics. Tokens, passwords, cookie values and keys are removed.', '', '## Summary', '', diagSummaryText(), ''];
  for (const [k, l] of DCATS) {
    const list = D.events.filter(v => v.cat === k && !v.normal);
    if (!list.length) continue;
    L.push('## ' + l, '');
    list.sort((a, b) => dSevRank[a.sev] - dSevRank[b.sev]).forEach(v => {
      L.push('### ' + (v.sev === 'error' ? '❗ ' : v.sev === 'warn' ? '⚠️ ' : 'ℹ️ ') + v.headline, '');
      if (v.e) L.push('- Request: #' + v.e.i + ' `' + v.e.method + ' ' + redactUrl(v.e.url) + '` → ' + (v.e.status || 'no response'));
      const c0 = v.causes[0];
      if (c0) L.push('- **Cause** (' + CONF_LABEL[c0.conf].toLowerCase() + '): ' + c0.title + (c0.detail ? '. ' + c0.detail : ''));
      for (const c of v.causes.slice(1)) L.push('- Also ' + CONF_LABEL[c.conf].toLowerCase() + ': ' + c.title);
      for (const x of v.evidence.slice(0, 12)) L.push('- Evidence: ' + x);
      if (v.related.length) L.push('- Related requests: ' + v.related.slice(0, 40).map(x => '#' + x.i).join(', '));
      const fx = fixesOf(v); if (fx.length) { L.push('- What to try:'); for (const f of fx) L.push('  - ' + f); }
      L.push('');
    });
  }
  return scrub(L.join('\n'));
}

/* ======================================================================
   Compare two HARs ("works here, fails there")
   Requests are matched by method + host + path with IDs and hashes
   replaced by placeholders + the names of the query parameters.
   ====================================================================== */
