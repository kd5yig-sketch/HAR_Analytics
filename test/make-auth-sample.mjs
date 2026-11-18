// Generates sample/auth-failures.har: a synthetic capture with one example of each common
// authentication failure, built from real protocol structures (JWTs, NTLM messages, SPNEGO,
// deflated SAML AuthnRequests, PKCE). All hosts are example domains; all secrets are fake.
// Usage: node test/make-auth-sample.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const t0 = Date.parse('2026-11-02T14:00:00.000Z');
const SKEW = { 'api.example.com': 120000 }; // this server's clock runs 2 minutes ahead
const b64url = b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jwt = (payload, n) => b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'key-2026' })) + '.' + b64url(JSON.stringify(payload)) + '.' + b64url('fake-signature-' + n + '-'.repeat(40));
const sec = s => Math.floor((t0 + s) / 1000);
const pkce = v => b64url(createHash('sha256').update(v).digest());
const form = o => new URLSearchParams(o).toString();

/* ---- NTLM / SPNEGO messages ---- */
const u16 = s => Buffer.from(s, 'utf16le');
const SIG = Buffer.from('NTLMSSP\0', 'latin1');
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const secbuf = (len, off) => { const b = Buffer.alloc(8); b.writeUInt16LE(len, 0); b.writeUInt16LE(len, 2); b.writeUInt32LE(off, 4); return b; };
const ntlm1 = () => Buffer.concat([SIG, u32(1), u32(0xa2088207), secbuf(0, 0), secbuf(0, 0)]).toString('base64');
function ntlm2(target) {
  const t = u16(target);
  return Buffer.concat([SIG, u32(2), secbuf(t.length, 56), u32(0xa2898205), Buffer.from('0123456789abcdef', 'hex'), Buffer.alloc(8), secbuf(0, 56 + t.length), Buffer.alloc(8), t]).toString('base64');
}
function ntlm3(domain, user, ws, ntLen) {
  const lm = Buffer.alloc(24), nt = Buffer.alloc(ntLen, 0x5a), d = u16(domain), u = u16(user), w = u16(ws);
  let off = 88; const at = len => { const o = off; off += len; return o; };
  const head = [SIG, u32(3), secbuf(lm.length, at(lm.length)), secbuf(nt.length, at(nt.length)), secbuf(d.length, at(d.length)), secbuf(u.length, at(u.length)), secbuf(w.length, at(w.length)), secbuf(0, off), u32(0xa2888205), Buffer.alloc(8), Buffer.alloc(16)];
  return Buffer.concat([...head, lm, nt, d, u, w]).toString('base64');
}
const KRB5_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
const spnegoKerberos = Buffer.from([0x60, 0x28, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x1e, 0x30, 0x1c, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, ...KRB5_OID, 0xa2, 0x0b, 0x04, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9]).toString('base64');
const negAccepted = Buffer.from([0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00]).toString('base64');

/* ---- HAR builder ---- */
const entries = [];
function add(o) {
  const t = { blocked: 1, dns: -1, connect: -1, ssl: -1, send: 0.2, wait: 60, receive: 3, ...(o.timings || {}) };
  const time = ['blocked', 'dns', 'connect', 'send', 'wait', 'receive'].reduce((a, k) => a + Math.max(0, t[k]), 0);
  const u = new URL(o.url), status = o.status ?? 200;
  const body = o.json !== undefined ? JSON.stringify(o.json) : (o.body ?? '');
  const mime = o.mime || (o.json !== undefined ? 'application/json' : '');
  const date = new Date(t0 + o.at + time + (SKEW[u.host] || 0)).toUTCString();
  const resHeaders = status === 0 ? [] : [['date', date], ...(mime ? [['content-type', mime]] : []), ...(o.loc ? [['location', o.loc]] : []), ...(o.res || [])];
  const reqHeaders = [['host', u.host], ['user-agent', 'Mozilla/5.0 (sample)'], ['accept', '*/*'], ...(o.req || [])];
  let postData;
  if (o.form) postData = { mimeType: 'application/x-www-form-urlencoded', text: form(o.form) };
  if (o.postJson) postData = { mimeType: 'application/json', text: JSON.stringify(o.postJson) };
  if (postData) reqHeaders.push(['content-type', postData.mimeType]);
  entries.push({
    startedDateTime: new Date(t0 + o.at).toISOString(), time, _resourceType: o.type || 'fetch', pageref: 'page_1',
    request: { method: o.method || (postData ? 'POST' : 'GET'), url: o.url, httpVersion: o.http || 'h2', headers: reqHeaders.map(([name, value]) => ({ name, value })), queryString: [...u.searchParams].map(([name, value]) => ({ name, value })), cookies: [], headersSize: -1, bodySize: postData ? postData.text.length : 0, ...(postData ? { postData } : {}) },
    response: { status, statusText: o.statusText ?? (status === 200 ? 'OK' : ''), httpVersion: status === 0 ? '' : (o.http || 'h2'), headers: resHeaders.map(([name, value]) => ({ name, value })), cookies: [], content: { size: body.length, mimeType: mime, ...(body ? { text: body } : {}) }, redirectURL: o.loc || '', headersSize: -1, bodySize: body.length, _transferSize: status === 0 ? 0 : body.length + 300, ...(o.error ? { _error: o.error } : {}) },
    cache: {}, timings: t, serverIPAddress: status === 0 ? '' : '203.0.113.' + (10 + (entries.length % 40)), connection: String(o.conn || 100 + entries.length),
  });
}

const APP = 'https://app.example.com', API = 'https://api.example.com', IDP = 'https://login.example-idp.com';
const CLIENT = 'spa-client-123';

// 1. OIDC sign-in with PKCE that succeeds
const verifier1 = 'v1-correct-horse-battery-staple-0123456789abcdefghijk';
add({ at: 0, url: APP + '/', type: 'document', mime: 'text/html', body: '<!doctype html><title>Example App</title>' });
add({ at: 300, type: 'document', status: 302, statusText: 'Found', url: IDP + '/oauth2/authorize?' + form({ client_id: CLIENT, response_type: 'code', redirect_uri: APP + '/callback', scope: 'openid profile orders:read offline_access', state: 'st-abc', nonce: 'n-xyz', code_challenge: pkce(verifier1), code_challenge_method: 'S256' }), loc: APP + '/callback?code=CODE-ONE-1111&state=st-abc' });
add({ at: 700, type: 'document', url: APP + '/callback?code=CODE-ONE-1111&state=st-abc', mime: 'text/html', body: '<!doctype html><title>Signing in…</title>' });
const ACCESS = jwt({ iss: IDP, aud: API, sub: 'user-42', client_id: CLIENT, scp: 'orders:read', iat: sec(900), exp: sec(300900) }, 1);
const IDTOKEN = jwt({ iss: IDP, aud: CLIENT, sub: 'user-42', name: 'Alex Example', nonce: 'n-xyz', iat: sec(900), exp: sec(3600900) }, 2);
add({ at: 900, url: IDP + '/oauth2/token', req: [['origin', APP]], form: { grant_type: 'authorization_code', code: 'CODE-ONE-1111', redirect_uri: APP + '/callback', client_id: CLIENT, code_verifier: verifier1 }, json: { access_token: ACCESS, id_token: IDTOKEN, refresh_token: 'rt-opaque-0f9e8d7c6b5a49382716', token_type: 'Bearer', expires_in: 300, scope: 'openid profile orders:read offline_access' }, res: [['access-control-allow-origin', APP], ['cache-control', 'no-store']] });
const BEARER = tok => [['authorization', 'Bearer ' + tok], ['origin', APP]];
const CORS = [['access-control-allow-origin', APP]];
add({ at: 1200, url: API + '/v1/orders', req: BEARER(ACCESS), json: { orders: [{ id: 1 }, { id: 2 }] }, res: CORS });
// 2. 403: token lacks the orders:write scope
add({ at: 1300, url: API + '/v1/orders', req: BEARER(ACCESS), postJson: { item: 'A-100', qty: 1 }, status: 403, statusText: 'Forbidden', json: { error: 'insufficient_scope' }, res: [...CORS, ['www-authenticate', 'Bearer error="insufficient_scope", scope="orders:write", error_description="Writing orders requires orders:write"']] });
// 3. 401: the ID token was sent instead of the access token
add({ at: 1400, url: API + '/v1/profile', req: BEARER(IDTOKEN), status: 401, statusText: 'Unauthorized', json: { message: 'Unauthorized' }, res: [...CORS, ['www-authenticate', 'Bearer error="invalid_token", error_description="Invalid audience"']] });
// 4. Authorization header dropped on a cross-origin redirect
add({ at: 1500, url: API + '/v1/reports/123/download', req: BEARER(ACCESS), status: 302, statusText: 'Found', loc: 'https://files.example-storage.net/reports/123.pdf', res: CORS });
add({ at: 1560, url: 'https://files.example-storage.net/reports/123.pdf', req: [['origin', APP]], status: 401, statusText: 'Unauthorized', json: { message: 'Missing bearer token' }, res: [['www-authenticate', 'Bearer realm="files"']] });
// 5. Silent token renewal in an iframe fails: login_required
add({ at: 2000, type: 'document', status: 302, statusText: 'Found', url: IDP + '/oauth2/authorize?' + form({ client_id: CLIENT, response_type: 'code', redirect_uri: APP + '/silent-renew.html', scope: 'openid orders:read', state: 'st-silent', prompt: 'none', code_challenge: pkce('silent-verifier-xyz-0123456789-0123456789'), code_challenge_method: 'S256' }), loc: APP + '/silent-renew.html#error=login_required&error_description=User+session+not+found+%28third-party+cookies+may+be+blocked%29&state=st-silent' });
// 6. Six minutes later the access token has expired
add({ at: 360000, url: API + '/v1/orders', req: BEARER(ACCESS), status: 401, statusText: 'Unauthorized', json: { error: 'invalid_token' }, res: [...CORS, ['www-authenticate', 'Bearer error="invalid_token", error_description="The access token expired"']] });
// 7. ...and the refresh token has been revoked
add({ at: 360300, url: IDP + '/oauth2/token', req: [['origin', APP]], form: { grant_type: 'refresh_token', refresh_token: 'rt-opaque-0f9e8d7c6b5a49382716', client_id: CLIENT }, status: 400, statusText: 'Bad Request', json: { error: 'invalid_grant', error_description: 'The refresh token has been revoked.' }, res: [['access-control-allow-origin', APP]] });

// 8. A second app whose PKCE verifier was lost between redirect and callback
const ADMIN = 'https://admin.example.com';
add({ at: 3000, type: 'document', status: 302, statusText: 'Found', url: IDP + '/oauth2/authorize?' + form({ client_id: 'admin-portal', response_type: 'code', redirect_uri: ADMIN + '/auth/callback', scope: 'openid admin', state: 'st-2', code_challenge: pkce('original-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), code_challenge_method: 'S256' }), loc: ADMIN + '/auth/callback?code=CODE-TWO-2222&state=st-2' });
add({ at: 3400, type: 'document', url: ADMIN + '/auth/callback?code=CODE-TWO-2222&state=st-2', mime: 'text/html', body: '<!doctype html><title>Admin</title>' });
add({ at: 3600, url: IDP + '/oauth2/token', req: [['origin', ADMIN]], form: { grant_type: 'authorization_code', code: 'CODE-TWO-2222', redirect_uri: ADMIN + '/auth/callback', client_id: 'admin-portal', code_verifier: 'regenerated-verifier-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }, status: 400, statusText: 'Bad Request', json: { error: 'invalid_grant', error_description: 'AADSTS501481: The Code_Verifier does not match the code_challenge supplied in the authorization request.' }, res: [['access-control-allow-origin', ADMIN]] });

// 9. HTTP Basic over plain HTTP: challenge, then wrong password
const INTRA = 'http://intranet.example.local/admin/';
add({ at: 5000, type: 'document', url: INTRA, status: 401, statusText: 'Unauthorized', mime: 'text/html', body: '<h1>401 Authorization Required</h1>', res: [['www-authenticate', 'Basic realm="Admin Area"']], http: 'http/1.1' });
add({ at: 9000, type: 'document', url: INTRA, req: [['authorization', 'Basic ' + Buffer.from('jsmith:wrong-pass-123').toString('base64')]], status: 401, statusText: 'Unauthorized', mime: 'text/html', body: '<h1>401 Authorization Required</h1>', res: [['www-authenticate', 'Basic realm="Admin Area"']], http: 'http/1.1' });

// 10. NTLM handshake broken because the type 3 message went out on a new connection
const PORTAL = 'https://portal.corp.example/';
add({ at: 10000, type: 'document', url: PORTAL, status: 401, statusText: 'Unauthorized', http: 'http/1.1', conn: 501, res: [['www-authenticate', 'Negotiate'], ['www-authenticate', 'NTLM']] });
add({ at: 10050, type: 'document', url: PORTAL, req: [['authorization', 'NTLM ' + ntlm1()]], status: 401, statusText: 'Unauthorized', http: 'http/1.1', conn: 501, res: [['www-authenticate', 'NTLM ' + ntlm2('CORP')]] });
add({ at: 10100, type: 'document', url: PORTAL, req: [['authorization', 'NTLM ' + ntlm3('CORP', 'jsmith', 'LAPTOP-7', 48)]], status: 401, statusText: 'Unauthorized', http: 'http/1.1', conn: 502, res: [['www-authenticate', 'Negotiate'], ['www-authenticate', 'NTLM']] });

// 11. Kerberos that works (for the method inventory)
const HR = 'https://hr.corp.example/';
add({ at: 11000, type: 'document', url: HR, status: 401, statusText: 'Unauthorized', http: 'http/1.1', conn: 601, res: [['www-authenticate', 'Negotiate']] });
add({ at: 11040, type: 'document', url: HR, req: [['authorization', 'Negotiate ' + spnegoKerberos]], mime: 'text/html', body: '<!doctype html><title>HR</title>', http: 'http/1.1', conn: 601, res: [['www-authenticate', 'Negotiate ' + negAccepted]] });

// 12. Session cookie with no SameSite attribute, not sent on a cross-site API call
const SHOP = 'https://shop.example.com';
add({ at: 12000, url: SHOP + '/api/login', postJson: { username: 'alex@example.com', password: 'hunter2-sample' }, json: { ok: true }, res: [['set-cookie', 'sid=s3ss10n-abc123def456; Path=/; Secure; HttpOnly']], req: [['origin', SHOP]] });
add({ at: 15000, url: SHOP + '/api/cart', req: [['origin', 'https://partner.example.org'], ['sec-fetch-site', 'cross-site'], ['sec-fetch-mode', 'cors'], ['referer', 'https://partner.example.org/widgets']], status: 401, statusText: 'Unauthorized', json: { error: 'not_authenticated', message: 'Please sign in' }, res: [['access-control-allow-origin', 'https://partner.example.org'], ['access-control-allow-credentials', 'true']] });
// 13. Session expired: an API call is redirected to the sign-in page
add({ at: 16000, url: SHOP + '/api/orders/history', req: [['cookie', 'sid=s3ss10n-abc123def456'], ['sec-fetch-site', 'same-origin'], ['sec-fetch-mode', 'cors']], status: 302, statusText: 'Found', loc: SHOP + '/account/login?returnUrl=%2Fapi%2Forders%2Fhistory' });
add({ at: 16080, url: SHOP + '/account/login?returnUrl=%2Fapi%2Forders%2Fhistory', req: [['cookie', 'sid=s3ss10n-abc123def456']], mime: 'text/html', body: '<!doctype html><title>Sign in</title><form method="post"><input name="email"><input type="password" name="password"></form>' });
// 14. CSRF token missing
add({ at: 17000, url: SHOP + '/api/address', req: [['cookie', 'sid=s3ss10n-abc123def456'], ['origin', SHOP], ['sec-fetch-site', 'same-origin']], postJson: { street: '1 Main St' }, status: 403, statusText: 'Forbidden', json: { error: 'csrf_failed', message: 'CSRF token missing or incorrect.' } });

// 15. SAML: the identity provider issues an assertion for the wrong audience
const SP = 'https://sp.example.com', SAMLIDP = 'https://idp.example.org';
const authnRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-7f3a9c" Version="2.0" IssueInstant="2026-11-02T14:00:20Z" Destination="${SAMLIDP}/saml2/sso" AssertionConsumerServiceURL="${SP}/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>${SP}/saml/metadata</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`;
const samlReqParam = deflateRawSync(Buffer.from(authnRequest)).toString('base64');
const idpSso = SAMLIDP + '/saml2/sso?' + form({ SAMLRequest: samlReqParam, RelayState: '/dashboard' });
add({ at: 20000, type: 'document', url: SP + '/sso/login', status: 302, statusText: 'Found', loc: idpSso });
add({ at: 20100, type: 'document', url: idpSso, mime: 'text/html', body: '<!doctype html><title>Sign in</title><form><input type="password"></form>' });
const samlResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-1" InResponseTo="_req-7f3a9c" Version="2.0" IssueInstant="2026-11-02T14:00:40Z" Destination="${SP}/saml/acs"><saml:Issuer>${SAMLIDP}/metadata</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>ZmFrZQ==</ds:SignatureValue></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a-1" Version="2.0" IssueInstant="2026-11-02T14:00:40Z"><saml:Issuer>${SAMLIDP}/metadata</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alex@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_req-7f3a9c" Recipient="${SP}/saml/acs" NotOnOrAfter="2026-11-02T14:05:40Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2026-11-02T14:00:10Z" NotOnOrAfter="2026-11-02T14:05:40Z"><saml:AudienceRestriction><saml:Audience>https://sp-staging.example.com/saml/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>`;
add({ at: 40000, type: 'document', url: SP + '/saml/acs', req: [['origin', SAMLIDP], ['sec-fetch-site', 'cross-site'], ['sec-fetch-mode', 'navigate']], form: { SAMLResponse: Buffer.from(samlResponse).toString('base64'), RelayState: '/dashboard' }, status: 403, statusText: 'Forbidden', mime: 'text/html', body: '<!doctype html><title>Single sign-on failed</title><p>Invalid audience</p>' });

// 16. S3-compatible presigned URL used an hour after it expired
add({ at: 50000, type: 'document', url: 'https://storage.example-cloud.com/reports-bucket/q3.pdf?' + form({ 'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': 'AKIAEXAMPLE7SAMPLE00/20261102/us-east-1/s3/aws4_request', 'X-Amz-Date': '20261102T120000Z', 'X-Amz-Expires': '3600', 'X-Amz-SignedHeaders': 'host', 'X-Amz-Signature': 'c0ffee5ignature0123456789abcdef0123456789abcdef0123456789abcdef' }), status: 403, statusText: 'Forbidden', mime: 'application/xml', body: '<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Request has expired</Message><X-Amz-Expires>3600</X-Amz-Expires><Expires>2026-11-02T13:00:00Z</Expires></Error>' });
// 17. Corporate proxy wants credentials
add({ at: 52000, type: 'document', url: 'http://downloads.example.net/tools/setup.zip', status: 407, statusText: 'Proxy Authentication Required', mime: 'text/html', body: '<h1>Proxy authentication required</h1>', http: 'http/1.1', res: [['proxy-authenticate', 'Negotiate'], ['proxy-authenticate', 'Basic realm="Corporate Proxy"']] });
// 18. API key rejected
add({ at: 53000, url: 'https://maps.example-api.com/v2/geocode?address=1+Main+St', req: [['x-api-key', 'k-live-SAMPLEKEY-9f8e7d6c5b4a'], ['origin', APP]], status: 401, statusText: 'Unauthorized', json: { error: { code: 401, message: 'API key not valid. Please pass a valid API key.', status: 'UNAUTHENTICATED' } }, res: CORS });
// 19. Mutual TLS: no client certificate
add({ at: 54000, url: 'https://secure.partner.example/api/v1/status', status: 0, statusText: '', error: 'net::ERR_BAD_SSL_CLIENT_AUTH_CERT', timings: { dns: 12, connect: 40, ssl: 30, wait: 0, receive: 0 } });

entries.sort((a, b) => Date.parse(a.startedDateTime) - Date.parse(b.startedDateTime));
const har = { log: { version: '1.2', creator: { name: 'HAR Analytics auth sample generator', version: '1.0' }, pages: [{ startedDateTime: new Date(t0).toISOString(), id: 'page_1', title: APP + '/', pageTimings: { onContentLoad: 400, onLoad: 650 } }], entries } };
const out = join(here, '..', 'sample', 'auth-failures.har');
writeFileSync(out, JSON.stringify(har, null, 2) + '\n');
console.log(`wrote ${entries.length} entries to ${out}`);
