# HAR_Analytics

HAR analyzer that does not need internet or cloud.

HAR_Analytics is a local, offline tool for troubleshooting HTTP/HTTPS sessions captured as
HAR files. It is a single HTML file: no install, no server, no account, no cloud.

## Quick start

1. Download [`har-analyzer.html`](har-analyzer.html). On its page, use the "Download raw
   file" button, or clone this repository.
2. Open it in Chrome, Edge, Firefox or Safari by double-clicking it.
3. Drag a `.har` file onto the page, or click **Open HAR…**.

No HAR file handy? Open [`sample/sample.har`](sample/sample.har) (general problems) or
[`sample/auth-failures.har`](sample/auth-failures.har) (19 authentication scenarios). Both are
synthetic captures. See [Capturing a HAR](#capturing-a-har) to record your own.

## Privacy

HAR files often contain passwords, session cookies and API tokens, so the analyzer is
built so that it **cannot** send them anywhere:

- Everything (HTML, CSS, JavaScript) is inside the one file. It loads no external
  scripts, fonts, styles or images.
- A Content-Security-Policy in the file sets `connect-src 'none'` and `default-src 'none'`.
  The browser itself refuses any network request the page might try to make.
- The file you open is read in memory with the browser's file API. Nothing is uploaded or
  stored. Close the tab and it's gone.
- Response bodies are shown as text only and never rendered as HTML. Image previews use
  `data:` URLs.

The automated test checks that loading and using the page produces zero network requests.

## What it shows

**Overview:** request count, failures, 4xx/5xx counts, bytes transferred, total time and
the page load event. It also lists findings, status code and resource type breakdowns, the
slowest and largest requests, and a per-domain table (click a domain to filter to it).

**Requests:** every request in a sortable, filterable table with a waterfall. Click a row
(or use ↑/↓ or j/k) to open its details:

| Tab | Contents |
|---|---|
| Headers | URL, status, HTTP version, remote IP, connection, timing, sizes, cache, initiator, the full redirect chain, and response and request headers |
| Payload | Query parameters and the request body (JSON pretty-printed, form fields as a table) |
| Response | The response body: JSON pretty-printed, text decoded from base64, images previewed |
| Timing | Queued, DNS, TCP, TLS, send, waiting (TTFB) and download, with a short reading of where the time went |
| Cookies | Cookies sent and set, with HttpOnly/Secure/SameSite flags |
| Findings | Problems detected on this request, with an explanation |

Each request also has **Copy URL** and **Copy as cURL** buttons, so you can replay it
from a terminal.

**Findings:** problems grouped by type, each with an explanation of common causes:

| Severity | Finding |
|---|---|
| Error | Request failed with no HTTP response (DNS, refused/reset, TLS, blocked, cancelled), showing the browser's `net::ERR_…` text when available |
| Error | CORS preflight (OPTIONS) failed |
| Error | Server error (5xx) |
| Warning | Client error (4xx) |
| Warning | Cross-origin response without `Access-Control-Allow-Origin` |
| Warning | Mixed content (HTTP subresource on an HTTPS page) |
| Warning | Redirect chain of 2 or more redirects |
| Warning | Cookie set over HTTPS without `Secure` |
| Warning | Slow server response (waiting > 1 s) or slow request (> 3 s) |
| Info | Slow DNS (> 200 ms), TCP connect (> 500 ms), TLS (> 500 ms), or queueing (> 500 ms) |
| Info | Large response (> 1 MB), uncompressed text response (> 2 KB), static asset without caching headers, same URL downloaded more than once |

## Authentication analysis

The **Authentication** tab works out how each request authenticated, finds every failed
authentication, authorization or sign-in, and explains **why it failed** from evidence in the HAR.

**Methods it recognizes.** It decodes the credentials and challenges rather than just naming them:

| Method | What it reads |
|---|---|
| HTTP Basic | User name (never the password); whether it went over plain HTTP |
| Bearer tokens / JWT | Header and claims: issuer, audience, scopes, roles, expiry; whether an ID token was sent instead of an access token |
| OAuth 2.0 / OpenID Connect | The whole flow: authorization request, redirect back, token request and response, refresh, client authentication method |
| SAML 2.0 | Decoded (and inflated) AuthnRequest and SAMLResponse: status, audience, destination, InResponseTo, validity window, signature |
| NTLM | Binary handshake messages: type 1/2/3, domain, user, workstation, NTLMv1 or v2, and which TCP connection each message used |
| Kerberos / Negotiate | SPNEGO tokens: Kerberos vs. NTLM fallback, and the server's accept/reject state |
| HTTP Digest | User, realm, algorithm, stale nonces |
| API keys | `X-API-Key`, `Ocp-Apim-Subscription-Key`, `api_key=` and similar |
| Session cookies | Which cookies were set, with which attributes, and whether they were sent |
| Signed URLs | AWS SigV4 (header and presigned URLs) and Azure SAS: signing time and expiry |
| Others | Proxy authentication (407), client certificates (mutual TLS), AWS / Azure Storage error codes, OAuth 1.0a, Okta SSWS, custom schemes |

**Failures it explains.** Some examples:

- **Expired or wrong tokens:** the token expired (and by how long), was not valid yet, was
  an ID token instead of an access token, has the wrong audience, or lacks a scope (it
  compares the scopes required with the scopes in the token).
- **Missing credentials:** the Authorization header was dropped on a cross-origin redirect or
  missing from a request when earlier ones had it; a session cookie wasn't sent because of
  SameSite, Secure, Path, expiry or deletion, or because a cross-origin fetch didn't send credentials.
- **OAuth / OIDC:** PKCE `code_verifier` doesn't match the `code_challenge` (it recomputes
  the SHA-256), `redirect_uri` or `client_id` mismatch, a reused or slow-to-redeem code,
  `state` and `nonce` mismatches, revoked refresh tokens, `login_required` from silent renewal,
  sign-in loops, every standard OAuth error code, and common Microsoft Entra ID `AADSTS` codes.
- **SAML:** non-success status codes, wrong audience, wrong destination or ACS URL,
  expired or not-yet-valid assertions, and missing signatures.
- **Windows authentication:** an NTLM handshake split across TCP connections (load balancer
  without affinity), NTLMv1, anonymous NTLM, Kerberos rejections, clock skew over 5 minutes, and
  NTLM over HTTP/2.
- **Everything else:** Basic credentials rejected; CSRF failures; a web application firewall
  block (Cloudflare, Akamai, AWS WAF, Imperva…) reported as not an authentication problem;
  expired presigned URLs and SAS tokens; S3/Azure signature, clock and permission errors;
  proxies demanding credentials; missing client certificates; captive portals; and API calls
  that got a sign-in page instead of data.

Each failure shows the credentials sent, what the server asked for, the most likely cause
(with how strong the evidence is), other possible causes, the evidence, and what to try.
Normal challenge/response steps, such as the first 401 of NTLM, Kerberos or Basic, are listed
separately so they don't look like failures. The tab also lists the methods used by each
host, reconstructs every sign-in flow step by step with ✓/✗ checks, shows a table of every
token seen, and warns when a server's clock differs from yours (from its `Date` headers).

**Copy report / Download report** produces a Markdown summary you can paste into a ticket.
Token values, passwords, cookie values, authorization codes, keys and signatures are removed
from it.

If a HAR was exported "sanitized" (no Authorization or Cookie headers at all), the tab says
so rather than wrongly reporting that no credentials were sent.

## Filtering

Type in the filter box. Plain words match the URL; prefix a word with `-` to exclude it.
You can combine these keys:

| Example | Meaning |
|---|---|
| `status:404` `status:5xx` `status:failed` | status code, class, or no response |
| `method:POST` | HTTP method |
| `domain:api.example.com` | host contains |
| `type:xhr` `type:image` | resource type |
| `mime:json` | content type contains |
| `larger:100k` | transfer size over 100 KB (`b`, `k`, `m`, `g`) |
| `slower:500ms` `slower:2s` | total time over |
| `auth:fail` `auth:any` | requests with an authentication failure / with any authentication information |

Tick **Search headers & bodies** to match words against headers, request bodies and
response bodies too. For example, find which request returned a particular error message
or set a cookie. The dropdowns filter by status group, domain and page. The type chips
filter by resource type. **With findings** shows only requests that have problems.
Press `/` to jump to the filter box and `Esc` to close the details pane.

## Exporting

**Export → Download redacted HAR** saves a copy that is safer to send to a vendor or
support team:

- Always masked: `Authorization`, `Cookie`, `Set-Cookie`, API-key, CSRF and similar
  headers, and every cookie value.
- On by default: token-like values in URLs, `Referer`/`Location` headers, form fields and
  JSON bodies (names containing token, secret, password, session, auth, signature, api_key,
  or exactly `code`, `key`, `state`, `nonce` and similar).
- Optional: remove request bodies entirely and/or remove response bodies (on by default).

Redaction is pattern-based. Skim the exported file before sharing it if it may contain
unusual secrets, such as a password in a field called `pass_phrase_value`.

**Export → Request list as CSV** saves the currently filtered requests with their status,
sizes, timing phases and findings, for use in a spreadsheet.

## Capturing a HAR

- **Chrome / Edge:** DevTools (F12) → Network → tick *Preserve log* → reproduce the
  problem → *Export HAR* (download arrow). Newer versions offer *Export HAR (sanitized)*
  and *Export HAR (with sensitive data)*. The sanitized export drops cookies and auth
  headers.
- **Firefox:** DevTools → Network → reproduce → gear icon → *Save All As HAR*.
- **Safari:** Develop → Show Web Inspector → Network → reproduce → *Export*.
- Proxies such as Fiddler, Charles, mitmproxy (`mitmdump --set hardump=out.har`) and Burp
  can also export HAR, including traffic from non-browser apps.

## Tests

The tests use Node.js and Playwright with Chromium. They also run on GitHub Actions on every push.

```bash
npm install
```

```bash
npx playwright install chromium
```

```bash
npm test
```

Pass a directory as an argument to `node test/smoke.mjs` or `node test/auth.mjs` to also save
screenshots. To regenerate the samples after changing them:

```bash
npm run sample
```

## Project layout

| Path | What it is |
|---|---|
| `har-analyzer.html` | The whole application: HTML, CSS and JavaScript in one file |
| `sample/sample.har` | Synthetic HAR (all `example` domains, fake credentials) for trying it out |
| `sample/auth-failures.har` | Synthetic HAR with one example of each common authentication failure |
| `test/smoke.mjs` | End-to-end browser test (Playwright + Chromium) |
| `test/auth.mjs` | End-to-end test of the authentication analysis |
| `test/make-sample.mjs`, `test/make-auth-sample.mjs` | Regenerate the sample HARs |

## License

[GNU General Public License v3.0](LICENSE).
