# Changelog

## v1.0.0-beta.1

First public beta. HAR Analytics is a single HTML file that analyzes HAR files and Chrome NetLogs
entirely on your computer: no install, no server, no cloud. A Content-Security-Policy stops the
page from making any network request, so captures full of tokens and cookies never leave the
machine.

**Download `har-analyzer-v1.0.0-beta.1.html` below and open it in Chrome, Edge, Firefox or Safari.**

### Analysis

- **Requests and findings:** sortable, filterable request table with a waterfall; per-request
  headers, payload, response, timing, cookies; findings for failures, CORS, mixed content,
  redirects, insecure cookies, slow phases, caching and compression.
- **Diagnose:** explains problems from the evidence, with the most likely cause, how strong the
  evidence is, and what to try: CORS (the exact header that is wrong), network and TLS errors,
  server and gateway errors (which layer produced a 5xx, and fixed timeouts), rate limiting and
  retry storms, hidden API errors (GraphQL, gRPC, JSON-RPC, HTML instead of JSON), redirect
  loops, WebSockets and SSE, hangs, caching and CDN, page-load performance, and security hygiene.
- **Authentication:** recognizes Basic, Bearer/JWT, OAuth 2.0 / OIDC flows, SAML, NTLM,
  Kerberos, Digest, API keys, session cookies, signed URLs, client certificates and sign-in
  forms, and explains why each failure happened (expired tokens, wrong audience or scope, PKCE
  mismatch, dropped headers, SameSite cookies, CSRF tokens, split NTLM handshakes, and more).
  Sign-in flows are drawn as sequence diagrams (SVG, PNG or Mermaid).
- **Compare:** ranks the differences between a working and a broken capture.
- **Timeline:** requests and latency over time, error onset, and per-endpoint statistics.
- **Chrome NetLog:** open a NetLog like a HAR or attach it to one, for DNS, proxy and PAC
  decisions, connection attempts, TLS details and the certificates Chrome received, including
  detection of TLS-inspection proxies.

### Working with captures

- JSON tree with JSONPath search, sandboxed HTML preview, a decoder (JWT, base64, gzip, URL,
  hex, timestamps), and request/response diffs.
- Copy any request as cURL, fetch, PowerShell, Python, HTTPie or wget; export a Postman
  collection with credentials replaced by variables.
- Stars and notes on requests, kept locally.
- **Settings:** your hosts, ignored hosts, expected token issuers and audiences, thresholds,
  extra redaction patterns, and custom rules.

### Sharing safely

- Personal-data scan (emails, phones, Luhn-checked card numbers, SSNs, IBANs, client IPs).
- Redacted HAR export with a preview of every change, and a case bundle (.zip) with the
  redacted HAR, reports, request list and notes.

### Command line

- `har-analytics` runs the same analysis on files and folders, writes reports, redacted HARs
  and case bundles, compares captures, and sets exit codes for CI (`--fail-on`).
  Install it from the `.tgz` below with `npm install -g ./har-analytics-1.0.0-beta.1.tgz`.

### Known limitations

- Beta: tested on synthetic captures and real Chromium captures (github.com, pypi.org, npm,
  a TLS-inspecting proxy). Please report false positives, ideally with a redacted HAR.
- Very large captures (over ~150 MB) depend on the browser's memory limits.
- NetLogs in the default capture mode contain no request or response bodies, so body-based
  diagnoses (sign-in forms, API error messages) need the HAR as well.
