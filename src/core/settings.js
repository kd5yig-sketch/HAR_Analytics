/* ---------- settings: what the analyzer knows about YOUR environment ----------
   Saved in the browser (localStorage) or passed to the CLI with --settings.
   Everything is optional; empty settings keep the built-in behaviour. */
const DEFAULT_SETTINGS = {
  version: 1,
  firstPartyHosts: [],   // "example.com" also covers its subdomains
  ignoreHosts: [],       // left out of findings and diagnoses (e.g. analytics)
  tokens: [],            // [{ hosts: 'api.example.com', issuer: 'https://login…', audience: 'api://…' }]
  slowMs: 3000,          // "slow request" finding
  ttfbMs: 1000,          // "slow server response" finding
  redactPatterns: [],    // extra regular expressions removed by the redacted export
  rules: [],             // custom rules, see core/rules.js
};
const asList = v => (Array.isArray(v) ? v : String(v || '').split(/[\n,]/)).map(x => String(x).trim()).filter(Boolean);
function normalizeSettings(o) {
  o = o && typeof o === 'object' ? o : {};
  const num = (v, d, min, max) => { const n = Number(v); return Number.isFinite(n) && n >= min && n <= max ? n : d; };
  const out = {
    version: 1,
    firstPartyHosts: asList(o.firstPartyHosts).map(x => x.toLowerCase().replace(/^\*\.|^\./, '')),
    ignoreHosts: asList(o.ignoreHosts).map(x => x.toLowerCase().replace(/^\*\.|^\./, '')),
    tokens: (Array.isArray(o.tokens) ? o.tokens : []).map(t => ({ hosts: asList(t && t.hosts).map(x => x.toLowerCase().replace(/^\*\.|^\./, '')), issuer: String((t && t.issuer) || '').trim(), audience: asList(t && t.audience) })).filter(t => t.hosts.length && (t.issuer || t.audience.length)),
    slowMs: num(o.slowMs, DEFAULT_SETTINGS.slowMs, 100, 600000),
    ttfbMs: num(o.ttfbMs, DEFAULT_SETTINGS.ttfbMs, 50, 600000),
    redactPatterns: asList(o.redactPatterns).filter(p => { try { new RegExp(p, 'g'); return true; } catch (_) { return false; } }),
    rules: (Array.isArray(o.rules) ? o.rules : []).map(normalizeRule).filter(Boolean),
  };
  return out;
}
const settingsJson = s => JSON.stringify(s || SETTINGS, null, 2);
function hostMatches(pattern, host) {
  host = String(host || '').toLowerCase().replace(/:\d+$/, '');
  pattern = String(pattern || '').toLowerCase().replace(/^\*\.|^\./, '').replace(/:\d+$/, '');
  return !!pattern && (host === pattern || host.endsWith('.' + pattern));
}
const anyHost = (patterns, host) => patterns.some(p => hostMatches(p, host));
// true / false when first-party hosts are configured, null when unknown
function isFirstParty(host) { return SETTINGS.firstPartyHosts.length ? anyHost(SETTINGS.firstPartyHosts, host) : null; }
const isIgnoredHost = host => SETTINGS.ignoreHosts.length > 0 && anyHost(SETTINGS.ignoreHosts, host);
function expectedToken(host) { return SETTINGS.tokens.find(t => anyHost(t.hosts, host)) || null; }
function applySettings(o) { SETTINGS = normalizeSettings(o); return SETTINGS; }
let SETTINGS = normalizeSettings({});
