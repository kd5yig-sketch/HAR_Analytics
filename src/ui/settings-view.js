/* ---------- Settings view ---------- */
const SETTINGS_KEY = 'har-analytics.settings.v1';
function loadStoredSettings() {
  try { const raw = localStorage.getItem(SETTINGS_KEY); if (raw) applySettings(JSON.parse(raw)); } catch (_) { /* storage blocked or bad JSON: keep defaults */ }
}
function storeSettings() {
  try { localStorage.setItem(SETTINGS_KEY, settingsJson()); return true; } catch (_) { return false; }
}
function settingsCount() { const s = SETTINGS; return s.firstPartyHosts.length + s.ignoreHosts.length + s.tokens.length + s.redactPatterns.length + s.rules.length + (s.slowMs !== DEFAULT_SETTINGS.slowMs) + (s.ttfbMs !== DEFAULT_SETTINGS.ttfbMs); }
function renderSettings() {
  const s = SETTINGS, root = $('#view-settings');
  const ta = (id, list, ph) => h('textarea', { id, rows: 3, placeholder: ph, spellcheck: 'false' }, list.join('\n'));
  const tokenRow = t => h('div', { class: 'srow tok' },
    h('input', { type: 'text', class: 't-hosts', placeholder: 'API host(s), e.g. api.example.com', value: (t.hosts || []).join(', ') }),
    h('input', { type: 'text', class: 't-iss', placeholder: 'expected issuer (iss)', value: t.issuer || '' }),
    h('input', { type: 'text', class: 't-aud', placeholder: 'expected audience(s) (aud)', value: (t.audience || []).join(', ') }),
    h('button', { class: 'icon', title: 'Remove', 'aria-label': 'Remove', onclick: ev => ev.target.closest('.srow').remove(), text: '✕' }));
  const sel = (cls, opts, v) => h('select', { class: cls }, opts.map(([k, l]) => h('option', { value: k, text: l, selected: k === v ? true : null })));
  const ruleRow = r => h('div', { class: 'srow rule' },
    h('input', { type: 'text', class: 'r-name', placeholder: 'rule name', value: r.name || '' }),
    h('input', { type: 'text', class: 'r-host', placeholder: 'host (blank = any)', value: r.host || '' }),
    h('input', { type: 'text', class: 'r-path', placeholder: 'path, e.g. /api/*', value: r.path || '' }),
    h('input', { type: 'text', class: 'r-method', placeholder: 'method', value: r.method || '' }),
    h('span', { class: 'muted', text: 'fails when' }),
    sel('r-check', Object.entries(RULE_CHECKS).map(([k, c]) => [k, c.label]), r.check || 'slower'),
    h('input', { type: 'text', class: 'r-value', placeholder: 'value', value: r.value || '' }),
    sel('r-sev', [['error', 'error'], ['warn', 'warning'], ['info', 'info']], r.severity || 'warn'),
    h('input', { type: 'text', class: 'r-msg', placeholder: 'message shown when it fails (optional)', value: r.message || '' }),
    h('button', { class: 'icon', title: 'Remove', 'aria-label': 'Remove', onclick: ev => ev.target.closest('.srow').remove(), text: '✕' }));
  root.replaceChildren(h('div', { class: 'av settings' },
    h('div', { class: 'verdict' }, h('div', { class: 'vt', text: 'Settings' }),
      h('p', { text: 'Tell the analyzer about your environment so it can be definite instead of guessing. Settings are saved in this browser only; they are never put into HARs or reports. Export them to share with your team.' }),
      h('div', { class: 'vbtns' },
        h('button', { class: 'primary', id: 'set-save', onclick: saveSettingsForm, text: S.entries.length ? 'Save and re-analyze' : 'Save' }),
        h('button', { id: 'set-export', onclick: () => download('har-analytics-settings.json', settingsJson(), 'application/json'), text: 'Export…' }),
        h('button', { id: 'set-import', onclick: () => $('#settings-file').click(), text: 'Import…' }),
        h('button', { id: 'set-reset', onclick: () => { if (confirm('Reset all settings to the defaults?')) { applySettings({}); storeSettings(); renderSettings(); afterSettingsChange(); } }, text: 'Reset' }),
        h('span', { class: 'muted', id: 'set-status' }))),
    h('h3', { text: 'Your hosts' }),
    h('label', { class: 'slabel', for: 'set-first' }, 'First-party hosts', h('span', { class: 'muted', text: ' — one per line; "example.com" also covers its subdomains. Everything else counts as third party.' })),
    ta('set-first', s.firstPartyHosts, 'example.com\napi.example.net'),
    h('label', { class: 'slabel', for: 'set-ignore' }, 'Hosts to ignore', h('span', { class: 'muted', text: ' — left out of findings and diagnoses (for example analytics or ads you do not control).' })),
    ta('set-ignore', s.ignoreHosts, 'analytics.example-tracker.com'),
    h('h3', { text: 'Expected tokens' }),
    h('p', { class: 'note', text: 'For each API, the token issuer and audience it accepts. Tokens sent to these hosts are checked against them, so "the audience may not match" becomes a definite answer.' }),
    h('div', { id: 'set-tokens' }, s.tokens.map(tokenRow)),
    h('button', { id: 'set-add-token', onclick: () => $('#set-tokens').append(tokenRow({})), text: '+ Add API' }),
    h('h3', { text: 'Thresholds' }),
    h('div', { class: 'srow' }, h('label', { for: 'set-slow', text: 'Slow request after (ms)' }), h('input', { type: 'number', id: 'set-slow', min: 100, value: s.slowMs }),
      h('label', { for: 'set-ttfb', text: 'Slow server response after (ms)' }), h('input', { type: 'number', id: 'set-ttfb', min: 50, value: s.ttfbMs })),
    h('h3', { text: 'Extra redaction patterns' }),
    h('label', { class: 'slabel', for: 'set-redact' }, 'Regular expressions', h('span', { class: 'muted', text: ' — one per line; matches are replaced with [REDACTED] in exported HARs and reports, in addition to the built-in rules. Example: CUST-\\d{6}' })),
    ta('set-redact', s.redactPatterns, 'CUST-\\d{6}'),
    h('div', { id: 'set-redact-msg', class: 'note' }),
    h('h3', { text: 'Custom rules' }),
    h('p', { class: 'note', text: 'Each rule selects requests (all fields optional) and fails them when the check is true. Matches appear in Diagnose → Your rules and in Findings. Examples: api.example.com · /v1/* · fails when takes longer than 800; or any host · fails when request header is missing · X-Request-Id.' }),
    h('div', { id: 'set-rules' }, s.rules.map(ruleRow)),
    h('button', { id: 'set-add-rule', onclick: () => $('#set-rules').append(ruleRow({})), text: '+ Add rule' })));
}
function readSettingsForm() {
  const v = id => $('#' + id).value;
  return {
    firstPartyHosts: v('set-first'), ignoreHosts: v('set-ignore'), slowMs: v('set-slow'), ttfbMs: v('set-ttfb'), redactPatterns: v('set-redact'),
    tokens: $$('#set-tokens .tok').map(r => ({ hosts: $('.t-hosts', r).value, issuer: $('.t-iss', r).value, audience: $('.t-aud', r).value })),
    rules: $$('#set-rules .rule').map(r => ({ name: $('.r-name', r).value, host: $('.r-host', r).value, path: $('.r-path', r).value, method: $('.r-method', r).value, check: $('.r-check', r).value, value: $('.r-value', r).value, severity: $('.r-sev', r).value, message: $('.r-msg', r).value })),
  };
}
async function saveSettingsForm() {
  const raw = readSettingsForm();
  const bad = asList(raw.redactPatterns).filter(p => { try { new RegExp(p); return false; } catch (_) { return true; } });
  $('#set-redact-msg').textContent = bad.length ? 'Ignored (not valid regular expressions): ' + bad.join('  ') : '';
  const before = raw.rules.filter(r => r.check && (r.value || '').trim()).length;
  applySettings(raw);
  const dropped = before - SETTINGS.rules.length;
  const ok = storeSettings();
  renderSettings();
  if (bad.length) $('#set-redact-msg').textContent = 'Ignored (not valid regular expressions): ' + bad.join('  ');
  $('#set-status').textContent = (ok ? 'Saved.' : 'Applied for this session (this browser does not allow saving).') + (dropped > 0 ? ' ' + dropped + ' rule(s) were skipped because their value is missing or not a number.' : '');
  await afterSettingsChange();
}
async function afterSettingsChange() {
  $('#btn-settings').classList.toggle('on', settingsCount() > 0);
  if (S.har) { const v = S.view; await loadHar(S.har, S.fileName); show(v === 'empty' ? 'overview' : v); toast('Re-analyzed with your settings'); }
}
function importSettingsFile(f) {
  const r = new FileReader();
  r.onload = async () => { try { applySettings(JSON.parse(String(r.result))); storeSettings(); renderSettings(); $('#set-status').textContent = 'Imported ' + f.name + '.'; await afterSettingsChange(); } catch (err) { toast('Not a settings file: ' + err.message); } };
  r.readAsText(f);
}
