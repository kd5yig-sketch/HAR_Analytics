// Replays a deliberately awkward request (quotes, $, backticks, Unicode, newlines,
// encoded query) with the code from each "Copy as" format against a local echo
// server, and checks the server received exactly the recorded request.
// Tools that are not installed are skipped. Usage: node test/copyas.mjs
import vm from 'node:vm';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { coreSource } from '../tools/build.mjs';

const run = promisify(execFile);
const ctx = vm.createContext({ console, URL, URLSearchParams, TextDecoder, TextEncoder, atob, btoa, crypto: globalThis.crypto, Blob, Response, DecompressionStream, CompressionStream });
vm.runInContext("'use strict';\n" + coreSource() + '\n;globalThis.__api = { normalize, toCurl, toFetch, toPython, toHttpie, toWget, toPowerShell };', ctx);
const api = ctx.__api;

let last = null;
const srv = http.createServer((req, res) => { let b = ''; req.setEncoding('utf8'); req.on('data', d => (b += d)); req.on('end', () => { last = { method: req.method, url: req.url, headers: req.headers, body: b }; res.end('ok'); }); });
await new Promise(r => srv.listen(0, '127.0.0.1', r));
const port = srv.address().port, path = '/api/items/7?q=a%20b&x=it%27s';
const body = JSON.stringify({ note: "it's a \"test\" with $HOME and `backticks`", unicode: 'héllo ✓', multi: 'line1\nline2' });
const quote = "it's \"quoted\" $HOME `x`";
const entry = { startedDateTime: new Date().toISOString(), time: 1, request: { method: 'PUT', url: `http://127.0.0.1:${port}${path}`, httpVersion: 'HTTP/1.1', headers: [
  { name: 'Host', value: 'ignored' }, { name: 'Content-Type', value: 'application/json' }, { name: 'X-Quote', value: quote }, { name: 'Authorization', value: 'Bearer abc.def.ghi' }, { name: 'Accept-Language', value: 'fr-CA,fr;q=0.9' }, { name: 'User-Agent', value: 'HAR-Test/1.0' }],
  queryString: [], cookies: [], headersSize: -1, bodySize: body.length, postData: { mimeType: 'application/json', text: body } },
  response: { status: 200, statusText: 'OK', httpVersion: 'HTTP/1.1', headers: [], cookies: [], content: { size: 0, mimeType: '' }, redirectURL: '', headersSize: -1, bodySize: 0 }, cache: {}, timings: { send: 0, wait: 1, receive: 0 } };
const e = api.normalize({ log: { entries: [entry] } }).entries[0];
const dir = mkdtempSync(join(tmpdir(), 'copyas-'));
const has = async cmd => { try { await run('bash', ['-c', 'command -v ' + cmd]); return true; } catch (_) { return false; } };
const cases = [
  ['curl', 'curl', () => run('bash', ['-c', api.toCurl(e)], { timeout: 20000 })],
  ['wget', 'wget', () => run('bash', ['-c', api.toWget(e)], { timeout: 20000 }), { decodedUrl: true }],
  ['HTTPie', 'http', () => run('bash', ['-c', api.toHttpie(e)], { timeout: 20000 })],
  ['Python requests', 'python3', async () => { writeFileSync(join(dir, 'r.py'), api.toPython(e)); await run('python3', ['-c', 'import requests']); return run('python3', [join(dir, 'r.py')], { timeout: 20000 }); }],
  ['JavaScript fetch (Node)', 'node', () => { writeFileSync(join(dir, 'r.mjs'), api.toFetch(e)); return run('node', [join(dir, 'r.mjs')], { timeout: 20000 }); }],
  ['PowerShell', 'pwsh', () => { writeFileSync(join(dir, 'r.ps1'), api.toPowerShell(e)); return run('pwsh', ['-NoProfile', '-File', join(dir, 'r.ps1')], { timeout: 30000 }); }],
];
let passed = 0, failed = 0, skipped = 0;
for (const [name, bin, fn, opt = {}] of cases) {
  if (!(await has(bin))) { console.log('  - ' + name + ': skipped (' + bin + ' not installed)'); skipped++; continue; }
  last = null;
  try { await fn(); } catch (err) { if (/No module named/.test(String(err.stderr))) { console.log('  - ' + name + ': skipped (module not installed)'); skipped++; continue; } console.log('  ✗ ' + name + ': ' + String(err.stderr || err.message).slice(0, 300)); failed++; continue; }
  const wantUrls = opt.decodedUrl ? [path, path.replace('%27', "'")] : [path]; // wget 1.x decodes %27, wget2 does not
  const problems = [];
  if (!last) problems.push('no request received');
  else {
    if (last.method !== 'PUT') problems.push('method ' + last.method);
    if (!wantUrls.includes(last.url)) problems.push('url ' + last.url);
    if (last.headers['x-quote'] !== quote) problems.push('X-Quote ' + last.headers['x-quote']);
    if (last.headers.authorization !== 'Bearer abc.def.ghi') problems.push('Authorization');
    if (!String(last.headers['content-type']).startsWith('application/json')) problems.push('Content-Type ' + last.headers['content-type']);
    if (String(last.headers['accept-language']).replace(/\s+/g, '') !== 'fr-CA,fr;q=0.9') problems.push('Accept-Language ' + JSON.stringify(last.headers['accept-language'])); // .NET re-formats it as "fr-CA, fr; q=0.9" (same meaning)
    if (last.body !== body) problems.push('body ' + JSON.stringify(last.body).slice(0, 120));
  }
  if (problems.length) { console.log('  ✗ ' + name + ': ' + problems.join('; ')); failed++; } else { console.log('  ✓ ' + name + ' replays the request exactly'); passed++; }
}
srv.close(); rmSync(dir, { recursive: true, force: true });
console.log(`\n${passed} checks passed, ${skipped} skipped`);
if (failed) process.exit(1);
