// Records a REAL Chrome NetLog (and the matching HAR) with Playwright's Chromium,
// against local servers that fail in known ways: an expired certificate, an
// untrusted self-signed certificate, a certificate for the wrong host name, a
// refused connection, a DNS failure, a server error and a slow response.
// Needs: Playwright's Chromium, python3 with the "cryptography" package.
// Writes sample/netlog-failures.json and sample/netlog-failures.har.
// Usage: node test/make-netlog-sample.mjs
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

const { chromium } = createRequire(import.meta.url)('playwright');
const here = dirname(fileURLToPath(import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), 'netlog-'));

// --- certificates (python + cryptography) ---
execFileSync('python3', ['-c', `
import datetime, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
out = sys.argv[1]
def make(name, cn, sans, nb, na):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'HAR Analytics test')])
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(key, hashes.SHA256()))
    open(out + '/' + name + '.key', 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(out + '/' + name + '.crt', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
now = datetime.datetime.now(datetime.timezone.utc)
make('expired', 'localhost', ['localhost'], now - datetime.timedelta(days=400), now - datetime.timedelta(days=35))
make('selfsigned', 'localhost', ['localhost'], now - datetime.timedelta(days=1), now + datetime.timedelta(days=300))
make('wrongname', 'wrong-host.example', ['wrong-host.example'], now - datetime.timedelta(days=1), now + datetime.timedelta(days=300))
`, tmp]);
const tls = n => ({ key: readFileSync(join(tmp, n + '.key')), cert: readFileSync(join(tmp, n + '.crt')) });

// --- servers ---
const listen = srv => new Promise(r => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));
const api = http.createServer((req, res) => {
  const cors = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };
  if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(page()); }
  if (req.url.startsWith('/api/ok')) { res.writeHead(200, cors); return res.end('{"ok":true}'); }
  if (req.url.startsWith('/api/fail')) { res.writeHead(500, cors); return res.end('{"error":"boom"}'); }
  if (req.url.startsWith('/api/slow')) { setTimeout(() => { res.writeHead(200, cors); res.end('{"slow":true}'); }, 1500); return; }
  res.writeHead(404, cors); res.end('{}');
});
const ports = { api: await listen(api) };
for (const n of ['expired', 'selfsigned', 'wrongname']) ports[n] = await listen(https.createServer(tls(n), (req, res) => { res.writeHead(200, { 'access-control-allow-origin': '*' }); res.end('{}'); }));
const closed = net.createServer(); ports.closed = await listen(closed); await new Promise(r => closed.close(r));
function page() {
  const urls = [
    `http://localhost:${ports.api}/api/ok`, `http://localhost:${ports.api}/api/fail`, `http://localhost:${ports.api}/api/slow`, `http://localhost:${ports.api}/api/ok?again=1`,
    `https://localhost:${ports.expired}/expired`, `https://localhost:${ports.selfsigned}/selfsigned`, `https://localhost:${ports.wrongname}/wrongname`,
    `http://localhost:${ports.closed}/refused`, `http://does-not-exist.invalid/dns`,
  ];
  return `<!doctype html><title>NetLog sample</title><script>
    Promise.allSettled(${JSON.stringify(urls)}.map(u => fetch(u).then(r => r.text()))).then(() => { document.title = 'done'; });
  </script>`;
}

// --- capture ---
const netlog = join(tmp, 'netlog.json'), har = join(tmp, 'capture.har');
const browser = await chromium.launch({ args: ['--log-net-log=' + netlog, '--net-log-capture-mode=Default'] });
const ctx = await browser.newContext({ recordHar: { path: har, content: 'embed' } });
const p = await ctx.newPage();
await p.goto(`http://localhost:${ports.api}/`);
await p.waitForFunction(() => document.title === 'done', null, { timeout: 30000 });
await ctx.close();
await browser.close();
api.close();

// Keep the fixture small: drop events unrelated to these requests' hosts is not
// possible without understanding them all, so keep everything but compact it.
const log = JSON.parse(readFileSync(netlog, 'utf8'));
writeFileSync(join(here, '..', 'sample', 'netlog-failures.json'), JSON.stringify(log));
writeFileSync(join(here, '..', 'sample', 'netlog-failures.har'), readFileSync(har, 'utf8'));
rmSync(tmp, { recursive: true, force: true });
console.log('NetLog events:', log.events.length, 'ports:', JSON.stringify(ports));
process.exit(0);
