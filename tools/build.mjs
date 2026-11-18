// Builds the single-file app: inlines src/styles.css and the src/ scripts into
// src/index.html and writes har-analyzer.html (the file users download and open).
//   node tools/build.mjs           build
//   node tools/build.mjs --check   fail if har-analyzer.html is not up to date
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// Analysis modules first (they also run under Node in the CLI), then the UI.
// Order matters only for top-level statements that use earlier declarations.
export const CORE_FILES = ['core/base.js', 'core/xml.js', 'core/auth.js', 'core/diag.js', 'core/compare.js', 'core/bodytools.js', 'core/copyas.js', 'core/settings.js', 'core/rules.js', 'core/pii.js', 'core/stats.js', 'core/netlog.js', 'core/zip.js'];
export const UI_FILES = ['ui/dom.js', 'ui/app.js', 'ui/auth-view.js', 'ui/diag-view.js', 'ui/compare-view.js', 'ui/settings-view.js', 'ui/share-view.js', 'ui/body-tools.js', 'ui/timeline-view.js', 'ui/sequence.js', 'ui/netlog-view.js', 'ui/events.js'];

const exists = f => { try { readFileSync(join(root, 'src', f)); return true; } catch (_) { return false; } };
export function coreSource() {
  return CORE_FILES.filter(exists).map(f => '// ---- src/' + f + ' ----\n' + readFileSync(join(root, 'src', f), 'utf8')).join('\n');
}
export function build() {
  const tpl = readFileSync(join(root, 'src', 'index.html'), 'utf8');
  const css = readFileSync(join(root, 'src', 'styles.css'), 'utf8');
  const js = "'use strict';\n\n" + coreSource() + '\n' + UI_FILES.filter(exists).map(f => '// ---- src/' + f + ' ----\n' + readFileSync(join(root, 'src', f), 'utf8')).join('\n');
  if (!tpl.includes('/*__STYLES__*/') || !tpl.includes('/*__SCRIPTS__*/')) throw new Error('src/index.html is missing a placeholder');
  if (/<\/script/i.test(js)) throw new Error('a source file contains "</script", which would end the inline script early');
  // Function replacements so "$&"-style patterns in the sources are not interpreted.
  return tpl.replace('/*__STYLES__*/', () => css.trimEnd()).replace('/*__SCRIPTS__*/', () => js.trimEnd());
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const out = join(root, 'har-analyzer.html'), html = build();
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== html) { console.error('har-analyzer.html is out of date: run npm run build'); process.exit(1); }
    console.log('har-analyzer.html is up to date');
  } else {
    writeFileSync(out, html);
    console.log('built har-analyzer.html (' + Math.round(html.length / 1024) + ' KB)');
  }
}
