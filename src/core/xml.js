/* ---------- minimal XML reader ----------
   Used where DOMParser is not available (the command-line tool under Node).
   Supports what the SAML analysis needs: elements, attributes, text, namespaces
   prefixes (matched by local name), comments, CDATA and processing instructions. */
function miniXml(text) {
  const decode = s => s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-f]+);/gi, (m, e) => e === 'lt' ? '<' : e === 'gt' ? '>' : e === 'amp' ? '&' : e === 'quot' ? '"' : e === 'apos' ? "'" : String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)));
  const mk = (name, attrs, parent) => {
    const local = name.includes(':') ? name.split(':').pop() : name;
    const el = { nodeName: name, localName: local, attrs, children: [], text: [], parent,
      getAttribute: n => (Object.prototype.hasOwnProperty.call(attrs, n) ? attrs[n] : null),
      getElementsByTagNameNS: (_ns, n) => findAll(el, n), getElementsByTagName: n => findAll(el, n) };
    Object.defineProperty(el, 'textContent', { get: () => el.text.join('') + el.children.map(c => c.textContent).join('') });
    return el;
  };
  const findAll = (el, n) => { const out = []; const walk = x => { for (const c of x.children) { if (n === '*' || c.localName === n || c.nodeName === n) out.push(c); walk(c); } }; walk(el); return out; };
  const doc = mk('#document', {}, null);
  let cur = doc, i = 0;
  try {
    while (i < text.length) {
      const lt = text.indexOf('<', i);
      if (lt < 0) { cur.text.push(decode(text.slice(i))); break; }
      if (lt > i) cur.text.push(decode(text.slice(i, lt)));
      if (text.startsWith('<!--', lt)) { const e = text.indexOf('-->', lt); if (e < 0) return null; i = e + 3; continue; }
      if (text.startsWith('<![CDATA[', lt)) { const e = text.indexOf(']]>', lt); if (e < 0) return null; cur.text.push(text.slice(lt + 9, e)); i = e + 3; continue; }
      if (text.startsWith('<?', lt) || text.startsWith('<!', lt)) { const e = text.indexOf('>', lt); if (e < 0) return null; i = e + 1; continue; }
      const gt = text.indexOf('>', lt); if (gt < 0) return null;
      const tag = text.slice(lt + 1, gt);
      if (tag[0] === '/') { if (cur === doc) return null; cur = cur.parent; i = gt + 1; continue; }
      const self = tag.endsWith('/'), body = self ? tag.slice(0, -1) : tag;
      const nm = /^\s*([^\s/>]+)/.exec(body); if (!nm) return null;
      const attrs = {}; const re = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')/g; let m;
      while ((m = re.exec(body.slice(nm[0].length)))) attrs[m[1]] = decode(m[3] != null ? m[3] : m[4]);
      const el = mk(nm[1], attrs, cur); cur.children.push(el);
      if (!self) cur = el;
      i = gt + 1;
    }
  } catch (_) { return null; }
  if (cur !== doc || !doc.children.length) return null;
  doc.documentElement = doc.children[0];
  return doc;
}
