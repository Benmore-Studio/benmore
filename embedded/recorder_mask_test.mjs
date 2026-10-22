// Masking test for the session recorder (recorder.go RecorderScript). Run via
// `node embedded/recorder_mask_test.mjs <script.js>` (invoked from the Go test
// TestRecorderMasksSecretSurfaces with the generated recorder script).
//
// The recorder runs against a small fake DOM. A page carrying secrets (an API
// token or TOTP secret in a [data-bm-mask] block, a password input with a
// value attribute, an otpauth URI, a reset token in the URL) must not put any
// of them in what the beacon sends: not in the DOM snapshots, the value
// attribute mutations, the input and click events, or the recorded URLs. An
// ordinary page must be recorded exactly as before.
import fs from 'node:fs';
import vm from 'node:vm';

const src = fs.readFileSync(process.argv[2], 'utf8');
const failures = [];

// ─── minimal DOM ─────────────────────────────────────────────────────
const VOID = new Set(['input', 'img', 'meta', 'br', 'link']);
const escText = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escAttr = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
class Text { constructor(d) { this.nodeType = 3; this.data = d; this.parentNode = null; } get outerHTML() { return escText(this.data); } }
class El {
  constructor(tag, attrs = {}, kids = []) {
    this.nodeType = 1; this.tag = tag; this.attrs = new Map(Object.entries(attrs)); this.childNodes = []; this.parentNode = null;
    for (const k of kids) this.appendChild(typeof k === 'string' ? new Text(k) : k);
  }
  appendChild(n) { n.parentNode = this; this.childNodes.push(n); return n; }
  get tagName() { return this.tag.toUpperCase(); }
  get parentElement() { return this.parentNode instanceof El ? this.parentNode : null; }
  get children() { return this.childNodes.filter((n) => n instanceof El); }
  get attributes() { return [...this.attrs].map(([name, value]) => ({ name, value })); }
  getAttribute(k) { return this.attrs.has(k) ? this.attrs.get(k) : null; }
  setAttribute(k, v) { this.attrs.set(k, String(v)); }
  hasAttribute(k) { return this.attrs.has(k); }
  removeAttribute(k) { this.attrs.delete(k); }
  get id() { return this.getAttribute('id') || ''; }
  get className() { return this.getAttribute('class') || ''; }
  get name() { return this.getAttribute('name') || ''; }
  get type() { return this.tag === 'textarea' ? 'textarea' : this.tag === 'input' ? (this.getAttribute('type') || 'text').toLowerCase() : ''; }
  get value() { return this._value !== undefined ? this._value : (this.tag === 'textarea' ? this.textContent : this.getAttribute('value') || ''); }
  set value(v) { this._value = String(v); }
  get textContent() { return this.childNodes.map((n) => (n instanceof Text ? n.data : n.textContent)).join(''); }
  set textContent(v) { this.childNodes = []; if (v !== '') this.appendChild(new Text(String(v))); }
  get innerText() { return this.textContent; }
  get innerHTML() { return this.childNodes.map((n) => n.outerHTML).join(''); }
  get outerHTML() {
    const a = this.attributes.map(({ name, value }) => ` ${name}="${escAttr(value)}"`).join('');
    return VOID.has(this.tag) ? `<${this.tag}${a}>` : `<${this.tag}${a}>${this.innerHTML}</${this.tag}>`;
  }
  matches(sel) {
    return sel.split(',').some((part) => {
      const m = /^\s*([a-z0-9]*)((?:\[[^\]]+\])*)\s*$/i.exec(part);
      if (!m) throw new Error('fake DOM: unsupported selector ' + part);
      if (m[1] && m[1].toLowerCase() !== this.tag) return false;
      for (const [, attr] of m[2].matchAll(/\[([^\]=]+)\]/g)) if (!this.attrs.has(attr)) return false;
      return true;
    });
  }
  closest(sel) { for (let n = this; n instanceof El; n = n.parentNode) if (n.matches(sel)) return n; return null; }
  querySelectorAll(sel) {
    const out = [];
    const walk = (n) => { for (const c of n.children) { if (c.matches(sel)) out.push(c); walk(c); } };
    walk(this); return out;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  cloneNode(deep) {
    const c = new El(this.tag, Object.fromEntries(this.attrs));
    if (deep) for (const k of this.childNodes) c.appendChild(k instanceof Text ? new Text(k.data) : k.cloneNode(true));
    return c;
  }
}
const h = (tag, attrs, ...kids) => new El(tag, attrs || {}, kids);

function runRecorder({ page, href, maskScript = src }) {
  const listeners = {}; const sent = [];
  let observerCb = null;
  const body = page.querySelector('body');
  const document = {
    documentElement: page, body, title: 'T',
    addEventListener: (t, fn) => { (listeners['doc:' + t] ||= []).push(fn); },
    querySelector: (s) => page.querySelector(s), querySelectorAll: (s) => page.querySelectorAll(s),
    implementation: { createHTMLDocument: () => ({ importNode: (n, deep) => n.cloneNode(deep), createElement: (t) => new El(t) }) },
    importNode: (n, deep) => n.cloneNode(deep),
  };
  const sandbox = {
    document, location: { href }, innerWidth: 800, innerHeight: 600, scrollX: 0, scrollY: 0,
    navigator: { sendBeacon: (_u, body) => { sent.push(String(body)); return true; } },
    addEventListener: (t, fn) => { (listeners['win:' + t] ||= []).push(fn); },
    setInterval: () => 0, setTimeout: (f) => { f(); return 0; }, clearTimeout: () => {},
    MutationObserver: class { constructor(cb) { observerCb = cb; } observe() {} },
  };
  sandbox.window = sandbox;
  vm.runInNewContext(maskScript, sandbox);
  const fire = (key, ev) => { for (const fn of listeners[key] || []) fn(ev); };
  return {
    sent,
    input(target) { fire('doc:input', { target }); },
    click(target) { fire('doc:click', { target, clientX: 1, clientY: 2 }); },
    setAttr(target, name, value) { target.setAttribute(name, value); observerCb([{ type: 'attributes', target, attributeName: name }]); },
    unload() { fire('win:beforeunload', {}); },
  };
}

// ─── an ordinary page records exactly as before ──────────────────────
{
  const note = h('textarea', { name: 'body' }, 'ORDINARY-NOTE');
  const page = h('html', {}, h('head', {}, h('title', {}, 'Notes')), h('body', {},
    h('h1', { class: 'title' }, 'ORDINARY-TEXT'), h('input', { name: 'title', value: 'ORDINARY-VALUE' }), note,
    h('a', { href: '/notes?id=5&q=ORDINARY-QUERY' }, 'open')));
  const before = page.outerHTML;
  const r = runRecorder({ page, href: 'https://app.test/notes?id=5&q=ORDINARY-QUERY' });
  note.value = 'TYPED-TEXT'; r.input(note);
  r.click(page.querySelector('a'));
  r.unload();
  const events = r.sent.flatMap((b) => JSON.parse(b).events);
  const snaps = events.filter((e) => e.type === 'snapshot');
  if (snaps.length !== 2) failures.push('ordinary page: expected two snapshots, got ' + snaps.length);
  for (const s of snaps) {
    if (s.data.html !== before) failures.push('ordinary page: snapshot html changed:\n' + s.data.html + '\nwant\n' + before);
    if (s.data.url !== 'https://app.test/notes?id=5&q=ORDINARY-QUERY') failures.push('ordinary page: url changed: ' + s.data.url);
  }
  const inp = events.find((e) => e.type === 'input');
  if (!inp || inp.data.value !== 'TYPED-TEXT') failures.push('ordinary page: input value not recorded: ' + JSON.stringify(inp));
  const clk = events.find((e) => e.type === 'click');
  if (!clk || clk.data.href !== '/notes?id=5&q=ORDINARY-QUERY' || clk.data.text !== 'open') failures.push('ordinary page: click changed: ' + JSON.stringify(clk));
}

// ─── a page carrying secrets ─────────────────────────────────────────
{
  const code = h('code', { class: 'tok' }, 'SECRET-TOKEN-ONE');
  const otpInput = h('input', { name: 'code', value: '' });
  const pw = h('input', { type: 'password', name: 'pw', value: 'PW-ATTR-TWO' });
  const page = h('html', {}, h('head', {}), h('body', {},
    h('p', {}, 'ORDINARY-TEXT'),
    h('div', { 'data-bm-mask': '', class: 'panel' }, code, otpInput, h('img', { src: 'data:image/png;base64,QRPIXELS', alt: 'QR' })),
    h('span', { 'data-bm-sensitive': '' }, h('span', {}, 'REVEALED-THREE')),
    pw,
    h('input', { name: 'api_token', value: 'TOKEN-ATTR-FOUR' }),
    h('img', { src: 'https://qr.example/?data=otpauth%3A%2F%2Ftotp%2Fx%3Fsecret%3DOTPSECRETFIVE' }),
    h('a', { href: 'otpauth://totp/App:a@b.test?secret=OTPSECRETSIX&issuer=App' }, 'add to app'),
  ));
  const r = runRecorder({ page, href: 'https://app.test/reset-password?token=RESETTOKENSEVEN&next=%2Fhome' });
  otpInput.value = 'TYPED-CODE-EIGHT'; r.input(otpInput);
  r.setAttr(pw, 'value', 'PW-MUTATION-NINE');
  r.setAttr(otpInput, 'value', 'VALUE-IN-MASK-TEN');
  r.click(code);
  r.unload();
  const all = r.sent.join('\n');
  for (const secret of ['SECRET-TOKEN-ONE', 'PW-ATTR-TWO', 'REVEALED-THREE', 'TOKEN-ATTR-FOUR', 'OTPSECRETFIVE', 'OTPSECRETSIX', 'RESETTOKENSEVEN', 'TYPED-CODE-EIGHT', 'PW-MUTATION-NINE', 'VALUE-IN-MASK-TEN', 'QRPIXELS']) {
    if (all.includes(secret)) failures.push(`secret page: ${secret} reached the recording`);
  }
  if (!all.includes('ORDINARY-TEXT')) failures.push('secret page: ordinary text missing from the snapshot');
  if (!all.includes('next=%2Fhome')) failures.push('secret page: ordinary query parameter was masked');
  if (!all.includes('data-bm-mask')) failures.push('secret page: masked block lost its marker');
  // The live page itself is untouched.
  if (code.textContent !== 'SECRET-TOKEN-ONE' || pw.getAttribute('value') !== 'PW-MUTATION-NINE') failures.push('secret page: the recorder modified the live DOM');
}

if (failures.length) { console.error(failures.join('\n')); process.exit(1); }
console.log('all recorder masking assertions passed');
