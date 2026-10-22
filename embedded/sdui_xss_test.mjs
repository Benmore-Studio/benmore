// Row-data escaping test for embedded/sdui.js. Run via
// `node embedded/sdui_xss_test.mjs` (invoked from the Go test
// TestEmbeddedSDUIRowDataEscaping). Exits non-zero on the first run with a
// finding.
//
// Every exported component is mounted on a fake DOM that logs each HTML
// write, with the network mocked so every string a table, API or option
// hands back is attacker text: an element (<img ... id=ROWXSS>), an attribute
// breakout (" data-rowattr="1") and, for URL-shaped keys, javascript:. Rows
// are written by other users, so none of it may reach markup unescaped, and no
// script URL may reach an href, form action or iframe src.
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const bmURL = url.pathToFileURL(path.join(here, 'bm.js')).href;
const sduiSrc = fs.readFileSync(path.join(here, 'sdui.js'), 'utf8').replace("import bm from 'bm';", `import bm from ${JSON.stringify(bmURL)};`);

const TAG = '#" data-rowattr="1"><img src=x id=ROWXSS>';
const JSU = 'javascript:ROWJS()';
// Spellings a browser still runs as script (it drops leading controls and
// any tab/newline, and schemes are case-insensitive).
const scriptURLs = [JSU, ' java\tscript:ROWJS()', 'JaVaScRiPt:ROWJS()', '\u0001javascript:ROWJS()', 'vbscript:ROWJS', 'data:text/html,<b>ROWJS</b>'];
const log = [];
const record = (where, html) => { if (typeof html === 'string') log.push({ where, html }); };

// ─── a minimal inert <template>: enough HTML to exercise RichText ────
// Parses start/end tags, attributes and text (no entities, no raw-text
// elements); serializes the way a browser does (escaped text and attrs).
const escText = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escAttr = (s) => escText(s).replace(/"/g, '&quot;');
class FakeNode {
  constructor(type) { this.nodeType = type; this.childNodes = []; this.parent = null; }
  remove() { if (this.parent) { const i = this.parent.childNodes.indexOf(this); if (i >= 0) this.parent.childNodes.splice(i, 1); this.parent = null; } }
  replaceWith(...nodes) {
    const p = this.parent; if (!p) return;
    const i = p.childNodes.indexOf(this);
    for (const n of nodes) { if (n.parent) n.remove(); n.parent = p; }
    p.childNodes.splice(i, 1, ...nodes); this.parent = null;
  }
}
class FakeText extends FakeNode { constructor(data) { super(3); this.data = data; } }
class FakeElement extends FakeNode {
  constructor(tag) { super(1); this.tagName = tag.toUpperCase(); this.attributes = []; }
  removeAttribute(name) { this.attributes = this.attributes.filter((a) => a.name !== name); }
}
const VOID = new Set(['BR', 'HR', 'IMG', 'INPUT', 'META', 'LINK']);
function parseFragment(html) {
  const root = new FakeNode(11);
  let cur = root;
  const re = /<\/([a-zA-Z0-9]+)\s*>|<([a-zA-Z][a-zA-Z0-9]*)((?:\s+[^\s=>\/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>|([^<]+|<)/g;
  let m;
  while ((m = re.exec(html))) {
    if (m[1]) { let n = cur; while (n !== root && n.tagName !== m[1].toUpperCase()) n = n.parent; if (n !== root) cur = n.parent; continue; }
    if (m[2]) {
      const el = new FakeElement(m[2]);
      const attrRe = /([^\s=>\/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g; let a;
      while ((a = attrRe.exec(m[3] || ''))) el.attributes.push({ name: a[1].toLowerCase(), value: a[2] ?? a[3] ?? a[4] ?? '' });
      el.parent = cur; cur.childNodes.push(el);
      if (!VOID.has(el.tagName)) cur = el;
      continue;
    }
    const t = new FakeText(m[4]); t.parent = cur; cur.childNodes.push(t);
  }
  return root;
}
function serialize(node) {
  return node.childNodes.map((c) => {
    if (c.nodeType === 3) return escText(c.data);
    const attrs = c.attributes.map((a) => ` ${a.name}="${escAttr(a.value)}"`).join('');
    const tag = c.tagName.toLowerCase();
    return VOID.has(c.tagName) ? `<${tag}${attrs}>` : `<${tag}${attrs}>${serialize(c)}</${tag}>`;
  }).join('');
}
function makeTemplate() {
  const t = { content: new FakeNode(11) };
  Object.defineProperty(t, 'innerHTML', { get: () => serialize(t.content), set: (v) => { t.content = parseFragment(String(v)); } });
  return t;
}

// ─── a permissive fake element that logs HTML writes ─────────────────
function makeEl(tag = 'div') {
  if (tag === 'template') return makeTemplate();
  const store = { innerHTML: '', attrs: {}, style: new Proxy({}, { set: () => true, get: () => '' }) };
  const noop = () => {};
  return new Proxy(store, {
    get(t, p) {
      switch (p) {
        case 'innerHTML': case 'outerHTML': return t.innerHTML;
        case 'style': return t.style;
        case 'querySelector': return () => makeEl();
        case 'querySelectorAll': return () => [];
        case 'closest': case 'parentElement': case 'parentNode': case 'files': return p === 'closest' ? () => null : null;
        case 'addEventListener': case 'removeEventListener': case 'focus': case 'blur': case 'click': case 'remove':
        case 'scrollIntoView': case 'select': case 'dispatchEvent': case 'setPointerCapture': return noop;
        case 'appendChild': case 'append': case 'prepend': case 'insertBefore': case 'replaceChildren': case 'before': case 'after': return (c) => c;
        case 'insertAdjacentHTML': return (_pos, h) => record('insertAdjacentHTML', h);
        case 'setAttribute': return (k, v) => { t.attrs[k] = v; if (/^(href|src|action|formaction)$/i.test(k)) record('setAttribute', `<${tag} ${k}="${v}">`); };
        case 'getAttribute': return (k) => t.attrs[k] ?? null;
        case 'hasAttribute': return (k) => k in t.attrs;
        case 'removeAttribute': return (k) => { delete t.attrs[k]; };
        case 'classList': return { add: noop, remove: noop, toggle: noop, contains: () => false };
        case 'children': case 'childNodes': return [];
        case 'dataset': return {};
        case 'getBoundingClientRect': return () => ({ top: 0, left: 0, width: 100, height: 20, right: 100, bottom: 20 });
        case 'getContext': return () => null;
        case 'tagName': return tag.toUpperCase();
        case 'value': return t.value ?? '';
        case 'textContent': return t.textContent ?? '';
        case 'offsetWidth': case 'clientWidth': case 'scrollHeight': return 100;
        default: return t[p];
      }
    },
    set(t, p, v) {
      if (p === 'innerHTML' || p === 'outerHTML') { t.innerHTML = String(v); record('innerHTML', t.innerHTML); return true; }
      if (p === 'href' || p === 'src' || p === 'action') record('property', `<${tag} ${p}="${v}">`);
      t[p] = v; return true;
    },
  });
}

// ─── browser globals ─────────────────────────────────────────────────
const noop = () => {};
globalThis.window = globalThis;
globalThis.addEventListener = noop; globalThis.removeEventListener = noop;
globalThis.location = { href: 'https://app.test/', search: '', hash: '', origin: 'https://app.test', protocol: 'https:', host: 'app.test', hostname: 'app.test', pathname: '/', assign: noop, replace: noop, reload: noop };
globalThis.document = {
  querySelector: () => null, querySelectorAll: () => [], getElementById: () => null,
  createElement: (t) => makeEl(t), createElementNS: (_n, t) => makeEl(t), createTextNode: () => makeEl(),
  head: makeEl('head'), body: makeEl('body'), documentElement: makeEl('html'),
  addEventListener: noop, removeEventListener: noop, execCommand: noop, cookie: '',
};
globalThis.getComputedStyle = () => ({ position: 'relative', getPropertyValue: () => '' });
globalThis.matchMedia = () => ({ matches: false, addEventListener: noop, removeEventListener: noop });
globalThis.requestAnimationFrame = (f) => setTimeout(f, 0);
for (const n of ['MutationObserver', 'ResizeObserver', 'IntersectionObserver']) globalThis[n] = class { observe() {} disconnect() {} unobserve() {} };
globalThis.EventSource = class { addEventListener() {} close() {} };
globalThis.WebSocket = class { constructor() { this.readyState = 0; } send() {} close() {} addEventListener() {} };
globalThis.CSS = { escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => '\\' + c) };
const memStore = () => { const m = new Map(); return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), key: () => null, get length() { return m.size; } }; };
globalThis.localStorage = memStore(); globalThis.sessionStorage = memStore();
try { Object.defineProperty(globalThis, 'navigator', { value: { sendBeacon: noop, clipboard: { writeText: noop }, language: 'en' }, configurable: true }); } catch (_) {}
globalThis.alert = noop; globalThis.confirm = () => true; globalThis.prompt = () => '';
globalThis.open = () => null;

// ─── attacker-written rows and API responses ─────────────────────────
const today = new Date().toISOString().slice(0, 10); // Calendar shows the current month
const urlKey = /(url|href|website|link|src|file|attachment|document|photo|image|avatar|logo)/i;
function evilRow(id) {
  const keys = ['title', 'name', 'label', 'email', 'user_email', 'body', 'message', 'text', 'summary', 'description', 'status', 'state', 'stage', 'kind', 'type',
    'notes', 'company', 'subtitle', 'website', 'url', 'href', 'attachment', 'file', 'photo', 'image', 'avatar_url', 'fileUrl', 'src', 'caption', 'events', 'event',
    'scopes', 'user_agent', 'ip', 'version', 'error', 'grantee_id', 'permission', 'role', 'provider', 'content', 'comment', 'detail', 'hint', 'group', 'category', 'owner',
    'assignee', 'priority', 'tags', 'key', 'value', 'plan', 'color', 'icon', 'username'];
  const r = { id, user_id: 2, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', due: today, date: today, start: '2026-01-01', end: '2026-01-05', amount: 5 };
  keys.forEach((k, i) => { r[k] = urlKey.test(k) ? scriptURLs[(i + id) % scriptURLs.length] : TAG; });
  return r;
}
const rows = [evilRow(1), evilRow(2)];
const fields = [['id', 'hidden'], ['title', 'text'], ['name', 'text'], ['website', 'url'], ['attachment', 'file'], ['photo', 'image'], ['status', 'text'],
  ['amount', 'number'], ['due', 'date'], ['email', 'email'], ['notes', 'textarea'], ['body', 'textarea'], ['url', 'url'], ['document', 'file']];
const schemaDoc = { tables: { things: { name: 'things', label: 'Things', fields: fields.map(([name, control]) => ({ name, control, label: name, writable: true })), ops: { create: true, read: true, update: true, delete: true }, children: [] } } };
function respond(u, init) {
  const parsed = new URL(u, 'https://app.test');
  const p = parsed.pathname;
  if (p === '/api/_schema') return schemaDoc;
  // The server renders Markdown through its sanitizer; mirror its escaping.
  if (p === '/_internal/markdown') return { __text: escText(JSON.parse(init.body).text) };
  if (p === '/_internal/flows.json') return [];
  if (parsed.searchParams.has('count')) return { count: 2 };
  if (p === '/api/_auth/profile') return { id: 2, email: TAG, roles: ['admin'], role: 'admin' };
  if (p.startsWith('/api/_auth/oauth-providers')) return [{ provider: TAG, token_storage: true }];
  if (p.startsWith('/api/_auth/oauth-tokens')) return [{ provider: TAG }];
  if (p.includes('/lock')) return { locked: true, user_email: TAG, user_id: 3 };
  if (p.startsWith('/api/_usage')) return { metrics: { [TAG]: TAG } };
  if (/^\/api\/things\/\d+$/.test(p)) return rows[0];
  return rows;
}
globalThis.fetch = async (u, init = {}) => {
  const data = respond(String(u), init);
  const text = data && data.__text !== undefined ? data.__text : JSON.stringify(data);
  const ct = data && data.__text !== undefined ? 'text/html' : 'application/json';
  return { ok: true, status: 200, headers: { get: (h) => (h.toLowerCase() === 'content-type' ? ct : null) }, text: async () => text, json: async () => JSON.parse(text), clone() { return this; } };
};

const sdui = await import('data:text/javascript;base64,' + Buffer.from(sduiSrc).toString('base64'));

const items = rows.map((r) => ({ ...r, label: TAG, title: TAG, href: JSU, fileUrl: JSU, src: JSU, caption: TAG, hint: TAG, group: TAG, done: false }));
const opts = {
  table: 'things', id: 1, slug: 'room', items, images: items, groupBy: 'status', dateField: 'due', startField: 'start', endField: 'end', field: 'title',
  stageField: 'status', stages: [TAG], titleField: 'title', labelField: 'title', text: TAG, value: TAG, code: TAG, before: rows[0], after: { ...rows[1], title: 'changed' },
  plans: rows, features: ['title', 'website'], users: rows, commands: [{ label: TAG, hint: TAG, run: noop }], nav: items, steps: items.map((i) => ({ ...i, content: 'step' })),
  // Tabs/Wizard content is documented as developer HTML, not row data.
  tabs: [{ label: TAG, content: 'tab' }], data: rows.map(() => ({ x: TAG, y: TAG, value: TAG })), url: JSU, colorField: 'color', markers: [{ lat: 1, lng: 1, label: TAG }],
  urlField: 'url', captionField: 'caption', options: [TAG], bodyField: 'body', nameField: 'name', policyUrl: JSU, redirect: JSU,
};
// Atoms take (text, opts) rather than a mount target; they are covered below.
const notComponents = new Set(['schema', 'clearSchemaCache', 'registerSkin', 'resetSkin', 'setAccent', 'query', 'can', 'hasRole', 'Toast', 'Lightbox', 'Badge', 'Avatar', 'Spinner', 'Skeleton', 'ProgressBar', 'Kbd', 'Sparkline']);

const failures = [];
const rendered = new Set();
function scan(name, from) {
  for (const { where, html } of log.slice(from)) {
    if (html.includes('ROWXSS')) rendered.add(name);
    // An element, or an attribute inside a tag (a quote in text is fine).
    const brk = /<[^<>]*\sdata-rowattr="1"/.exec(html);
    const bad = html.indexOf('<img src=x id=ROWXSS>') >= 0 ? html.indexOf('<img src=x id=ROWXSS>') : (brk ? brk.index : -1);
    if (bad >= 0) failures.push(`${name}: row text reached markup unescaped (${where}): …${html.slice(Math.max(0, bad - 100), bad + 40)}…`);
    // Every mocked script URL carries ROWJS; a blocked one no longer does.
    const js = /\s(href|action|formaction)\s*=\s*"[^"]*ROWJS|<iframe[^>]*\ssrc\s*=\s*"[^"]*ROWJS/i.exec(html);
    if (js) failures.push(`${name}: script URL reached a navigation attribute (${where}): …${html.slice(Math.max(0, js.index - 60), js.index + 60)}…`);
  }
}
for (const [name, fn] of Object.entries(sdui)) {
  if (typeof fn !== 'function' || notComponents.has(name)) continue;
  const from = log.length;
  try {
    const p = fn(makeEl(), { ...opts });
    if (p && typeof p.then === 'function') await Promise.race([p.catch(() => {}), new Promise((r) => setTimeout(r, 300))]);
  } catch (_) { /* a component that needs a shape this mock lacks; coverage is asserted below */ }
  await new Promise((r) => setTimeout(r, 5));
  scan(name, from);
}
// Atoms.
for (const [name, html] of [['Badge', sdui.Badge(TAG)], ['Avatar', sdui.Avatar({ name: TAG, src: JSU })], ['ProgressBar', sdui.ProgressBar(5, { label: TAG })]]) {
  record(name, html); scan(name, log.length - 1);
}
// RichText keeps formatting but drops script and handlers from stored HTML.
{
  const el = makeEl();
  sdui.RichText(el, { value: '<b onclick="x()">bold</b><img src=x onerror=alert(1)><a href="javascript:alert(1)">l</a><a href="https://ok.test/">ok</a><svg onload=alert(1)><script>alert(1)</script></svg><section>kept</section>' });
  const h = el.innerHTML;
  const want = '<b>bold</b><a>l</a><a href="https://ok.test/">ok</a>kept';
  if (!h.includes(want)) failures.push(`RichText: stored HTML not reduced to formatting: ${h}`);
  if (/onerror|onclick|onload|<script|<svg|<img|javascript:/i.test(h)) failures.push(`RichText: active content survived: ${h}`);
}

// RecordLock builds /api/{table}/{id}/lock and POSTs/DELETEs it. An id taken
// from the page URL must not move that request to another endpoint: '..'
// segments, or a '?' that turns '/lock' into a query string.
{
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u, init = {}) => { sent.push(new URL(String(u), 'https://app.test/').pathname); return realFetch(u, init); };
  try {
    for (const bad of ['../_auth/api-tokens/7?', '..', '7?', '7#', '.\t./x', 'a/b']) {
      sent.length = 0;
      try { await sdui.RecordLock(makeEl(), { table: 'things', id: bad }); } catch (_) {}
      for (const p of sent) if (!/^\/api\/things\/[^/]+\/lock$/.test(p)) failures.push(`RecordLock(${JSON.stringify(bad)}): request left the row's lock endpoint: ${p}`);
    }
    for (const good of [7, 'b7e1c2d0-0000-4000-8000-000000000000']) {
      sent.length = 0;
      await sdui.RecordLock(makeEl(), { table: 'things', id: good });
      if (sent.join() !== `/api/things/${good}/lock`) failures.push(`RecordLock(${JSON.stringify(good)}): sent ${sent.join(' ')}`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
}

// Secrets the components show the user once (a TOTP secret, a new API token)
// sit inside [data-bm-mask], so the session recorder never records them.
{
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u, init = {}) => {
    const p = new URL(String(u), 'https://app.test/').pathname;
    const body = p === '/api/_auth/mfa/setup' ? { secret: 'MFASECRETVALUE', otpauth_uri: 'otpauth://totp/x?secret=MFASECRETVALUE' }
      : p === '/api/_auth/profile' ? { id: 2, email: 'a@b.test', mfa_enabled: false } : null;
    if (!body) return realFetch(u, init);
    return { ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => JSON.stringify(body) };
  };
  try {
    await (await import(bmURL)).default.auth.refreshMe(); // drop the cached profile
    const el = makeEl();
    await sdui.MfaSetup(el, {});
    // Enrollment waits for the password form's submit, which this fake DOM
    // can't fire (TestSDUIMfaSetupEnrollsWithPasswordAndShowsBackupCodes
    // drives it); nothing secret may render before it.
    if (/MFASECRETVALUE/.test(el.innerHTML)) failures.push(`MfaSetup: enrolled before the password was confirmed: ${el.innerHTML}`);
  } finally {
    globalThis.fetch = realFetch;
  }
  for (const [what, re] of [['TOTP secret', /<code data-bm-mask[^\n]*esc\(res\.secret/], ['otpauth URI', /<code data-bm-mask[^\n]*esc\(res\.otpauth_uri\)/], ['backup codes', /<code data-bm-mask[^\n]*codes\.map\(esc\)/]]) {
    if (!re.test(sduiSrc)) failures.push(`MfaSetup: ${what} not inside [data-bm-mask]`);
  }
  // The new-token modal only opens on submit, which this fake DOM can't fire.
  if (!/Modal\(\{ title: 'Copy your token now[^\n]*<code data-bm-mask[^\n]*esc\(r\.token\)/.test(sduiSrc)) failures.push('ApiTokenManager: new token not inside [data-bm-mask]');
}

// Guard against a silent pass: these components must actually have rendered
// the attacker rows (escaped) for the scan above to mean anything.
const mustRender = ['DataTable', 'Cards', 'Board', 'Detail', 'RecordForm', 'Chat', 'CommentThread', 'ActivityFeed', 'NotificationBell', 'SessionManager', 'GanttChart', 'Heatmap', 'Checklist', 'Calendar', 'KnowledgeBase', 'Slider', 'NumberStepper', 'Badge'];
for (const n of mustRender) if (!rendered.has(n)) failures.push(`${n}: never rendered the mocked rows; the harness no longer exercises it`);

if (failures.length) { console.error(failures.join('\n')); process.exit(1); }
console.log(`all sdui row-data escaping assertions passed (${rendered.size} components rendered attacker rows)`);
// Pollers and live subscriptions the components started keep the loop alive.
process.exit(0);
