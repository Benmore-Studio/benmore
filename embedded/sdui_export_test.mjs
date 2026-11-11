// ExportButton must export every row the caller can read, not the first
// page. Run via `node embedded/sdui_export_test.mjs` from the Go test
// TestSDUIExportButtonExportsEveryRow, which serves a real app at
// BM_TEST_URL with BM_TEST_TOKEN for its owner.
//
// The button asked for ?limit=5000, the list API caps a page at 500 without
// saying so, and a 28k-row table exported as a 500-row CSV.
import assert from 'node:assert/strict';
import fs from 'node:fs';

const fetchHTTP = globalThis.fetch;
const requests = [];
globalThis.fetch = async (path, init = {}) => {
  const url = new URL(path, process.env.BM_TEST_URL);
  requests.push(url.pathname + url.search);
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${process.env.BM_TEST_TOKEN}`);
  return fetchHTTP(url, { ...init, headers });
};

// ─── a minimal DOM: enough for ExportButton, Toast and the download link ───
const toasts = [];
const fakeEl = (tag) => {
  const el = {
    tag, style: {}, attrs: {}, children: [], textContent: '', id: '',
    setAttribute(k, v) { this.attrs[k] = v; if (k === 'data-bm-toast') toasts.push(this); },
    getAttribute(k) { return this.attrs[k]; },
    appendChild(c) { this.children.push(c); return c; },
    addEventListener() {}, remove() {}, click() {},
  };
  let html = '';
  Object.defineProperty(el, 'innerHTML', { get: () => html, set: (v) => { html = v; } });
  return el;
};
const byId = {};
globalThis.document = {
  head: fakeEl('head'), body: fakeEl('body'),
  createElement: (tag) => fakeEl(tag),
  getElementById: (id) => byId[id] || null,
  querySelector: () => null,
};
document.body.appendChild = (c) => { if (c.id) byId[c.id] = c; return c; };
let lastBlob = null;
URL.createObjectURL = (blob) => { lastBlob = blob; return 'blob:test'; };
URL.revokeObjectURL = () => {};

const source = fs.readFileSync(new URL('./sdui.js', import.meta.url), 'utf8')
  .replace("import bm from 'bm';", `import bm from ${JSON.stringify(new URL('./bm.js', import.meta.url).href)};`);
const { ExportButton } = await import('data:text/javascript;base64,' + Buffer.from(source + '\n//# sourceURL=sdui-export-fixture.js').toString('base64'));

// Mounts the button, clicks it and returns the downloaded CSV as rows of
// cells, plus any toast messages the export raised.
async function exportCSV(opts) {
  let onClick;
  const button = { textContent: 'Export CSV', disabled: false, addEventListener: (name, fn) => { assert.equal(name, 'click'); onClick = fn; } };
  const target = fakeEl('div');
  target.querySelector = (sel) => { assert.equal(sel, 'button'); return button; };
  ExportButton(target, opts);
  lastBlob = null; toasts.length = 0; requests.length = 0;
  await onClick();
  assert.equal(button.disabled, false, 'button re-enabled after the export');
  const messages = toasts.map((t) => ({ type: t.attrs['data-bm-toast'], text: t.innerHTML }));
  assert.ok(lastBlob, `no CSV was produced: ${JSON.stringify(messages)}`);
  const lines = (await lastBlob.text()).split('\n');
  const header = lines[0].split(',');
  return { header, rows: lines.slice(1).map((l) => Object.fromEntries(l.split(',').map((v, i) => [header[i], v]))), toasts: messages, requests: [...requests] };
}

// 1. Every row, across the 500-row page cap, and none of another user's.
{
  const { rows, toasts: t } = await exportCSV({ table: 'ledger' });
  assert.equal(rows.length, 1234, `exported ${rows.length} of 1234 rows`);
  assert.equal(new Set(rows.map((r) => r.id)).size, 1234, 'every row exactly once');
  assert.ok(rows.every((r) => r.note !== 'other user'), 'another user\'s rows leaked into the export');
  assert.deepEqual(t.filter((x) => x.type === 'warning' || x.type === 'error'), [], 'a complete export raised no warning');
}

// 2. The caller's filter applies on every page.
{
  const { rows } = await exportCSV({ table: 'ledger', where: { kind: 'in' } });
  assert.equal(rows.length, 617, `filtered export has ${rows.length} rows, want 617`);
  assert.ok(rows.every((r) => r.kind === 'in'), 'filter dropped on a later page');
}

// 3. The bound truncates visibly, never silently.
{
  const { rows, toasts: t } = await exportCSV({ table: 'ledger', maxRows: 600 });
  assert.equal(rows.length, 600);
  const warn = t.find((x) => x.type === 'warning');
  assert.ok(warn, `truncated export raised no warning: ${JSON.stringify(t)}`);
  assert.match(warn.text, /600/);
  assert.match(warn.text, /1,?234/, 'the warning names how many rows there are');
}

// 4. UUID text ids page through the same keyset cursor (starting at 0).
{
  const { rows } = await exportCSV({ table: 'docs' });
  assert.equal(rows.length, 700, `UUID-id export has ${rows.length} of 700 rows`);
  assert.equal(new Set(rows.map((r) => r.id)).size, 700);
  assert.ok(rows.some((r) => r.id.startsWith('00000000-')), 'the lowest id is included');
}

console.log('ExportButton exports every row passed');
process.exit(0);
