// DownloadMyData must download the signed-in user's own data, complete, or
// say that it could not. Run via `node embedded/sdui_my_data_test.mjs` from
// the Go test TestSDUIDownloadMyDataIsTheUsersCompleteExport, which serves a
// real app at BM_TEST_URL. BM_TEST_TOKEN is the owner's session (empty when
// signed out) and BM_TEST_MODE names the case: complete, disabled or
// signed_out.
//
// The component listed every readable table itself with ?limit=1000 (the
// list API caps a page at 500), turned a table that failed into [], and so
// handed over a short file, or one missing tables, without a word. For an
// admin it also exported every row of every table as "my data".
import assert from 'node:assert/strict';
import fs from 'node:fs';

const fetchHTTP = globalThis.fetch;
const requests = [];
globalThis.fetch = async (path, init = {}) => {
  const url = new URL(path, process.env.BM_TEST_URL);
  requests.push(url.pathname + url.search);
  const headers = new Headers(init.headers);
  if (process.env.BM_TEST_TOKEN) headers.set('Authorization', `Bearer ${process.env.BM_TEST_TOKEN}`);
  return fetchHTTP(url, { ...init, headers });
};

// ─── a minimal DOM: enough for the button, Toast and the download link ───
const toasts = [];
const fakeEl = (tag) => {
  const el = {
    tag, style: {}, attrs: {}, children: [], textContent: '', id: '', download: '',
    setAttribute(k, v) { this.attrs[k] = v; if (k === 'data-bm-toast') toasts.push(this); },
    getAttribute(k) { return this.attrs[k]; },
    appendChild(c) { this.children.push(c); return c; },
    addEventListener() {}, remove() {}, click() { downloads.push(this.download); },
  };
  let html = '';
  Object.defineProperty(el, 'innerHTML', { get: () => html, set: (v) => { html = v; } });
  return el;
};
const downloads = [];
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
const { DownloadMyData } = await import('data:text/javascript;base64,' + Buffer.from(source + '\n//# sourceURL=sdui-my-data-fixture.js').toString('base64'));

let onClick;
const button = { textContent: 'Download my data', disabled: false, addEventListener: (name, fn) => { assert.equal(name, 'click'); onClick = fn; } };
const target = fakeEl('div');
target.querySelector = (sel) => { assert.equal(sel, 'button'); return button; };
await DownloadMyData(target, {});
await onClick();
assert.equal(button.disabled, false, 'button re-enabled after the export');
const messages = toasts.map((t) => ({ type: t.attrs['data-bm-toast'], text: t.innerHTML }));
const problems = messages.filter((x) => x.type === 'warning' || x.type === 'error');

switch (process.env.BM_TEST_MODE) {
  case 'complete': {
    assert.deepEqual(requests, ['/api/_my-data'], 'the export is the server-side my-data export, in one request');
    assert.deepEqual(problems, [], 'a complete export raised no warning');
    assert.ok(lastBlob, `no file was produced: ${JSON.stringify(messages)}`);
    assert.deepEqual(downloads, ['my-data.json']);
    const out = JSON.parse(await lastBlob.text());
    assert.equal(out.email, 'exporter@example.com');
    assert.equal(out.profile?.email, 'exporter@example.com', 'the profile is in the file');
    assert.ok(!('password_hash' in out.profile), 'no credential column in the profile');
    assert.equal(out.tables.ledger.length, 1234, `exported ${out.tables.ledger.length} of the user's 1234 ledger rows`);
    assert.equal(new Set(out.tables.ledger.map((r) => r.id)).size, 1234, 'every ledger row exactly once');
    assert.ok(out.tables.ledger.every((r) => r.user_id === out.user_id && r.note !== 'other user'), 'another user\'s rows are not "my data"');
    assert.equal(out.tables.docs.length, 700, `exported ${out.tables.docs.length} of the user's 700 docs`);
    assert.ok(Array.isArray(out.audit_log), 'the audit events are in the file');
    break;
  }
  case 'disabled': {
    assert.equal(lastBlob, null, 'no file when exports are turned off');
    assert.equal(problems.length, 1, `want one error: ${JSON.stringify(messages)}`);
    assert.equal(problems[0].type, 'error');
    assert.match(problems[0].text, /not downloaded/);
    assert.match(problems[0].text, /turned off/);
    break;
  }
  case 'signed_out': {
    assert.equal(lastBlob, null, 'no file without a signed-in user');
    assert.equal(problems.length, 1, `want one error: ${JSON.stringify(messages)}`);
    assert.match(problems[0].text, /not downloaded/);
    assert.match(problems[0].text, /authentication required/);
    break;
  }
  default:
    throw new Error('unknown BM_TEST_MODE ' + process.env.BM_TEST_MODE);
}

console.log(`DownloadMyData ${process.env.BM_TEST_MODE} passed`);
process.exit(0);
