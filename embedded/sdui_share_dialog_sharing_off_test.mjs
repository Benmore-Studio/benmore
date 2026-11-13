// ShareDialog on a table whose record sharing is turned off: the dialog says
// so in place of its form, keeps stored grants revocable, and never sends a
// share request it knows will be refused.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import bm from './bm.js';

const fetchHTTP = globalThis.fetch;
let credential = process.env.BM_TEST_OWNER;
// older: answer as a runtime that predates the switch's reporting would (no
// `capabilities.sharing` in the descriptor, no `sharing`/`active` in the
// list); the share request is still refused by the real server.
let older = false;
const requests = [];
globalThis.document = { querySelector: () => null, getElementById: () => ({}) };
globalThis.fetch = async (path, init = {}) => {
  const url = new URL(path, process.env.BM_TEST_URL);
  const headers = new Headers(init.headers); headers.set('Authorization', `Bearer ${credential}`);
  const response = await fetchHTTP(url, { ...init, headers });
  requests.push({ method: (init.method || 'GET').toUpperCase(), path: url.pathname, status: response.status });
  if (!older || !response.ok) return response;
  if (url.pathname === '/api/_schema') {
    const body = await response.json();
    for (const t of Object.values(body.tables || {})) delete t.capabilities.sharing;
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  if (url.pathname.endsWith('/permissions')) {
    const body = await response.json();
    delete body.sharing;
    for (const p of body.permissions || []) delete p.active;
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  return response;
};
// The dialog reads its form through FormData; the fixture form carries the values.
globalThis.FormData = class { constructor(form) { this.form = form; } get(name) { return this.form.values[name]; } };
const source = fs.readFileSync(new URL('./sdui.js', import.meta.url), 'utf8')
  .replace("import bm from 'bm';", `import bm from ${JSON.stringify(new URL('./bm.js', import.meta.url).href)};`);
const { ShareDialog, schema, clearSchemaCache } = await import('data:text/javascript;base64,' + Buffer.from(source + '\n//# sourceURL=sdui-share-dialog-sharing-off-fixture.js').toString('base64'));

// A mount target that keeps the handlers the dialog attaches, so the test can
// submit the form and click Revoke as a browser would.
const mount = () => {
  const target = {
    html: '', form: null, error: null, revokes: [], retry: null,
    set innerHTML(value) {
      this.html = value;
      this.form = value.includes('<form') ? { values: {}, submit: null, addEventListener(name, handler) { assert.equal(name, 'submit'); this.submit = handler; } } : null;
      this.error = value.includes('data-bm-error') ? { hidden: true, textContent: '' } : null;
      this.revokes = Array.from(value.matchAll(/data-revoke="([^"]*)"/g), match => ({
        id: match[1], click: null, getAttribute() { return match[1]; }, addEventListener(name, handler) { assert.equal(name, 'click'); this.click = handler; },
      }));
      this.retry = value.includes('data-bm-retry') ? { addEventListener() {} } : null;
    },
    get innerHTML() { return this.html; },
    querySelector(selector) { return selector === 'form' ? this.form : selector === '[data-bm-retry]' ? this.retry : selector === '[data-bm-error]' ? this.error : null; },
    querySelectorAll(selector) { assert.equal(selector, '[data-revoke]'); return this.revokes; },
  };
  return target;
};
const offText = 'Sharing is turned off for this table.';
const shareRequests = () => requests.filter(r => r.method === 'POST' && r.path.endsWith('/share')).length;
const until = async (check, what) => {
  for (let i = 0; i < 200; i++) { if (check()) return; await new Promise(resolve => setTimeout(resolve, 10)); }
  assert.fail(`timed out waiting for ${what}`);
};

// The descriptor reports the switch for every table, on or off.
const tables = await schema();
assert.equal(tables.docs.capabilities.sharing, true, 'docs: sharing is on');
assert.equal(tables.tasks.capabilities.sharing, false, 'tasks: sharing is off');
assert.equal(typeof tables.notes.capabilities.sharing, 'boolean', 'every table reports the switch');

// Sharing on: the form, as before.
const docs = mount();
await ShareDialog(docs, { table: 'docs', id: 1 });
assert.ok(docs.form, 'a shared table keeps its form');
assert.ok(!docs.innerHTML.includes(offText));
docs.form.values = { email: 'reader@example.com', permission: 'view' };
await docs.form.submit({ preventDefault() {} });
await until(() => docs.revokes.length === 1, 'the new grant to be listed');
assert.ok(docs.innerHTML.includes('reader@example.com'));
assert.ok(!docs.innerHTML.includes('no access while sharing is off'));

// Sharing off: the state instead of the form, the stored grant still listed
// (marked as giving no access) and revocable, and no share request sent.
const sent = shareRequests();
const tasks = mount();
const handle = await ShareDialog(tasks, { table: 'tasks', id: 1 });
assert.equal(tasks.form, null, 'no form on a table whose sharing is off');
assert.ok(tasks.innerHTML.includes(offText), tasks.innerHTML);
assert.ok(tasks.innerHTML.includes('data-bm-sharing="off"'));
assert.ok(!tasks.innerHTML.includes('role="alert"'), 'the off state is not an error');
assert.ok(!tasks.innerHTML.includes('Not shared with anyone.'));
assert.equal(tasks.revokes.length, 1, 'the stored grant stays listed');
assert.ok(tasks.innerHTML.includes('stored@example.com') && tasks.innerHTML.includes('no access while sharing is off'));
await tasks.revokes[0].click();
await until(() => tasks.revokes.length === 0, 'the revoked grant to leave the list');
assert.ok(tasks.innerHTML.includes(offText) && tasks.form === null, 'still the off state after a revoke');
assert.equal((await bm.permissions.list('tasks', 1)).permissions.length, 0, 'the revoke removed the stored grant');
await handle.refresh();
assert.ok(tasks.innerHTML.includes(offText) && tasks.form === null, 'refresh keeps the off state');
assert.equal(shareRequests(), sent, 'the dialog sent no share request while sharing is off');

// A signed-in account that may not list the row's grants gets the same state
// on that table, not a load error; on a shared table it keeps the load error.
credential = process.env.BM_TEST_READER;
const refusedOff = mount();
await ShareDialog(refusedOff, { table: 'tasks', id: 1 });
assert.equal(requests.filter(r => r.path === '/api/tasks/1/permissions').at(-1).status, 403);
assert.ok(refusedOff.innerHTML.includes(offText) && refusedOff.form === null && refusedOff.revokes.length === 0, refusedOff.innerHTML);
const refusedOn = mount();
await ShareDialog(refusedOn, { table: 'docs', id: 1 });
assert.equal(requests.filter(r => r.path === '/api/docs/1/permissions').at(-1).status, 403);
assert.ok(refusedOn.innerHTML.includes('role="alert"') && refusedOn.retry && !refusedOn.innerHTML.includes(offText), refusedOn.innerHTML);
credential = process.env.BM_TEST_OWNER;

// Answers that do not report the switch: the dialog shows its form, the
// server refuses the share with sharing_disabled, and the dialog moves to the
// same state instead of printing the refusal under the form.
older = true;
clearSchemaCache();
const legacy = mount();
await ShareDialog(legacy, { table: 'tasks', id: 2 });
assert.ok(legacy.form, 'without the switch in the answers the form is shown');
legacy.form.values = { email: 'late@example.com', permission: 'view' };
await legacy.form.submit({ preventDefault() {} });
assert.equal(requests.at(-1).status, 403, 'the server refused the share');
assert.equal(shareRequests(), sent + 1);
assert.equal(legacy.form, null, 'the refusal replaces the form');
assert.ok(legacy.innerHTML.includes(offText), legacy.innerHTML);
assert.ok(legacy.innerHTML.includes('second@example.com') && legacy.revokes.length === 1, 'the grants already listed stay revocable');
older = false;
assert.equal((await bm.permissions.list('tasks', 2)).permissions.length, 1, 'the refused share stored nothing');

// Any other refusal still prints under the form.
const other = mount();
await ShareDialog(other, { table: 'docs', id: 1 });
other.form.values = { email: 'reader@example.com', permission: 'owner' };
await other.form.submit({ preventDefault() {} });
assert.ok(other.form && other.error.hidden === false && other.error.textContent, 'another failure stays under the form');
assert.ok(!other.innerHTML.includes(offText));
console.log('ShareDialog sharing-off state passed');
