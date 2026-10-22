// A denied native ACL request must never be presented as an empty sharing list.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import bm from './bm.js';

const fetchHTTP = globalThis.fetch;
let credential = process.env.BM_TEST_OWNER, transportError = '', holdNext = null;
const deferNextList = () => {
  let start, release;
  const started = new Promise(resolve => { start = resolve; });
  const held = new Promise(resolve => { release = resolve; });
  holdNext = { start, held };
  return { started, release };
};
const responses = [];
globalThis.document = { querySelector: () => null, getElementById: () => ({}) };
globalThis.fetch = async (path, init = {}) => {
  if (transportError) throw new Error(transportError);
  const url = new URL(path, process.env.BM_TEST_URL);
  const hold = url.pathname.endsWith('/permissions') ? holdNext : null;
  if (hold) holdNext = null;
  const headers = new Headers(init.headers); headers.set('Authorization', `Bearer ${credential}`);
  const response = await fetchHTTP(url, { ...init, headers });
  responses.push({ path, status: response.status });
  if (hold) { hold.start(response.status); await hold.held; }
  return response;
};
const source = fs.readFileSync(new URL('./sdui.js', import.meta.url), 'utf8')
  .replace("import bm from 'bm';", `import bm from ${JSON.stringify(new URL('./bm.js', import.meta.url).href)};`);
const { ShareDialog } = await import('data:text/javascript;base64,' + Buffer.from(source + '\n//# sourceURL=sdui-permissions-errors-fixture.js').toString('base64'));
const form = { addEventListener() {} }, error = { hidden: true };
const target = {
  html: '', buttons: [], retry: null,
  set innerHTML(value) {
    this.html = value;
    this.buttons = Array.from(value.matchAll(/data-revoke="([^"]*)"/g), match => ({
      getAttribute() { return match[1]; }, addEventListener() {},
    }));
    this.retry = value.includes('data-bm-retry') ? { click: null, addEventListener(name, handler) { assert.equal(name, 'click'); this.click = handler; } } : null;
  },
  get innerHTML() { return this.html; },
  querySelector(selector) { return selector === '[data-bm-retry]' ? this.retry : selector === 'form' ? form : error; },
  querySelectorAll(selector) { assert.equal(selector, '[data-revoke]'); return this.buttons; },
};
const recipient = 'reader+files/test@example.test';
await bm.permissions.share('notes', 1, recipient, 'view');
const original = (await bm.permissions.list('notes', 1)).permissions[0];
const handle = await ShareDialog(target, { table: 'notes', id: 1 });
assert.equal(target.buttons.length, 1);
assert.ok(target.innerHTML.includes(recipient));
const failed = status => {
  assert.equal(responses.at(-1).status, status);
  assert.ok(target.innerHTML.includes('role="alert"'), `${status} must display a load error`);
  assert.ok(!target.innerHTML.includes('Not shared with anyone.'), 'failed load must not assert no grants');
  assert.ok(!target.innerHTML.includes('<form'), 'failed refresh must remove sharing controls');
  assert.equal(target.buttons.length, 0, 'failed refresh must clear stale revoke controls');
  assert.equal(typeof target.retry?.click, 'function');
};
credential = process.env.BM_TEST_READER;
assert.equal((await bm.table('notes').get(1)).id, 1, 'view grantee positive control can read row');
await handle.refresh();
failed(403);
credential = process.env.BM_TEST_OWNER;
await target.retry.click();
assert.equal(target.buttons.length, 1, 'retry after recovered authority must reload native grants');
assert.equal((await bm.permissions.list('notes', 1)).permissions[0].id, original.id, 'failed read must preserve grant');
// Deferred responses are real native requests; only delivery to the component waits.
let deferred = deferNextList(), older = handle.refresh();
assert.equal(await deferred.started, 200);
credential = process.env.BM_TEST_READER;
await handle.refresh(); failed(403);
const deniedHTML = target.innerHTML;
deferred.release(); await older;
assert.equal(target.innerHTML, deniedHTML, 'older successful list must not resurrect controls after a newer denial');
assert.equal(target.buttons.length, 0);
deferred = deferNextList(); older = handle.refresh();
assert.equal(await deferred.started, 403);
credential = process.env.BM_TEST_OWNER;
await target.retry.click();
const recoveredHTML = target.innerHTML;
assert.equal(target.buttons.length, 1);
deferred.release(); await older;
assert.equal(target.innerHTML, recoveredHTML, 'older denied list must not overwrite newer successful recovery');
credential = process.env.BM_TEST_READER;
await bm.api.post('/logout', {});
await handle.refresh();
failed(401);
credential = process.env.BM_TEST_OWNER;
await target.retry.click();
assert.equal(target.buttons.length, 1);
assert.equal((await bm.permissions.list('notes', 1)).permissions[0].id, original.id);
await bm.api.delete(`/api/notes/1/share/${original.id}`);
await handle.refresh();
assert.ok(target.innerHTML.includes('Not shared with anyone.'), 'successful empty list retains the real empty state');
assert.equal(target.retry, null);
assert.equal(target.buttons.length, 0);
transportError = '<img src=x onerror="alert(1)">& failure';
await handle.refresh();
assert.ok(target.innerHTML.includes('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&amp; failure'), 'error message must be escaped');
assert.ok(!target.innerHTML.includes('<img'), 'error text must not create markup');
assert.ok(!target.innerHTML.includes('Not shared with anyone.'));
transportError = '';
await target.retry.click();
assert.ok(target.innerHTML.includes('Not shared with anyone.'));
await bm.permissions.share('notes', 1, recipient, 'view');
deferred = deferNextList(); older = handle.refresh();
assert.equal(await deferred.started, 200);
handle.destroy();
assert.equal(target.innerHTML, '');
deferred.release(); await older;
assert.equal(target.innerHTML, '', 'pending success must not resurrect a destroyed dialog');
const requestCount = responses.length;
await handle.refresh();
assert.equal(responses.length, requestCount, 'destroyed refresh must not start another request');
assert.equal(target.innerHTML, '');
console.log('ShareDialog native load errors passed');
