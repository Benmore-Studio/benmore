// Exercise the shipped component and SDK against the real native permission API.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import bm from './bm.js';

const fetchHTTP = globalThis.fetch;
globalThis.document = { querySelector: () => null, getElementById: () => ({}) };
globalThis.fetch = (path, init = {}) => fetchHTTP(new URL(path, process.env.BM_TEST_URL), {
  ...init, headers: { ...init.headers, Authorization: `Bearer ${process.env.BM_TEST_OWNER}` },
});
const source = fs.readFileSync(new URL('./sdui.js', import.meta.url), 'utf8')
  .replace("import bm from 'bm';", `import bm from ${JSON.stringify(new URL('./bm.js', import.meta.url).href)};`);
const { ShareDialog } = await import('data:text/javascript;base64,' + Buffer.from(source + '\n//# sourceURL=sdui-permissions-fixture.js').toString('base64'));

// A small event-capable DOM double; HTTP responses and SDK calls stay real.
const decode = s => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const form = { addEventListener() {} };
const error = { hidden: true };
const target = {
  html: '', buttons: [],
  set innerHTML(value) {
    this.html = value;
    this.buttons = Array.from(value.matchAll(/data-revoke="([^"]*)"/g), match => ({
      target: decode(match[1]), click: null,
      getAttribute(name) { assert.equal(name, 'data-revoke'); return this.target; },
      addEventListener(name, handler) { assert.equal(name, 'click'); this.click = handler; },
    }));
  },
  get innerHTML() { return this.html; },
  querySelector(selector) { return selector === 'form' ? form : error; },
  querySelectorAll(selector) { assert.equal(selector, '[data-revoke]'); return this.buttons; },
};
const recipient = 'reader+files/test@example.test';
await bm.permissions.share('notes', 1, recipient, 'view');
await bm.permissions.share('notes', 2, recipient, 'edit');
const listed = await bm.permissions.list('notes', 1);
assert.equal(listed.permissions.length, 2);
assert.ok(listed.permissions.every(grant => grant.grantee_id === recipient && grant.email === undefined));
const roleID = Math.min(...listed.permissions.map(grant => grant.id)); // authored before native user share
const userID = Math.max(...listed.permissions.map(grant => grant.id));
const handle = await ShareDialog(target, { table: 'notes', id: 1 });
assert.ok(target.innerHTML.includes(recipient), 'ShareDialog must display the recipient returned by native permissions');
assert.equal(target.buttons.length, 2);
assert.deepEqual(target.buttons.map(button => Number(button.target)).sort(), [roleID, userID], 'Revoke must address exact native grant IDs');
await target.buttons.find(button => Number(button.target) === roleID).click();
for (let i = 0; i < 100 && target.buttons.length !== 1; i++) await new Promise(resolve => setTimeout(resolve, 5));
assert.equal(target.buttons.length, 1, 'role grant revoke must refresh the component');
const retained = await bm.permissions.list('notes', 1);
assert.equal(retained.permissions.length, 1);
assert.equal(retained.permissions[0].id, userID, 'role revoke must preserve the same-spelled user grant');
assert.equal(retained.permissions[0].grantee_id, recipient);
await target.buttons[0].click();
for (let i = 0; i < 100 && target.buttons.length; i++) await new Promise(resolve => setTimeout(resolve, 5));
assert.equal(target.buttons.length, 0, 'successful revoke must refresh the component');
assert.ok(target.innerHTML.includes('Not shared with anyone.'));
assert.equal((await bm.permissions.list('notes', 1)).permissions?.length ?? 0, 0);
assert.equal((await bm.permissions.list('notes', 2)).permissions.length, 1, 'revoke must not affect another row');
handle.destroy();
assert.equal(target.innerHTML, '');
for (const invalid of ['.', '..', '']) {
  await assert.rejects(() => ShareDialog(target, { table: 'notes', id: invalid }), /invalid identifier/);
}
console.log('ShareDialog native recipient and revoke passed');
