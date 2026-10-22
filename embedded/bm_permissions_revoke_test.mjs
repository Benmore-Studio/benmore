import assert from 'node:assert/strict';
import bm from './bm.js';
const fetchHTTP = globalThis.fetch;
let actor = process.env.BM_TEST_OWNER;
globalThis.document = {querySelector: () => null};
globalThis.fetch = (path, init = {}) => fetchHTTP(new URL(path, process.env.BM_TEST_URL), {
  ...init, headers: {...init.headers, Authorization: `Bearer ${actor}`},
});
const email = 'reader+files/test@example.test';
await bm.permissions.share('notes', 1, email, 'view');
actor = process.env.BM_TEST_READER;
assert.equal((await bm.table('notes').get(1)).title, 'First private note');
actor = process.env.BM_TEST_OWNER;
const listed = await bm.permissions.list('notes', 1);
assert.equal(listed.resource_id, '1');
assert.equal(listed.resource_type, 'notes');
assert.equal(listed.permissions.length, 1);
const grant = listed.permissions[0];
assert.deepEqual(Object.keys(grant).sort(), ['expires_at', 'granted_at', 'grantee_id', 'id', 'permission']);
assert.equal(typeof grant.id, 'number');
assert.equal(grant.grantee_id, email);
assert.equal(grant.permission, 'view');
assert.equal(typeof grant.granted_at, 'string');
assert.equal(grant.expires_at, null);
actor = process.env.BM_TEST_READER;
await assert.rejects(() => bm.permissions.list('notes', 1));
actor = process.env.BM_TEST_OWNER;
// Rendered share managers must revoke using the recipient actually listed.
assert.equal((await bm.permissions.revoke('notes', 1, grant.grantee_id)).status, 'revoked');
assert.equal((await bm.permissions.list('notes', 1)).permissions?.length ?? 0, 0);
actor = process.env.BM_TEST_READER;
await assert.rejects(() => bm.table('notes').get(1));
console.log('permission SDK round trip passed');
