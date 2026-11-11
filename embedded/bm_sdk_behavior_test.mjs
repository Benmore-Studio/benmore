// Behavioral tests for the bm.createStore + bm.query SDK primitives.
// Run via `node embedded/bm_sdk_behavior_test.mjs` (invoked from the Go test
// TestEmbeddedBMSDKBehavior). Exits non-zero with a message on first failure.
//
// These exercise the real logic rather than grepping for symbols: store
// no-op/shallow-equality suppression, persistence round-trip, query concurrent
// fetch dedupe, stale-time hit/miss, optimistic mutate rollback, and
// invalidate / invalidateTable targeting.

import fs from 'node:fs';
import bm from './bm.js';

let failures = 0;
function ok(cond, msg) {
  if (!cond) { failures++; console.error('FAIL:', msg); }
}
async function section(name, fn) {
  try { await fn(); } catch (e) { failures++; console.error('FAIL (threw):', name, '-', e && e.message); }
}

// Unique key helper so tests don't collide in the shared module-global cache.
let _n = 0;
const uniq = (p) => [p, ++_n, Math.random()];

await section('api: request options preserve CSRF and same-origin credentials', async () => {
  const realFetch = globalThis.fetch;
  const hadDocument = 'document' in globalThis;
  const previousDocument = globalThis.document;
  const calls = [];
  const controller = new AbortController();
  globalThis.document = { querySelector: () => ({ content: 'framework-csrf' }) };
  globalThis.fetch = async (path, init) => {
    calls.push({ path, init });
    return { ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => '{"ok":true}' };
  };
  try {
    const options = {
      headers: { 'Idempotency-Key': 'retry-key', 'X-CSRF-Token': 'caller-csrf', 'Content-Type': 'text/plain' },
      signal: controller.signal,
      credentials: 'omit',
    };
    const raw = await bm.api.raw.post('/api/send', { value: 1 }, options);
    const data = await bm.api.post('/api/send', { value: 2 }, options);
    ok(raw.ok && data.ok, 'raw and convenience requests should both complete');
    for (const { init } of calls) {
      const headers = new Headers(init.headers);
      ok(init.credentials === 'same-origin', 'caller changed credentials mode');
      ok(init.signal === controller.signal, 'AbortSignal was not forwarded');
      ok(headers.get('Idempotency-Key') === 'retry-key', 'custom idempotency header was dropped');
      ok(headers.get('X-CSRF-Token') === 'framework-csrf', 'caller replaced framework CSRF token');
      ok(headers.get('Content-Type') === 'application/json', 'caller replaced automatic JSON content type');
    }
  } finally {
    globalThis.fetch = realFetch;
    if (hadDocument) globalThis.document = previousDocument;
    else delete globalThis.document;
  }
});

await section('store: shallow-equality no-op suppression', () => {
  const s = bm.createStore({ a: 1, b: 2 });
  let calls = 0;
  s.subscribe((st) => st.a, () => { calls++; });
  s.set({ a: 1 });          // no change to a -> no fire
  ok(calls === 0, 'selector fired on no-op set (a unchanged)');
  s.set({ b: 99 });         // b changed but selector tracks a -> no fire
  ok(calls === 0, 'selector fired when unrelated slice changed');
  s.set({ a: 2 });          // a changed -> fire once
  ok(calls === 1, 'selector did not fire on real change, calls=' + calls);
});

await section('store: object patches merge shallowly; non-object rejected', () => {
  const s = bm.createStore({ a: 1, b: 2 });
  s.set({ a: 5 });
  ok(s.get().a === 5 && s.get().b === 2, 'shallow merge lost a key');
  // function returning an array must NOT replace whole state
  s.set(() => [1, 2, 3]);
  ok(!Array.isArray(s.get()) && s.get().a === 5, 'non-object patch replaced state');
});

await section('store: unsubscribe + reset', () => {
  const s = bm.createStore({ a: 1 });
  let calls = 0;
  const off = s.subscribe((st) => st.a, () => { calls++; });
  off();
  s.set({ a: 2 });
  ok(calls === 0, 'listener fired after unsubscribe');
  s.reset();
  ok(s.get().a === 1, 'reset did not restore initial state');
});

await section('store: persistence round-trip', () => {
  // Build a fake namespaced cache by intercepting bm.cache.namespaced.
  const mem = {};
  const realNamespaced = bm.cache.namespaced;
  bm.cache.namespaced = (name) => ({
    get: () => mem[name],
    set: (v) => { mem[name] = v; },
  });
  try {
    const s1 = bm.createStore({ a: 1 }, { persist: { name: 'rt-test', version: 'v0' } });
    s1.set({ a: 42 });
    const s2 = bm.createStore({ a: 1 }, { persist: { name: 'rt-test', version: 'v0' } });
    ok(s2.get().a === 42, 'persisted state not restored, got ' + s2.get().a);
    // malformed (non-object) persisted blob must be ignored, not replace state
    mem['bad-test'] = JSON.stringify([1, 2, 3]);
    const s3 = bm.createStore({ a: 7 }, { persist: { name: 'bad-test', version: 'v0' } });
    ok(s3.get().a === 7 && !Array.isArray(s3.get()), 'malformed persisted blob corrupted state');
  } finally {
    bm.cache.namespaced = realNamespaced;
  }
});

await section('query: concurrent fetch dedupe', async () => {
  const key = uniq('dedupe');
  let calls = 0;
  const fetcher = () => { calls++; return new Promise((r) => setTimeout(() => r('v'), 10)); };
  const p1 = bm.query.fetch(key, fetcher);
  const p2 = bm.query.fetch(key, fetcher);
  const [v1, v2] = await Promise.all([p1, p2]);
  // The dedupe guarantee is that the fetcher runs exactly once and both callers
  // observe the same resolved value (fetch is async so the returned promise
  // objects are wrappers and not reference-equal).
  ok(calls === 1, 'fetcher ran more than once for concurrent fetch, calls=' + calls);
  ok(v1 === 'v' && v2 === 'v', 'concurrent callers got different values');
});

await section('query: concurrent fetch does not clobber fetcher for refetch', async () => {
  const key = uniq('clobber');
  let which = '';
  const f1 = () => new Promise((r) => setTimeout(() => { which = 'f1'; r('a'); }, 10));
  const f2 = () => new Promise((r) => setTimeout(() => { which = 'f2'; r('b'); }, 10));
  const p1 = bm.query.fetch(key, f1);
  const p2 = bm.query.fetch(key, f2); // should be ignored; returns p1
  await Promise.all([p1, p2]);
  which = '';
  await bm.query.refetch(key);
  ok(which === 'f1', 'refetch ran the wrong (later) fetcher: ' + which);
});

await section('query: stale-time hit/miss', async () => {
  const key = uniq('stale');
  let calls = 0;
  const fetcher = () => { calls++; return calls; };
  await bm.query.fetch(key, fetcher, { staleTime: 1000 });
  await bm.query.fetch(key, fetcher, { staleTime: 1000 }); // fresh -> cached, no refetch
  ok(calls === 1, 'stale-time fresh read refetched, calls=' + calls);
  await bm.query.fetch(key, fetcher, { force: true });     // force -> refetch
  ok(calls === 2, 'force did not trigger refetch, calls=' + calls);
});

await section('query: a save invalidates an older in-flight refresh', async () => {
  const key = uniq('save-during-refresh');
  let persisted = { done: false }, releaseOld, calls = 0;
  bm.query.set(key, persisted);
  const fetcher = async () => {
    const snapshot = { ...persisted };
    if (++calls === 1) await new Promise(resolve => { releaseOld = resolve; });
    return snapshot;
  };
  const oldRead = bm.query.fetch(key, fetcher, { force: true });
  await Promise.resolve();
  await bm.query.mutate({ key, apply: () => ({ done: true }),
    request: async () => { persisted = { done: true }; },
    invalidate: key, refetch: true });
  releaseOld();
  await oldRead;
  await new Promise(resolve => setImmediate(resolve));
  ok(calls === 2, 'save reused the pre-save read instead of refetching');
  ok(bm.query.get(key).done === true, 'pre-save response replaced the persisted value in cache');
});

await section('query: old errors cannot clear a replacement pending fetch', async () => {
  const key = uniq('invalidated-error');
  let failOld, finishNew, latest;
  const off = bm.query.subscribe(key, snapshot => { latest = snapshot; });
  const oldRead = bm.query.fetch(key, () => new Promise((resolve, reject) => { failOld = reject; }));
  const oldFailure = oldRead.catch(error => error.message);
  await Promise.resolve();
  bm.query.invalidate(key);
  const newRead = bm.query.fetch(key, () => new Promise(resolve => { finishNew = resolve; }));
  await Promise.resolve();
  failOld(new Error('old response failed'));
  await oldFailure;
  ok(latest.pending && latest.error === null, 'obsolete error cleared/replaced current pending state');
  if (finishNew) finishNew('current');
  try { await newRead; } catch {}
  ok(bm.query.get(key) === 'current', 'replacement request did not publish');
  off();
});

await section('query: explicit set survives an older read completion', async () => {
  const key = uniq('set-during-read');
  let finish;
  const pending = bm.query.fetch(key, () => new Promise(resolve => { finish = resolve; }));
  await Promise.resolve();
  bm.query.set(key, 0);
  finish(42);
  await pending;
  ok(bm.query.get(key) === 0, 'old request overwrote an explicit cached zero');
});

await section('query: optimistic mutate rollback restores prior snapshot', async () => {
  const key = uniq('rollback');
  bm.query.set(key, { n: 1 });
  const before = bm.query.get(key);
  let threw = false;
  try {
    await bm.query.mutate({
      key,
      apply: (cur) => ({ n: (cur ? cur.n : 0) + 1 }),
      request: () => Promise.reject(new Error('boom')),
    });
  } catch { threw = true; }
  ok(threw, 'mutate did not propagate request error');
  ok(bm.query.get(key).n === before.n, 'rollback did not restore prior data');
});

await section('query: invalidate exact + array-prefix (no false positives)', () => {
  const a = ['user', 1];
  const ab = ['user', 1, 'posts'];
  const other = ['username'];
  bm.query.set(a, 'a'); bm.query.set(ab, 'ab'); bm.query.set(other, 'o');
  const hit = bm.query.invalidate(['user']);
  const sk = (k) => bm.query.key(k);
  ok(hit.includes(sk(a)) && hit.includes(sk(ab)), 'array-prefix did not match nested keys');
  ok(!hit.includes(sk(other)), "['user'] wrongly matched ['username']");

  // object exact-match must not match a superset object
  const o1 = { a: 1 };
  const o2 = { a: 1, b: 2 };
  bm.query.set(o1, 1); bm.query.set(o2, 2);
  const hit2 = bm.query.invalidate({ a: 1 });
  ok(hit2.includes(sk(o1)) && !hit2.includes(sk(o2)), '{a:1} wrongly matched {a:1,b:2}');
});

await section('query: table read + invalidateTable targeting', async () => {
  // Stub api.post so table()/read() do not hit the network.
  const realPost = bm.api.post;
  bm.api.post = async () => ({ rows: [{ id: 1 }] });
  try {
    const tbl = 't_' + (++_n);
    const rows = await bm.query.table(tbl, { live: false });
    ok(Array.isArray(rows) && rows.length === 1, 'table() did not return rows');
    // invalidateTable should target the remembered key for this table.
    const rows2 = await bm.query.read({ table: tbl }, { live: true });
    ok(Array.isArray(rows2), 'read() failed');
    const invalidated = bm.query.invalidateTable(tbl);
    ok(invalidated.length >= 1, 'invalidateTable found no keys for table');
  } finally {
    bm.api.post = realPost;
  }
});

await section('query: table() and read() share one cache entry for identical rows', async () => {
  const realPost = bm.api.post;
  let posts = 0;
  bm.api.post = async () => { posts++; return { rows: [] }; };
  try {
    const tbl = 'shared_' + (++_n);
    await bm.query.read({ table: tbl }, { live: false });
    posts = 0;
    // table() should resolve to the same ['query', spec] key shape -> cached.
    await bm.query.table(tbl, { live: false, staleTime: 10000 });
    ok(posts === 0, 'table() did not share cache with read(), extra posts=' + posts);
  } finally {
    bm.api.post = realPost;
  }
});

await section('table: a row id cannot walk the path to another endpoint', async () => {
  const seen = [];
  const real = { get: bm.api.get, patch: bm.api.patch, delete: bm.api.delete, post: bm.api.post };
  for (const m of Object.keys(real)) bm.api[m] = async (p) => { seen.push(p); return {}; };
  try {
    const t = bm.table('notes');
    // A URL parser deletes every tab, LF and CR before it reads the path, so
    // '.\t.' is a dot segment by the time the request leaves.
    for (const bad of ['../_auth/tokens/7', '..', './x', '5/../../_admin', '%2e%2e/x', '.%2E/x', 'a\\..\\b', '.\t./_auth/tokens/7', '.\n.', '%2e\r%2E/x', '5/.\t\n./x']) {
      for (const [name, call] of [['get', () => t.get(bad)], ['update', () => t.update(bad, {})], ['delete', () => t.delete(bad)], ['restore', () => t.restore(bad)], ['revertTo', () => t.revertTo(1, bad)]]) {
        let threw = false;
        try { await call(); } catch (_) { threw = true; }
        ok(threw, `table().${name}(${JSON.stringify(bad)}) was sent`);
      }
    }
    await t.get('42?include=owner');
    await t.delete('b7e1c2d0-uuid');
    ok(seen.includes('/api/notes/42?include=owner'), 'id with a query string no longer works: ' + seen.join(' '));
    ok(seen.includes('/api/notes/b7e1c2d0-uuid'), 'plain id no longer works');
  } finally {
    Object.assign(bm.api, real);
  }
});

await section('sdk: an id encoded as one segment still cannot be a dot segment', async () => {
  // encodeURIComponent leaves '.' alone, so an id of '..' popped the table
  // segment: bm.permissions.revoke('docs', '..', 'x') sent DELETE /api/permissions/x.
  const seen = [];
  const real = { get: bm.api.get, patch: bm.api.patch, delete: bm.api.delete, post: bm.api.post };
  const realFetch = globalThis.fetch;
  const hadDocument = 'document' in globalThis;
  if (!hadDocument) globalThis.document = { querySelector: () => null };
  for (const m of Object.keys(real)) bm.api[m] = async (p) => { seen.push(p); return {}; };
  globalThis.fetch = async (p) => { seen.push(String(p)); return { ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => '{}' }; };
  try {
    const calls = (id) => [
      ['users.get', () => bm.users.get(id)],
      ['workflow.transitionTo', () => bm.workflow('orders', id).transitionTo('shipped')],
      ['workflow.available', () => bm.workflow('orders', id).available()],
      ['permissions.share', () => bm.permissions.share('docs', id, 'a@b.test')],
      ['permissions.revoke', () => bm.permissions.revoke('docs', id, 'a@b.test')],
      ['permissions.revoke(email)', () => bm.permissions.revoke('docs', 5, id)],
      ['permissions.list', () => bm.permissions.list('docs', id)],
      ['notifications.markRead', () => bm.notifications.markRead(id)],
      ['notifications.delete', () => bm.notifications.delete(id)],
      ['jobs.status', () => bm.jobs.status(id)],
      ['auth.passkey.remove', () => bm.auth.passkey.remove(id)],
      ['broadcast.stats', () => bm.broadcast.stats(id)],
    ];
    for (const bad of ['..', '.']) {
      for (const [name, call] of calls(bad)) {
        seen.length = 0;
        let threw = false;
        try { await call(); } catch (_) { threw = true; }
        ok(threw && seen.length === 0, `${name}(${JSON.stringify(bad)}) was sent: ${seen.join(' ')}`);
      }
    }
    for (const bad of ['../_auth/tokens/7', '.\t./x']) {
      seen.length = 0;
      let threw = false;
      try { await bm.users.get(bad); } catch (_) { threw = true; }
      ok(threw && seen.length === 0, `users.get(${JSON.stringify(bad)}) was sent: ${seen.join(' ')}`);
    }
    // Ordinary ids are sent exactly as before.
    for (const good of [7, '7', 'b7e1c2d0-0000-4000-8000-000000000000']) {
      for (const [name, call] of calls(good)) {
        seen.length = 0;
        try { await call(); } catch (e) { ok(false, `${name}(${JSON.stringify(good)}) threw: ${e && e.message}`); }
        ok(seen.length === 1 && seen[0].includes(String(good)), `${name}(${JSON.stringify(good)}) sent ${seen.join(' ')}`);
      }
    }
  } finally {
    Object.assign(bm.api, real);
    globalThis.fetch = realFetch;
    if (!hadDocument) delete globalThis.document;
  }
});

// Fixture fetch: answers each path from `routes` (a function of the request,
// or a [status, body] pair) and records every non-registry request.
function mockFetch(routes) {
  const seen = [];
  const realFetch = globalThis.fetch;
  const hadDocument = 'document' in globalThis;
  const previousDocument = globalThis.document;
  if (!hadDocument) globalThis.document = { querySelector: () => null };
  globalThis.fetch = async (p, init = {}) => {
    const path = String(p);
    if (path !== '/_internal/flows.json') seen.push(`${init.method || 'GET'} ${path}`);
    const route = routes[path.split('?')[0]];
    const [status, data] = typeof route === 'function' ? route(path, init) : (route || [404, { error: 'not found' }]);
    const body = JSON.stringify(data);
    return { ok: status < 300, status, headers: { get: () => 'application/json' }, text: async () => body, json: async () => JSON.parse(body) };
  };
  return {
    seen,
    restore() {
      globalThis.fetch = realFetch;
      if (!hadDocument) delete globalThis.document;
      else globalThis.document = previousDocument;
    },
  };
}

await section('flows: camelCase, kebab and snake spellings reach a kebab-named flow file', async () => {
  // flows/save-quote.yaml registers as saveQuote (bm_types.go flowSDKName).
  const registry = { saveQuote: { path: '/api/quote', method: 'POST', inputs: { hours: { type: 'number' } } } };
  const m = mockFetch({ '/_internal/flows.json': [200, registry], '/api/quote': [200, { total: 120 }] });
  try {
    for (const name of ['saveQuote', 'save-quote', 'save_quote']) {
      m.seen.length = 0;
      const res = await bm.flows[name]({}, { hours: 2 });
      ok(res && res.total === 120 && m.seen.join() === 'POST /api/quote', `bm.flows.${name} sent ${m.seen.join(' ')}`);
    }
    let msg = '';
    try { await bm.flows.saveQuotes({}); } catch (e) { msg = e.message; }
    ok(msg.includes('bm.flows.saveQuote()'), 'unknown flow error should list the callable spelling: ' + msg);
    let threw = false;
    try { await bm.flows.constructor({}); } catch (_) { threw = true; }
    ok(threw, 'a prototype key resolved as a flow');

    // FlowForm (sdui) resolves the same spellings.
    const src = fs.readFileSync(new URL('./sdui.js', import.meta.url), 'utf8')
      .replace("import bm from 'bm';", `import bm from ${JSON.stringify(new URL('./bm.js', import.meta.url).href)};`);
    const hadDocument = 'document' in globalThis, prev = globalThis.document;
    delete globalThis.document; // ensureStyles is a no-op without a DOM
    try {
      const { FlowForm } = await import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'));
      for (const flow of ['save-quote', 'saveQuote']) {
        const form = { addEventListener() {}, querySelectorAll: () => [] };
        const target = { innerHTML: '', querySelector: (s) => (s === 'form' ? form : null) };
        let err = null;
        try { await FlowForm(target, { flow }); } catch (e) { err = e; }
        ok(!err && target.innerHTML.includes('name="hours"'), `FlowForm({flow:'${flow}'}) did not render the flow's inputs: ${err && err.message}`);
      }
    } finally {
      if (hadDocument) globalThis.document = prev;
    }
  } finally {
    m.restore();
  }
});

await section('errors: a JSON error explains itself through message and keeps its code', async () => {
  const registry = { saveQuote: { path: '/api/quote', method: 'POST', inputs: {} } };
  const m = mockFetch({
    '/_internal/flows.json': [200, registry],
    '/api/notes': [403, { error: 'forbidden', message: 'You can read notes but not create them.' }],
    '/api/quote': [500, { error: 'flow_no_response', message: '2 of 2 steps ran and none responded' }],
    '/api/plain': [400, { error: 'No fields to update' }],
  });
  try {
    let e = null;
    try { await bm.api.post('/api/notes', { title: 'x' }); } catch (x) { e = x; }
    ok(e && e.message === 'You can read notes but not create them.' && e.code === 'forbidden' && e.status === 403,
      `refused write: message=${e && e.message} code=${e && e.code} status=${e && e.status}`);
    e = null;
    try { await bm.flows.saveQuote({}); } catch (x) { e = x; }
    ok(e && e.message === '2 of 2 steps ran and none responded' && e.code === 'flow_no_response',
      `failed flow: message=${e && e.message} code=${e && e.code}`);
    e = null;
    try { await bm.api.patch('/api/plain', {}); } catch (x) { e = x; }
    ok(e && e.message === 'No fields to update' && e.code === 'No fields to update', `error-only body: ${e && e.message}`);
    e = null;
    try { await bm.api.get('/api/missing'); } catch (x) { e = x; }
    ok(e && e.message === 'not found' && e.status === 404, `404: ${e && e.message}`);
  } finally {
    m.restore();
  }
});

await section('errors: a failed answer that is not JSON never becomes a page-long message', async () => {
  const realFetch = globalThis.fetch;
  const page = '<!DOCTYPE html><html><head><title>Not Found</title></head><body><h1>Not Found</h1>' + 'x'.repeat(500) + '</body></html>';
  const answers = {
    '/verify-mfa': [404, 'text/html; charset=utf-8', page],
    '/login': [404, 'text/html', page],
    '/api/plain': [429, 'text/plain; charset=utf-8', 'rate limited\n'],
    '/api/long': [500, 'text/plain', 'y'.repeat(300)],
    '/api/badjson': [502, 'application/json', '<html>Bad gateway</html>'],
  };
  const hadDocument = 'document' in globalThis;
  if (!hadDocument) globalThis.document = { querySelector: () => null };
  globalThis.fetch = async (path) => {
    const [status, type, text] = answers[path];
    return { ok: false, status, headers: { get: () => type }, text: async () => text };
  };
  try {
    let e = null;
    try { await bm.api.get('/verify-mfa'); } catch (x) { e = x; }
    ok(e && e.message === 'Request failed (HTTP 404)' && e.status === 404 && e.body && e.body.body === page,
      `HTML 404: message=${e && String(e.message).slice(0, 80)} body kept=${!!(e && e.body && e.body.body === page)}`);
    const raw = await bm.api.raw.get('/verify-mfa');
    ok(raw.data && raw.data.error === 'Request failed (HTTP 404)' && raw.data.body === page, 'raw result carries the HTML as data.error');
    e = null;
    try { await bm.auth.signIn('a@b.test', 'pw'); } catch (x) { e = x; }
    ok(e && e.message === 'Request failed (HTTP 404)', `signIn shows the page: ${e && String(e.message).slice(0, 80)}`);
    e = null;
    try { await bm.api.get('/api/plain'); } catch (x) { e = x; }
    ok(e && e.message === 'rate limited' && e.body.body === 'rate limited\n', `short plain text: ${e && e.message}`);
    e = null;
    try { await bm.api.get('/api/long'); } catch (x) { e = x; }
    ok(e && e.message === 'Request failed (HTTP 500)', `long plain text: ${e && String(e.message).slice(0, 40)}`);
    e = null;
    try { await bm.api.get('/api/badjson'); } catch (x) { e = x; }
    ok(e && e.message === 'Request failed (HTTP 502)' && e.body.body === '<html>Bad gateway</html>', `unparseable JSON error: ${e && e.message}`);
  } finally {
    globalThis.fetch = realFetch;
    if (!hadDocument) delete globalThis.document;
  }
});

await section('table.list: REST options are sent under their REST names; unknown keys warn', async () => {
  const m = mockFetch({ '/api/bookings': [200, { data: [{ id: 1 }], total: 1, page: 2, per_page: 10 }] });
  const warnings = [];
  const realWarn = console.warn;
  console.warn = (...a) => warnings.push(a.join(' '));
  try {
    const rows = await bm.table('bookings').list({
      orderBy: 'starts_at:asc', include: ['client', 'service'], fields: 'id,starts_at', page: 2, per_page: 10, where: { status: 'open' },
    });
    ok(Array.isArray(rows) && rows.length === 1, 'page envelope rows were not unwrapped');
    const q = new URL(m.seen[0].split(' ')[1], 'https://fixture.example').searchParams;
    for (const [k, v] of [['orderBy', 'starts_at:asc'], ['include', 'client,service'], ['fields', 'id,starts_at'], ['page', '2'], ['per_page', '10'], ['status', 'open']]) {
      ok(q.get(k) === v, `list() sent ${k}=${q.get(k)}, want ${v} (${m.seen[0]})`);
    }
    ok(warnings.length === 0, 'known options warned: ' + warnings.join(' | '));
    // A filter written at the top level never reaches the server: say so, once.
    m.seen.length = 0;
    await bm.table('bookings').list({ status: 'open' });
    await bm.table('bookings').list({ status: 'open' });
    ok(!m.seen[0].includes('status='), 'top-level filter was sent anyway');
    ok(warnings.length === 1 && warnings[0].includes('"status"') && warnings[0].includes('where'), 'unknown option did not warn once: ' + warnings.join(' | '));
  } finally {
    console.warn = realWarn;
    m.restore();
  }
});

await section('workflow: current() reads the workflow field; available()/transitionTo() pass the wire shapes', async () => {
  const m = mockFetch({
    // A workflow on a field named neither state nor status.
    '/api/orders/7/transitions': [200, { current: 'packed', transitions: [{ to: 'shipped', role: 'staff' }] }],
    '/api/orders/7': [200, { id: 7, stage: 'packed' }],
    '/api/orders/7/transition': [200, { status: 'transitioned', from: 'packed', to: 'shipped', id: '7' }],
    // Anonymous reader: /transitions needs a session, the row is public.
    '/api/orders/8/transitions': [401, { error: 'authentication required' }],
    '/api/orders/8': [200, { id: 8, status: 'open' }],
  });
  try {
    const wf = bm.workflow('orders', 7);
    ok(await wf.current() === 'packed', 'current() missed a workflow field not named state/status');
    const avail = await wf.available();
    ok(avail.current === 'packed' && avail.transitions[0].to === 'shipped', 'available() shape changed: ' + JSON.stringify(avail));
    const moved = await wf.transitionTo('shipped');
    ok(moved.status === 'transitioned' && moved.to === 'shipped' && moved.id === '7', 'transitionTo() shape changed: ' + JSON.stringify(moved));
    ok(await bm.workflow('orders', 8).current() === 'open', 'anonymous current() lost the row fallback');
  } finally {
    m.restore();
  }
});

await section('flows: a path param cannot be a dot segment', async () => {
  // bm.flows.removeMember({ org: 5, member: '..' }) on DELETE
  // /api/orgs/:org/members/:member sent DELETE /api/orgs/5/ once the
  // browser resolved the '..'.
  const seen = [];
  const realFetch = globalThis.fetch;
  const hadDocument = 'document' in globalThis;
  if (!hadDocument) globalThis.document = { querySelector: () => null };
  globalThis.fetch = async (p) => {
    const body = String(p) === '/_internal/flows.json'
      ? JSON.stringify({ removeMember: { path: '/api/orgs/:org/members/:member', method: 'DELETE' } })
      : '{}';
    if (String(p) !== '/_internal/flows.json') seen.push(String(p));
    return { ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => body, json: async () => JSON.parse(body) };
  };
  try {
    for (const bad of ['..', '.']) {
      seen.length = 0;
      let threw = false;
      try { await bm.flows.removeMember({ org: 5, member: bad }); } catch (_) { threw = true; }
      ok(threw && seen.length === 0, `flow param ${JSON.stringify(bad)} was sent: ${seen.join(' ')}`);
    }
    seen.length = 0;
    await bm.flows.removeMember({ org: 5, member: 'a/b c', note: '..' }); // not a path param
    ok(seen.join() === '/api/orgs/5/members/a%2Fb%20c', 'ordinary flow params changed: ' + seen.join(' '));
    seen.length = 0;
    await bm.flows.removeMember({ org: 5, member: 'a/b c' });
    ok(seen.join() === '/api/orgs/5/members/a%2Fb%20c', 'ordinary flow params changed: ' + seen.join(' '));
  } finally {
    globalThis.fetch = realFetch;
    if (!hadDocument) delete globalThis.document;
  }
});

await section('html: a value starting a URL attribute cannot be a script URL', () => {
  const blocked = '#blocked-unsafe-url';
  for (const u of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', ' java\tscript:alert(1)', '\u0001javascript:x', 'vbscript:x', 'data:text/html,<script>x</script>']) {
    ok(String(bm.html`<a href="${u}">x</a>`) === `<a href="${blocked}">x</a>`, 'script URL kept in href: ' + JSON.stringify(u));
    ok(String(bm.html`<iframe src=${u}></iframe>`).includes(blocked), 'script URL kept in unquoted src: ' + JSON.stringify(u));
    ok(String(bm.html`<form action='${u}'>`).includes(blocked), 'script URL kept in action: ' + JSON.stringify(u));
  }
  for (const u of ['https://ok.test/a?b=1', '/local/path', '#frag', 'mailto:a@b.test', 'data:image/png;base64,AAAA']) {
    ok(String(bm.html`<a href="${u}">x</a>`) === `<a href="${u.replace(/&/g, '&amp;')}">x</a>`, 'safe URL changed: ' + u);
  }
  // Only the start of the attribute decides the scheme; text is untouched.
  ok(String(bm.html`<a href="/u/${'javascript:x'}">x</a>`) === '<a href="/u/javascript:x">x</a>', 'mid-URL value was rewritten');
  ok(String(bm.html`<p>${'javascript:x'}</p>`) === '<p>javascript:x</p>', 'text content was rewritten');
  ok(String(bm.html`<a title="${'javascript:x'}">x</a>`) === '<a title="javascript:x">x</a>', 'non-URL attribute was rewritten');
  // bm.raw is the explicit opt-out.
  ok(String(bm.html`<a href="${bm.raw('javascript:void 0')}">x</a>`) === '<a href="javascript:void 0">x</a>', 'bm.raw URL was rewritten');
});

await section('notifications: drain bursts once and stop pending callbacks', async () => {
  const realFetch = globalThis.fetch;
  const realEventSource = globalThis.EventSource;
  let source;
  globalThis.EventSource = class {
    constructor() { source = this; }
    addEventListener(name, fn) { if (name === 'change') this.change = fn; }
    close() {}
  };
  let rows = [{id: 1, read: 0}, {id: 5, read: 1}];
  let releaseFetch;
  let block = false;
  const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(r => setImmediate(r)); };
  let calls = 0;
  globalThis.fetch = async path => {
    calls++;
    const q = new URL(path, 'https://fixture.example').searchParams;
    const selected = rows.filter(n => !q.get('unread') || !n.read)
      .filter(n => !q.has('after_id') || n.id > Number(q.get('after_id')))
      .sort((a, b) => q.has('after_id') ? a.id - b.id : a.read - b.read || b.id - a.id)
      .slice(Number(q.get('offset') || 0), Number(q.get('offset') || 0) + Number(q.get('limit') || 20));
    if (block) await new Promise(r => { releaseFetch = r; });
    return {ok: true, status: 200, headers: {get: () => 'application/json'},
      text: async () => JSON.stringify({notifications: selected, latest_id: Math.max(...rows.map(n => n.id))})};
  };
  let stop;
  try {
    const delivered = [];
    stop = bm.notifications.onNew(n => delivered.push(n.id));
    await flush();
    rows.push(...Array.from({length: 205}, (_, i) => ({id: i + 6, read: i % 3 === 0 ? 1 : 0})));
    const emit = () => source.change({data: JSON.stringify({table: '_benmore_notifications', action: 'insert'})});
    for (let i = 0; i < 25; i++) emit();
    await flush();
    ok(delivered.length === 205 && new Set(delivered).size === 205, 'burst lost/duplicated notifications: ' + delivered.length);
    ok(delivered[0] === 6 && delivered.at(-1) === 210, 'new callbacks must exclude baseline rows and retain ID order');
    ok(calls < 12, 'one burst performed an unbounded per-event fetch fan-out: ' + calls);
    emit(); await flush();
    ok(delivered.length === 205, 'repeated event redelivered old notifications');
    rows.push({id: 211, read: 0}); block = true; emit(); await flush();
    stop(); releaseFetch(); await flush();
    ok(delivered.length === 205, 'stopped subscription delivered an in-flight callback');
  } finally {
    stop?.(); globalThis.fetch = realFetch;
    if (realEventSource === undefined) delete globalThis.EventSource;
    else globalThis.EventSource = realEventSource;
  }
});

await section('notifications: transient initialization failure can recover', async () => {
  // live() deliberately retains one EventSource per page; this scenario is
  // a fresh page with its own module instance and bus.
  const pageBM = (await import('./bm.js?notification-initialization')).default;
  const originalFetch = globalThis.fetch, originalSource = globalThis.EventSource;
  let source, calls = 0;
  globalThis.EventSource = class {
    constructor() { source = this; }
    addEventListener(name, cb) { if (name === 'change') this.change = cb; }
    close() {}
  };
  let latest = 5;
  globalThis.fetch = async path => {
    if (++calls === 1) throw new Error('temporary network failure');
    const q = new URL(path, 'https://fixture.example').searchParams;
    const rows = q.has('after_id') && Number(q.get('after_id')) < latest ? [{id: latest, read: 0}] : [];
    return {ok:true, status:200, headers:{get:()=> 'application/json'}, text:async()=>JSON.stringify({latest_id:latest,notifications:rows})};
  };
  const flush = async () => { for (let i=0;i<12;i++) await new Promise(r=>setImmediate(r)); };
  const received=[];
  const stop=pageBM.notifications.onNew(n=>received.push(n.id));
  try {
    await flush();
    source.change({data:JSON.stringify({table:'_benmore_notifications',action:'insert'})});
    await flush();
    ok(received.length===0, 'failed baseline must not replay historical notifications');
    latest=6;
    source.change({data:JSON.stringify({table:'_benmore_notifications',action:'insert'})});
    await flush();
    ok(received.length===1 && received[0]===6, 'initial network failure permanently disabled the subscription');
  } finally {
    stop(); globalThis.fetch=originalFetch;
    if (originalSource===undefined) delete globalThis.EventSource; else globalThis.EventSource=originalSource;
  }
});

await section('query: failed older edits preserve newer authoritative values', async () => {
  for (const source of ['set', 'fetch', 'successful mutation']) {
    for (const custom of [false, true]) {
      const key = uniq('overlapping-save');
      const original = { title: 'original', spent: 0 };
      const saved = { title: 'newer persisted title', spent: 0 };
      bm.query.set(key, original);
      let reject;
      let rollbackCalls = 0;
      const error = new Error('old validation failure');
      const failed = bm.query.mutate({ key, apply: row => ({ ...row, spent: 999 }),
        request: () => new Promise((_resolve, no) => { reject = no; }),
        ...(custom ? { rollback: row => { rollbackCalls++; return row; } } : {}),
      }).catch(e => e);
      if (source === 'set') bm.query.set(key, saved);
      else if (source === 'fetch') await bm.query.fetch(key, async () => saved, { force: true });
      else await bm.query.mutate({ key, apply: () => saved, request: async () => ({ ok: true }) });
      reject(error);
      ok(await failed === error, source + ': original mutation error was lost');
      ok(bm.query.get(key) === saved, source + ': older failure overwrote the newer value');
      ok(rollbackCalls === 0, source + ': custom rollback ran for superseded data');
    }
  }
});

await section('query: both failed optimistic writes unwind without reviving a failed value', async () => {
  for (const order of ['old-first', 'new-first']) {
    const key = uniq('two-failures');
    const original = { title: 'persisted' };
    bm.query.set(key, original);
    const reject = [];
    const pending = ['older', 'newer'].map(title => bm.query.mutate({ key,
      apply: () => ({ title }),
      request: () => new Promise((_resolve, no) => { reject.push(no); }),
    }).catch(e => e));
    const first = order === 'old-first' ? 0 : 1, last = 1 - first;
    reject[first](new Error('rejected ' + first)); await pending[first];
    ok(bm.query.get(key).title === (first === 0 ? 'newer' : 'older'), order + ': first failure erased the pending edit');
    reject[last](new Error('rejected ' + last)); await pending[last];
    ok(bm.query.get(key) === original, order + ': a failed optimistic value survived both errors');
  }
});

await section('query: failure restores only its still-owned keys', async () => {
  const keys = [uniq('unchanged-key'), uniq('replaced-key')];
  const original = { n: 0 }, saved = { n: 2 };
  for (const key of keys) bm.query.set(key, original);
  let reject;
  const callbacks = [];
  const pending = bm.query.mutate({ keys,
    apply: () => ({ n: 1 }), request: () => new Promise((_resolve, no) => { reject = no; }),
    rollback: (row, _error, key) => { callbacks.push(key); return row; },
  }).catch(e => e);
  bm.query.set(keys[1], saved);
  reject(new Error('failed')); await pending;
  ok(bm.query.get(keys[0]) === original && bm.query.get(keys[1]) === saved, 'multi-key rollback clobbered a newer key');
  ok(callbacks.length === 1 && callbacks[0] === keys[0], 'rollback callback ran for a superseded key');
});

await section('query: failed edit does not cancel invalidation replacement read', async () => {
  const key = uniq('replacement-read');
  await bm.query.fetch(key, async () => ({ title: 'base' }));
  let reject, resolve;
  const edit = bm.query.mutate({ key, apply: () => ({ title: 'optimistic' }),
    request: () => new Promise((_yes, no) => { reject = no; }),
  }).catch(e => e);
  bm.query.invalidate(key);
  const replacement = bm.query.fetch(key, () => new Promise(yes => { resolve = yes; }));
  await Promise.resolve();
  let state;
  const stop = bm.query.subscribe(key, next => { state = next; });
  reject(new Error('old write failed')); await edit;
  ok(state.pending && state.updatedAt === 0, 'rollback cancelled or refreshed an invalidated pending read');
  resolve({ title: 'server state' }); await replacement;
  ok(bm.query.get(key).title === 'server state' && !state.pending, 'replacement result did not publish');
  stop();
});

await section('query: failed refetch does not strand a rejected optimistic value', async () => {
  for (const custom of [false, true]) {
    const key = uniq('failed-refetch');
    const original = { spent: 0 }, readError = new Error('read unavailable');
    bm.query.set(key, original);
    let reject, state;
    const edit = bm.query.mutate({ key, apply: () => ({ spent: 999 }),
      request: () => new Promise((_yes, no) => { reject = no; }),
      ...(custom ? { rollback: previous => previous } : {}),
    }).catch(e => e);
    const stop = bm.query.subscribe(key, next => { state = next; });
    await bm.query.fetch(key, async () => { throw readError; }, { force: true }).catch(() => {});
    reject(new Error('write rejected')); await edit;
    ok(bm.query.get(key) === original, 'failed read prevented optimistic rollback');
    ok(state.error === readError && !state.pending, 'rollback lost the newer read error');
    stop();
  }
});

await section('query: optimistic rollback preserves a newer pending forced fetch', async () => {
  for (const custom of [false, true]) {
    const key = uniq('read-after-edit');
    const original = { title: 'base' }, saved = { title: 'server state' };
    bm.query.set(key, original);
    let reject, resolve, state;
    const edit = bm.query.mutate({ key, apply: () => ({ title: 'optimistic' }),
      request: () => new Promise((_yes, no) => { reject = no; }),
      ...(custom ? { rollback: previous => previous } : {}),
    }).catch(e => e);
    const newerRead = bm.query.fetch(key, () => new Promise(yes => { resolve = yes; }), { force: true });
    await Promise.resolve();
    const stop = bm.query.subscribe(key, next => { state = next; });
    reject(new Error('write rejected')); await edit;
    ok(bm.query.get(key) === original && state.pending, 'rollback did not preserve current read pending state');
    resolve(saved); await newerRead;
    ok(bm.query.get(key) === saved && !state.pending, 'newer read lost its right to publish');
    stop();
  }
});

if (failures > 0) {
  console.error(`\n${failures} behavioral assertion(s) failed`);
  process.exit(1);
}
console.log('all bm SDK behavioral assertions passed');
