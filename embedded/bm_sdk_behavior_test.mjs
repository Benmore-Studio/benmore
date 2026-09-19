// Behavioral tests for the bm.createStore + bm.query SDK primitives.
// Run via `node embedded/bm_sdk_behavior_test.mjs` (invoked from the Go test
// TestEmbeddedBMSDKBehavior). Exits non-zero with a message on first failure.
//
// These exercise the real logic rather than grepping for symbols: store
// no-op/shallow-equality suppression, persistence round-trip, query concurrent
// fetch dedupe, stale-time hit/miss, optimistic mutate rollback, and
// invalidate / invalidateTable targeting.

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

if (failures > 0) {
  console.error(`\n${failures} behavioral assertion(s) failed`);
  process.exit(1);
}
console.log('all bm SDK behavioral assertions passed');
