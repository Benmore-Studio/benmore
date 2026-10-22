import bm from './bm.js';

let failures = 0, version = 1, hold = null;
const counts = new Map(), connections = [];
const ok = (value, message) => { if (!value) { failures++; console.error('FAIL:', message); } };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const response = data => ({ ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => JSON.stringify(data) });
globalThis.document = { querySelector: () => ({ content: 'synthetic-csrf' }) };
globalThis.EventSource = class {
  constructor() { this.handlers = {}; connections.push(this); }
  addEventListener(name, fn) { this.handlers[name] = fn; }
  close() { this.closed = true; }
};
globalThis.fetch = async (path, init) => {
  if (path === '/api/_query') {
    const spec = JSON.parse(init.body), table = spec.table;
    counts.set(table, (counts.get(table) || 0) + 1);
    const result = response({ rows: [{ table, version }] });
    if (hold) { const pending = hold; hold = null; await pending.promise; }
    return result;
  }
  if (path === '/login') return response({ user: { id: version } });
  return response({ ok: true });
};
const emit = event => connections.at(-1).handlers.change({ data: JSON.stringify(event) });
const count = table => counts.get(table) || 0;
async function reset() { hold = null; counts.clear(); version = 1; await bm.auth.signIn('synthetic', 'synthetic'); }
async function section(name, fn) { try { await reset(); await fn(); } catch (err) { failures++; console.error('FAIL:', name, err); } }

await section('generic refresh updates every registered live query and its subscriber', async () => {
  const events = [], stop = bm.query.subscribe('queue', state => events.push(state.data));
  await bm.query.read({ table: 'tasks' }, { key: 'queue', staleTime: 60000 });
  await bm.query.read({ table: 'tasks', group_by: ['status'] }, { key: 'summary', staleTime: 60000 });
  await bm.query.read({ table: 'notes' }, { key: 'notes', staleTime: 60000 });
  await bm.query.read({ table: 'archive' }, { key: 'offline', live: false, staleTime: 60000 });
  let customReads = 0; await bm.query.fetch('custom', () => ++customReads);
  version = 2; emit({ table: '', action: 'refresh' }); await sleep(85);
  ok(bm.query.get('queue')[0].version === 2 && bm.query.get('summary')[0].version === 2 && bm.query.get('notes')[0].version === 2, 'tableless refresh left registered private queries stale');
  ok(events.at(-1)?.[0]?.version === 2, 'tableless refresh did not update the rendered subscription');
  ok(count('tasks') === 4 && count('notes') === 2, 'generic refresh did not read each registered key exactly once');
  ok(count('archive') === 1 && bm.query.get('offline')[0].version === 1 && customReads === 1, 'generic refresh refetched an unregistered/live:false query');
  stop();
});

await section('generic and detailed bursts coalesce without duplicate refetches', async () => {
  await bm.query.table('tasks', { key: 'tasks', staleTime: 60000 });
  await bm.query.table('notes', { key: 'notes', staleTime: 60000 });
  version = 2;
  for (const event of [{ table: 'tasks', action: 'update' }, { table: '', action: 'refresh' }, { action: 'refresh' }, { table: 'notes', action: 'insert' }]) emit(event);
  await sleep(85);
  ok(count('tasks') === 2 && count('notes') === 2, 'mixed generic/detailed burst duplicated or omitted a refetch');
  ok(bm.query.get('tasks')[0].version === 2 && bm.query.get('notes')[0].version === 2, 'mixed burst retained stale data');
});

await section('named changes remain table-specific and malformed empty events are ignored', async () => {
  await bm.query.table('tasks', { key: 'tasks' }); await bm.query.table('notes', { key: 'notes' });
  version = 2; emit({ table: 'tasks', action: 'update' }); emit({ table: '', action: 'update' }); await sleep(85);
  ok(count('tasks') === 2 && bm.query.get('tasks')[0].version === 2 && count('notes') === 1, 'named change invalidated unrelated tables or ignored the changed one');
});

await section('generic refresh supersedes an older pending read', async () => {
  await bm.query.table('tasks', { key: 'queue' });
  let release; hold = { promise: new Promise(resolve => { release = resolve; }) };
  const old = bm.query.refetch('queue'); await Promise.resolve();
  version = 2; emit({ table: '', action: 'refresh' }); await sleep(85);
  ok(bm.query.get('queue')[0].version === 2, 'generic refresh deduped onto stale in-flight data');
  release(); const oldRows = await old;
  ok(oldRows[0].version === 1 && bm.query.get('queue')[0].version === 2, 'superseded read overwrote generic refresh result');
});

await section('session reset cancels queued generic invalidation', async () => {
  await bm.query.table('tasks', { key: 'shared-key' });
  const oldConnection = connections.at(-1);
  emit({ table: '', action: 'refresh' });
  await bm.auth.signOut(); version = 2; await bm.auth.signIn('next', 'synthetic');
  await bm.query.table('tasks', { key: 'shared-key', staleTime: 60000 });
  oldConnection.handlers.change({ data: JSON.stringify({ table: '', action: 'refresh' }) });
  await sleep(85);
  ok(count('tasks') === 2 && bm.query.get('shared-key')[0].version === 2, 'old generic timer/event refetched the next session cache');
});

await bm.auth.signOut();
if (failures) { console.error(failures + ' query live refresh failures'); process.exit(1); }
console.log('all bm query live refresh assertions passed');
