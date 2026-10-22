import bm from './bm.js';

let failures = 0, clock = 0, nextTimer = 0;
const timers = new Map(), connections = [], visibility = new Set(), warnings = [];
const ok = (value, message) => { if (!value) { failures++; console.error('FAIL:', message); } };
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
globalThis.setTimeout = (fn, delay) => { const id = ++nextTimer; timers.set(id, { fn, at: clock + delay }); return id; };
globalThis.clearTimeout = id => timers.delete(id);
globalThis.document = {
  hidden: false,
  addEventListener(name, fn) { if (name === 'visibilitychange') visibility.add(fn); },
  removeEventListener(name, fn) { if (name === 'visibilitychange') visibility.delete(fn); },
};
globalThis.EventSource = class {
  constructor() { this.listeners = {}; connections.push(this); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  close() {}
};
const originalWarn = console.warn;
console.warn = (...args) => warnings.push(args);
const emit = event => connections.at(-1).listeners.change({ data: JSON.stringify(event) });
const tick = async ms => {
  const target = clock + ms;
  for (;;) {
    const next = [...timers.entries()].sort((a, b) => a[1].at - b[1].at)[0];
    if (!next || next[1].at > target) break;
    clock = next[1].at; timers.delete(next[0]); next[1].fn(); await flush();
  }
  clock = target; await flush();
};
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };

// Same callback shape as the hosted board: read a snapshot, then render after
// asynchronous work. Holding the first completion reproduces old-over-new UI.
{
  let version = 1, rendered = null, calls = 0, running = 0, peak = 0;
  const first = deferred();
  const stop = bm.live.scoped('notes', async () => {
    const call = ++calls, snapshot = version;
    peak = Math.max(peak, ++running);
    try { if (call === 1) await first.promise; rendered = snapshot; }
    finally { running--; }
  }, { debounce: 20 });
  await tick(19); ok(calls === 0, 'mount respects debounce');
  await tick(1); ok(calls === 1, 'mount primes a read');
  version = 2;
  emit({ table: 'notes', action: 'update' });
  await tick(20);
  version = 3;
  for (let i = 0; i < 4; i++) emit({ table: '', action: 'refresh' });
  await tick(20);
  ok(calls === 1 && peak === 1, 'running callback must not overlap a newer callback');
  first.resolve(); await flush(); await tick(20);
  ok(rendered === 3, 'held old snapshot must not overwrite final newest state');
  ok(calls === 2, 'events during a running callback coalesce into one follow-up');
  emit({ table: 'unrelated', action: 'update' }); await tick(20);
  ok(calls === 2, 'named unrelated changes remain filtered');
  version = 4; emit({ table: 'notes', action: 'update' }); await tick(20);
  ok(rendered === 4 && calls === 3, 'settled subscription still refreshes');
  stop();
}

// A pending callback cannot block another subscription's independent slot.
{
  const first = deferred(); let waiting = 0, other = 0;
  const stop = bm.live.scoped('notes', async () => { waiting++; await first.promise; }, { debounce: 5 });
  const stopOther = bm.live.scoped('other', () => { other++; }, { debounce: 5 });
  await tick(5); emit({ table: 'other', action: 'update' }); await tick(5);
  ok(waiting === 1 && other === 2, 'one pending subscription must not block an independent subscription');
  first.resolve(); await flush(); stop(); stopOther();
}

// A rejected callback releases the slot and preserves one queued refresh.
{
  const first = deferred(); let calls = 0;
  const before = warnings.length;
  const stop = bm.live.scoped('notes', () => ++calls === 1 ? first.promise : undefined, { debounce: 5 });
  await tick(5); emit({ table: 'notes', action: 'update' }); await tick(5);
  ok(calls === 1, 'pending rejection path is also serialized');
  first.reject(new Error('synthetic read failure')); await flush(); await tick(5);
  ok(calls === 2 && warnings.length === before + 1, 'rejected read releases slot and reports error once');
  stop();
}

// A synchronous callback/throw still supports ordinary trailing-edge debounce
// and visibility refresh. Each subscription owns its own running slot.
{
  let calls = 0, other = 0;
  const before = warnings.length;
  const stop = bm.live.scoped('notes', () => { if (++calls === 1) throw Error('synthetic sync failure'); }, { debounce: 10 });
  const stopOther = bm.live.scoped('other', () => { other++; }, { debounce: 10 });
  await tick(10);
  ok(calls === 1 && other === 1 && warnings.length === before + 1, 'sync failure does not block another subscription');
  emit({ table: 'notes', action: 'update' }); await tick(6);
  emit({ table: 'notes', action: 'update' }); await tick(9);
  ok(calls === 1, 'burst waits until last event debounce window ends');
  await tick(1); ok(calls === 2 && other === 1, 'burst refreshes once and stays table-specific');
  document.hidden = true; for (const fn of visibility) fn(); await tick(10);
  ok(calls === 2, 'becoming hidden does not request visibility refresh');
  document.hidden = false; for (const fn of visibility) fn(); await tick(10);
  ok(calls === 3 && other === 2, 'returning to foreground refreshes each subscription');
  stop(); stopOther();
}

{
  let calls = 0;
  const stop = bm.live.scoped('notes', () => { calls++; }, { debounce: 5 });
  const queuedVisibility = [...visibility][0];
  stop(); stop();
  queuedVisibility(); // an event callback retained before disposal
  emit({ table: 'notes', action: 'update' }); await tick(10);
  ok(calls === 0, 'unsubscribe prevents pending and subsequently delivered work');
  ok(visibility.size === 0, 'unsubscribe removes visibility listener');
}

{
  let calls = 0, completed = 0;
  const first = deferred();
  const stop = bm.live.scoped('notes', async () => { calls++; await first.promise; completed++; }, { debounce: 5 });
  await tick(5); emit({ table: 'notes', action: 'update' }); await tick(5);
  stop(); first.resolve(); await flush(); await tick(20);
  ok(calls === 1 && completed === 1, 'unsubscribe cancels queued follow-up but cannot cancel a running callback');
}

console.warn = originalWarn;
if (failures) { console.error(failures + ' live.scoped failures'); process.exit(1); }
console.log('all live.scoped ordering and lifecycle assertions passed');
