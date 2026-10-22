import bm from './bm.js';

let failures = 0, serial = 0;
const ok = (v, message) => { if (!v) { failures++; console.error('FAIL:', message); } };
async function section(name, fn) { try { await fn(); } catch (e) { failures++; console.error('FAIL:', name, e); } }
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const response = (data, status = 200, html = false) => ({ ok: status >= 200 && status < 300, status, headers: { get: () => html ? 'text/html' : 'application/json' }, text: async () => html ? data : JSON.stringify(data) });
globalThis.document = { querySelector: () => ({ content: 'synthetic-csrf' }) };
let actor = 'alpha', handler = null, reads = 0;
globalThis.fetch = async (path, init) => {
  if (handler) { const result = handler(path, init); if (result !== undefined) return result; }
  if (path === '/api/_auth/profile') return response({ id: actor === 'alpha' ? 1 : 2, email: actor });
  if (path === '/api/_query') { reads++; return response({ rows: [{ id: actor === 'alpha' ? 1 : 2, title: actor + ' private' }] }); }
  if (path === '/logout') return response({ ok: true });
  if (path === '/login' || path === '/signup') return response({ ok: true, user: { id: actor === 'alpha' ? 1 : 2 } });
  return response({ ok: true });
};
const key = () => ['auth-boundary', ++serial];
async function switchAccount() { actor = actor === 'alpha' ? 'beta' : 'alpha'; await bm.auth.signIn(actor, 'synthetic-password'); }

await section('successful sign-in evicts cached private table results', async () => {
  actor = 'alpha'; await bm.auth.signIn(actor, 'synthetic-password');
  const options = { columns: ['id', 'title'], staleTime: 60000, live: false };
  const before = reads;
  const first = await bm.query.table('private_tasks', options);
  await switchAccount();
  const second = await bm.query.table('private_tasks', options);
  ok(first[0].id === 1 && second[0].id === 2 && reads === before + 2, 'new account received the previous account’s staleTime cache');
});

await section('logout clears subscriptions without removing them', async () => {
  const k = key(), states = []; bm.query.set(k, ['private']);
  const stop = bm.query.subscribe(k, s => states.push(s));
  await bm.auth.signOut();
  ok(bm.query.get(k) === undefined && states.at(-1).data === undefined && !states.at(-1).pending, 'logout retained private subscribed data');
  bm.query.set(k, ['new']);
  ok(states.at(-1).data[0] === 'new', 'auth reset lost the existing subscription');
  stop();
});

await section('refused auth and unfinished challenges preserve the current session', async () => {
  await bm.auth.signIn(actor, 'synthetic-password');
  const current = await bm.auth.me(), k = key(); bm.query.set(k, 'current');
  for (const path of ['/login', '/signup', '/logout', '/api/_switch_group']) {
    handler = p => p === path ? response({ error: 'refused' }, 403) : undefined;
    let rejected = false;
    try { if (path === '/login') await bm.auth.signIn('other', 'wrong'); else if (path === '/signup') await bm.auth.signUp({ email: 'other' }); else if (path === '/logout') await bm.auth.signOut(); else await bm.api.post(path, { group_id: 'other' }); } catch { rejected = true; }
    ok(rejected && bm.query.get(k) === 'current' && (await bm.auth.me())?.id === current.id, 'refused ' + path + ' changed or misreported the session');
  }
  handler = p => p === '/login' ? response({ ok: true, otp_required: true, redirect: '/verify-otp' }) : undefined;
  ok(await bm.auth.signIn('other', 'proof') === null && bm.query.get(k) === 'current', 'OTP challenge evicted a still-current session or claimed login success');
  handler = null;
});

await section('signup, MFA completion, and tenant switching reset scoped state', async () => {
  for (const operation of [
    async () => bm.auth.signUp({ email: actor, password: 'synthetic-password' }),
    async () => { handler = p => p === '/api/_auth/mfa/verify' ? response({ status: 'mfa_enabled', token: 'synthetic-token', user_id: 2 }) : undefined; return bm.mfa.verify('000000'); },
    async () => { handler = p => p === '/api/_switch_group' ? response('<html>new group</html>', 200, true) : undefined; return bm.api.post('/api/_switch_group', { group_id: 2 }); },
    async () => bm.api.post('/api/_groups/create', { name: 'new workspace' }),
    async () => { handler = p => p === '/verify-mfa' ? response('<html>signed in</html>', 200, true) : undefined; return bm.api.post('/verify-mfa', { code: '000000' }); },
    async () => { handler = p => p === '/verify-otp' ? response('<html>signed in</html>', 200, true) : undefined; return bm.api.post('/verify-otp', { code: '000000' }); },
  ]) { const k = key(); bm.query.set(k, 'private'); await operation(); ok(bm.query.get(k) === undefined, 'session/tenant completion kept private cache'); handler = null; }
  const k = key(); bm.query.set(k, 'same-session');
  handler = p => p === '/api/_auth/mfa/verify' ? response({ status: 'mfa_enabled' }) : undefined;
  await bm.mfa.verify('000000');
  ok(bm.query.get(k) === 'same-session', 'ordinary MFA enrollment was mistaken for a new session'); handler = null;
});

await section('passkey session success resets but an OTP continuation does not', async () => {
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: { get: async () => ({ id: 'synthetic', type: 'public-key', rawId: new ArrayBuffer(1), response: { clientDataJSON: new ArrayBuffer(1), authenticatorData: new ArrayBuffer(1), signature: new ArrayBuffer(1), userHandle: null } }) } } });
  const k = key();
  for (const completed of [false, true]) {
    bm.query.set(k, 'private');
    handler = p => p === '/api/_auth/passkeys/login/options' ? response({ challenge: 'AA' }) : p === '/api/_auth/passkeys/login' ? response(completed ? { user: { id: 2 } } : { otp_required: true }) : undefined;
    const user = await bm.auth.passkey.signIn();
    ok(completed ? user.id === 2 && bm.query.get(k) === undefined : user === null && bm.query.get(k) === 'private', 'passkey completion and pending challenge semantics diverged');
  }
  handler = null;
});

await section('impersonation and act-as scopes reset only on successful changes', async () => {
  for (const [method, path, result] of [
    ['POST', '/api/_auth/impersonate', { token: 'synthetic-token', user_id: 2 }],
    ['POST', '/api/_auth/end-impersonation', { status: 'restored' }],
    ['POST', '/api/_auth/act_as', { status: 'acting_as', acting_as_group: '2' }],
    ['DELETE', '/api/_auth/act_as', { status: 'cleared' }],
  ]) for (const success of [false, true]) {
    const k = key(); bm.query.set(k, 'prior-scope');
    handler = p => p === path ? response(success ? result : { error: 'refused' }, success ? 200 : 403) : undefined;
    let rejected = false;
    try { if (method === 'DELETE') await bm.api.delete(path); else await bm.api.post(path, {}); } catch { rejected = true; }
    ok(success ? !rejected && bm.query.get(k) === undefined : rejected && bm.query.get(k) === 'prior-scope', method + ' ' + path + ' misclassified scope change');
    handler = null;
  }
  const k = key(); bm.query.set(k, 'same-scope');
  await bm.api.get('/api/_auth/act_as');
  ok(bm.query.get(k) === 'same-scope', 'act-as status read cleared the cache');
});

await section('pending old reads cannot publish data or errors after an auth change', async () => {
  for (const reject of [false, true]) {
    const k = key(), pending = deferred();
    const old = bm.query.fetch(k, () => pending.promise).catch(e => e.message); await Promise.resolve();
    await switchAccount();
    ok(bm.query.get(k) === undefined, 'auth change retained a pending old query');
    if (reject) pending.reject(new Error('old-account-error')); else pending.resolve('old-private');
    await old;
    let state; const stop = bm.query.subscribe(k, s => state = s); stop();
    ok(state.data === undefined && state.error === null && !state.pending, 'old read repopulated new-session state');
  }
});

await section('old mutation settlement cannot restore or invalidate a new session', async () => {
  for (const kind of ['default', 'custom', 'unapplied', 'success']) for (const publishNew of [false, true]) {
    const k = key(), pending = deferred(); let rollbackCalls = 0;
    bm.query.set(k, 'old-private');
    const opts = { key: k, request: () => pending.promise, invalidate: k, refetch: false };
    if (kind !== 'unapplied') opts.apply = () => 'old-optimistic';
    if (kind === 'custom' || kind === 'unapplied') opts.rollback = value => { rollbackCalls++; return value; };
    const old = bm.query.mutate(opts).catch(e => e.message);
    await switchAccount(); if (publishNew) bm.query.set(k, 'new-private');
    if (kind === 'success') pending.resolve({ ok: true }); else pending.reject(new Error('old write refused'));
    await old;
    let state; const stop = bm.query.subscribe(k, s => state = s); stop();
    ok(state.data === (publishNew ? 'new-private' : undefined) && (publishNew ? state.updatedAt > 0 : state.updatedAt === 0) && rollbackCalls === 0, 'old ' + kind + ' mutation crossed the auth boundary');
  }
});

await section('explicit session refresh clears cached scopes and supersedes profile reads', async () => {
  const k = key(); bm.query.set(k, 'old-private');
  const oldProfile = deferred();
  handler = p => p === '/api/_auth/profile' ? oldProfile.promise : undefined;
  const old = bm.auth.refreshMe(); await Promise.resolve();
  ok(bm.query.get(k) === undefined, 'refreshMe retained old scoped queries');
  handler = null; await switchAccount();
  const current = await bm.auth.me(); oldProfile.resolve(response({ id: 99, email: 'old' })); await old;
  ok((await bm.auth.me()).id === current.id, 'old pending profile repopulated the auth cache');
});

await section('live subscribers rebind and queued old events are ignored', async () => {
  const connections = [];
  globalThis.EventSource = class { constructor(path) { this.path = path; this.handlers = {}; this.closed = false; connections.push(this); } addEventListener(name, fn) { this.handlers[name] = fn; } close() { this.closed = true; } };
  const events = []; const stop = bm.live('private_tasks', e => events.push(e));
  const old = connections.at(-1); await switchAccount(); const current = connections.at(-1);
  old.handlers.change({ data: JSON.stringify({ table: 'private_tasks', id: 1 }) });
  current.handlers.change({ data: JSON.stringify({ table: 'private_tasks', id: 2 }) });
  ok(old !== current && old.closed && events.length === 1 && events[0].id === 2, 'old-session live events reached new-session listeners');
  await bm.auth.signOut();
  ok(current.closed, 'logout left its authenticated EventSource open'); stop();
  const anonymousStop = bm.live('public_table', () => {});
  ok(connections.at(-1) !== current && !connections.at(-1).closed, 'new public subscription could not reconnect after logout'); anonymousStop();
});

if (failures) { console.error(failures + ' auth cache failures'); process.exit(1); }
console.log('all bm auth cache assertions passed');
