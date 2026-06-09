// bm - Benmore frontend SDK. Auto-served at /_internal/bm.js, resolved
// in TSX/JS via the `import 'bm'` bare specifier (HTML pages set up an
// import map pointing to this file).
//
// Surface intentionally narrow. Does ONE thing: wraps the backend so
// the agent doesn't reinvent fetch/CSRF/SSE/WS on every app.
// Rendering / DOM / state are NOT in scope - bring your own.
//
// Hard cap: <5KB gzipped. Anything that creeps past goes into an opt-in
// /_internal/bm-<thing>.js side-module instead.
//
// =================================================================
//  1. fetch wrapper - auto CSRF, auto JSON, uniform { ok, status, data }
// =================================================================

const CSRF_META = () => document.querySelector('meta[name="csrf-token"]')?.content || '';

async function request(method, path, body) {
  const headers = { Accept: 'application/json' };
  const init = { method, credentials: 'same-origin', headers };
  if (body !== undefined && body !== null) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  if (method !== 'GET' && method !== 'HEAD') {
    headers['X-CSRF-Token'] = CSRF_META();
  }
  const res = await fetch(path, init);
  if (res.status === 204) return { ok: true, status: 204, data: null };
  const text = await res.text();
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  let data = null;
  if (text) {
    if (ct.includes('application/json')) {
      try { data = JSON.parse(text); } catch { data = { error: text }; }
    } else {
      data = { error: text };
    }
  }
  return { ok: res.ok, status: res.status, data };
}

// Convenience: unwrap or throw. Most agent code wants this shape:
//   const message = await bm.api.post('/api/messages', {...});
async function unwrap(res) {
  if (!res.ok) {
    const msg = res.data?.error || `HTTP ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.body = res.data;
    throw err;
  }
  return res.data;
}

export const api = {
  // Raw forms - return { ok, status, data }, never throw on HTTP errors.
  raw: {
    get:    (p)    => request('GET',    p),
    post:   (p, b) => request('POST',   p, b),
    patch:  (p, b) => request('PATCH',  p, b),
    delete: (p)    => request('DELETE', p),
  },
  // Convenience forms - throw on !ok, return data directly.
  get:    async (p)    => unwrap(await request('GET',    p)),
  post:   async (p, b) => unwrap(await request('POST',   p, b)),
  patch:  async (p, b) => unwrap(await request('PATCH',  p, b)),
  delete: async (p)    => unwrap(await request('DELETE', p)),

  /**
   * Optimistic mutation + reconcile. Applies the change to local
   * state IMMEDIATELY (so the UI is instant), races a network
   * PATCH/POST/DELETE, and reconciles when the server responds.
   *
   *   const handle = bm.api.optimistic({
   *     apply:    () => state.markRead(channelId),   // local mutation
   *     revert:   (snapshot) => state.restore(snapshot),   // on failure
   *     snapshot: () => state.snapshotChannel(channelId),  // for revert
   *     request:  () => bm.api.patch('/api/memberships/' + id, { last_read_at: new Date().toISOString() }),
   *   });
   *   // optional: await handle for the server response (or .catch for errors)
   *
   * Returns a thenable that resolves with the server response (or
   * rejects with the error after the local state has been reverted).
   *
   * The "newer-wins" guard an earlier app build built for last_read_at maps
   * directly onto `snapshot()` / `revert()` here - keep a snapshot of
   * the field before the optimistic apply, restore it on rejection
   * BUT only if no NEWER optimistic apply happened in between (track
   * a generation counter at the caller side or via the snapshot).
   */
  optimistic({ apply, revert, snapshot, request }) {
    if (typeof apply !== 'function' || typeof request !== 'function') {
      throw new Error('bm.api.optimistic({ apply, request, ... }) requires apply + request functions');
    }
    let snap;
    try {
      if (typeof snapshot === 'function') snap = snapshot();
      apply();
    } catch (err) {
      // apply() itself blew up - bail before sending the request.
      return Promise.reject(err);
    }
    return Promise.resolve()
      .then(() => request())
      .catch(err => {
        if (typeof revert === 'function') {
          try { revert(snap); } catch (rerr) {
            console.warn('[bm.api.optimistic] revert threw:', rerr);
          }
        }
        throw err;
      });
  },
};

// =================================================================
//  2. Auth - current user, sign out
// =================================================================

let _meCache = undefined; // distinguish "never fetched" (undefined) from "fetched, no session" (null)

async function me() {
  if (_meCache !== undefined) return _meCache;
  const res = await request('GET', '/api/_auth/profile');
  _meCache = res.ok ? res.data : null;
  return _meCache;
}

async function signOut() {
  // Framework's logout endpoint is registered at app.Paths.Logout (default /logout).
  await request('POST', '/logout');
  _meCache = null;
}

// Force-refresh the profile cache (useful right after signup).
async function refreshMe() {
  _meCache = undefined;
  return me();
}

// signIn - POST /login. `identifier` is the email/phone/username.
// Server side accepts both form-encoded and JSON bodies (v2.7.26+).
// Returns the user object on success; throws { status, body } on failure.
async function signIn(identifier, password) {
  const res = await request('POST', '/login', { email: identifier, password });
  if (!res.ok) {
    const err = new Error(res.data?.error || 'Invalid credentials');
    err.status = res.status;
    err.body = res.data;
    throw err;
  }
  _meCache = undefined; // force next me() to refetch with new session
  return res.data?.user || null;
}

// signUp - POST /signup. Pass any extra signup_fields (configured in
// app.yaml's `auth.signup_fields`) as additional keys on the object:
//   await bm.auth.signUp({ email, password, first_name: 'Ada' })
async function signUp(fields) {
  const res = await request('POST', '/signup', fields);
  if (!res.ok) {
    const err = new Error(res.data?.error || 'Sign-up failed');
    err.status = res.status;
    err.body = res.data;
    throw err;
  }
  _meCache = undefined;
  return res.data?.user || null;
}

export const auth = { me, signOut, refreshMe, signIn, signUp };

// =================================================================
//  3. Users - public user-lookup (v2.7.11+, default-private)
// =================================================================

export const users = {
  async list(opts = {}) {
    const qs = new URLSearchParams();
    if (opts.limit)  qs.set('limit',  String(opts.limit));
    if (opts.offset) qs.set('offset', String(opts.offset));
    const path = '/api/_auth/users' + (qs.toString() ? '?' + qs : '');
    const r = await api.get(path);
    return r.users || [];
  },
  async get(id) {
    return api.get(`/api/_auth/users/${id}`);
  },
};

// =================================================================
//  4. Tables - CRUD for any model in schema.prisma
//     Usage: bm.table('messages').list() / .get(id) / .create({...})
//            .update(id, {...}) / .delete(id)
//
//     INTERCEPTORS (v2.7.65+): register transforms that mutate every
//     read/write opts before the request fires. Use case: multi-tenant
//     apps that need to inject `where[group_id]=N` on every query.
//
//       bm.table.before('read', opts => ({
//         ...opts,
//         where: { ...opts.where, group_id: currentGroupId() }
//       }));
//
//     Hooks: 'read' fires for list/get/count; 'write' fires for
//     create/update/delete. The hook receives (opts, ctx) where
//     ctx = { table, op } so an interceptor can scope by table.
//     Multiple hooks run in registration order, output of one feeds
//     the next. Pre-2.7.65, multi-tenant apps had to wrap api.get in
//     their own apiList() helper and bypass bm.table entirely; this
//     hook lets them stay on the typed client.
// =================================================================

const _tableHooks = { read: [], write: [] };
const _runHooks = (kind, opts, ctx) => {
  let cur = opts || {};
  for (const fn of _tableHooks[kind]) {
    try { cur = fn(cur, ctx) ?? cur; }
    catch (e) { console.warn('bm.table interceptor threw:', e); }
  }
  return cur;
};

export function table(name) {
  if (!name || typeof name !== 'string') {
    throw new Error('bm.table(name) requires a string table name');
  }
  // Trim leading /api/ if the agent pasted a path; trim trailing slash.
  const t = name.replace(/^\/api\//, '').replace(/\/+$/, '');
  const base = `/api/${t}`;
  return {
    name: t,
    async list(opts = {}) {
      opts = _runHooks('read', opts, { table: t, op: 'list' });
      const qs = new URLSearchParams();
      if (opts.limit)  qs.set('limit',  String(opts.limit));
      if (opts.offset) qs.set('offset', String(opts.offset));
      if (opts.cursor) qs.set('cursor', String(opts.cursor));
      if (opts.q)      qs.set('q',      String(opts.q));
      if (opts.where) {
        for (const [k, v] of Object.entries(opts.where)) qs.set(k, String(v));
      }
      const path = base + (qs.toString() ? '?' + qs : '');
      const r = await api.get(path);
      // Auto-CRUD returns a bare array OR { rows: [...] } depending on path.
      return Array.isArray(r) ? r : (r.rows || []);
    },
    get(id) {
      _runHooks('read', { id }, { table: t, op: 'get' });
      return api.get(`${base}/${id}`);
    },
    create(body) {
      const opts = _runHooks('write', { body }, { table: t, op: 'create' });
      return api.post(base, opts.body ?? body);
    },
    update(id, body) {
      const opts = _runHooks('write', { id, body }, { table: t, op: 'update' });
      return api.patch(`${base}/${opts.id ?? id}`, opts.body ?? body);
    },
    delete(id) {
      _runHooks('write', { id }, { table: t, op: 'delete' });
      return api.delete(`${base}/${id}`);
    },
    // bm.table('x').count({ where, q }) - TRUE row count, no LIMIT cap.
    //
    // Auto-CRUD list defaults to a 50-row page cap (a real app
    // session: "50 records showing but actual count is 693" surfaced
    // three times before the agent hand-rolled /api/reports/stats). This
    // hits /api/<table>?count=true which short-circuits the row fetch
    // server-side and returns just { count: N }. WHERE filters are
    // honored (`where`, `q`); LIMIT / page caps are not.
    async count(opts = {}) {
      opts = _runHooks('read', opts, { table: t, op: 'count' });
      const qs = new URLSearchParams({ count: '1' });
      if (opts.q) qs.set('q', String(opts.q));
      if (opts.where) {
        for (const [k, v] of Object.entries(opts.where)) qs.set(k, String(v));
      }
      const r = await api.get(`${base}?${qs}`);
      return (r && typeof r.count === 'number') ? r.count : 0;
    },
    // Feature methods - TS gates them at compile time per TableFeatures.
    // At runtime they always exist; the server returns 4xx when the
    // table doesn't actually support the operation.
    restore:  (id)               => api.post(`${base}/${id}/restore`),
    versions: (id)               => api.get(`${base}/${id}/versions`),
    revertTo: (id, version)      => api.post(`${base}/${id}/revert/${version}`),
  };
}

// Interceptor surface - attached to the table function itself so the
// call site reads `bm.table.before('read', fn)`. Two hook points:
//
//   'read'   fires for list / get / count   - receives (opts, ctx)
//   'write'  fires for create / update / delete - receives (opts, ctx)
//
// Hooks run in registration order; each hook's return value feeds the
// next. Returning undefined keeps the previous opts (so `() => {}` is
// a no-op, not a wipe). Throwing logs a warning + continues - never
// aborts the request, never silently drops data.
table.before = function (kind, fn) {
  if (kind !== 'read' && kind !== 'write') {
    throw new Error("bm.table.before(kind, fn): kind must be 'read' or 'write'");
  }
  if (typeof fn !== 'function') {
    throw new Error('bm.table.before(kind, fn): fn must be a function');
  }
  _tableHooks[kind].push(fn);
  // Return an unsubscribe so a feature module can undo its own
  // interceptor on teardown (test cleanup, dynamic provider swap).
  return () => {
    const i = _tableHooks[kind].indexOf(fn);
    if (i >= 0) _tableHooks[kind].splice(i, 1);
  };
};
table.clearHooks = function () {
  _tableHooks.read.length = 0;
  _tableHooks.write.length = 0;
};

// =================================================================
//  5. Live - SSE invalidation, NAMED event-aware
//
// The framework emits `event: change\ndata: {...}` - a NAMED event.
// EventSource.onmessage only catches DEFAULT events, so wiring onmessage
// alone silently drops every framework broadcast. bm.live() wires BOTH
// listeners so this trap is impossible.
//
// Usage:
//   const stop = bm.live('messages', ev => render(...));
//   stop(); // unsubscribe + close connection
//   const stop2 = bm.live('*', ev => log(ev)); // every table
// =================================================================

const _liveConns = new Map(); // share one EventSource per page

function liveBus() {
  if (_liveConns.has('__bus__')) return _liveConns.get('__bus__');
  const subs = new Set();
  const es = new EventSource('/sse/events');
  const fire = (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }
    subs.forEach(fn => { try { fn(data); } catch (e) { console.error(e); } });
  };
  es.addEventListener('change', e => fire(e.data));
  es.onmessage = e => fire(e.data);
  es.onerror = () => { /* EventSource auto-reconnects */ };
  const bus = { subs, close: () => es.close() };
  _liveConns.set('__bus__', bus);
  return bus;
}

export function live(tableOrStar, cb) {
  if (typeof cb !== 'function') {
    throw new Error('bm.live(table, callback) requires a function');
  }
  const bus = liveBus();
  const handler = (data) => {
    // table === '' means "generic refresh hint for an owner-scoped table
    // you can't see the row of." `*` subscribers always get it.
    if (tableOrStar === '*' ||
        data.table === tableOrStar ||
        data.action === 'refresh') {
      cb(data);
    }
  };
  bus.subs.add(handler);
  return () => bus.subs.delete(handler);
}

// bm.live.scoped(table, fetchAndRender, opts) - `live()` with the
// production-grade plumbing baked in:
//
//   - **Generation counter**: only the freshest fetch can write to
//     state. When SSE fires a burst (insert + membership + conv update
//     in ~30ms, an earlier app build's exact pattern), older in-flight
//     fetches that resolve later are dropped instead of overwriting
//     the freshest one. Pre-2.7.37 every app re-derived this counter
//     pattern manually.
//
//   - **Trailing-edge debounce**: bursts of events coalesce into a
//     single fetch fired `debounce` ms after the LAST event. Avoids
//     N round-trips for N events; the framework's SSE fan-out is
//     intentionally chatty (every CRUD mutation emits) so debouncing
//     downstream is the right pattern.
//
// `fetchAndRender` is called with no args; it should read whatever
// data it needs (auto-CRUD list, custom flow, whatever) and update
// the DOM. Return value ignored. Errors caught + logged.
//
// Returns an unsubscribe function. Calling it stops the SSE
// subscription AND cancels any pending debounced fetch.
//
//   const unsub = bm.live.scoped('messages', refreshChat, { debounce: 60 });
//   // ... later
//   unsub();
live.scoped = function liveScoped(tableOrStar, fetchAndRender, opts) {
  if (typeof fetchAndRender !== 'function') {
    throw new Error('bm.live.scoped(table, fetchAndRender, opts) requires a function');
  }
  const debounceMs = (opts && typeof opts.debounce === 'number') ? opts.debounce : 60;
  let generation = 0;
  let pendingTimer = null;

  const runFetch = async () => {
    const my = ++generation;
    pendingTimer = null;
    try {
      const result = fetchAndRender();
      if (result && typeof result.then === 'function') {
        await result;
      }
    } catch (err) {
      console.warn('[bm.live.scoped] fetchAndRender threw:', err);
    }
    // If newer fetches kicked off while we were awaiting, ours is
    // stale - caller doesn't care, the newer one wins. The generation
    // counter is the discriminator; we don't actually need to do
    // anything here since fetchAndRender is responsible for its own
    // state updates (which we hope are also generation-guarded for
    // user-side render correctness).
    void my;
  };

  const schedule = () => {
    if (pendingTimer != null) clearTimeout(pendingTimer);
    pendingTimer = setTimeout(runFetch, debounceMs);
  };

  // Fire immediately on subscribe so the caller doesn't need to
  // double-call: `bm.live.scoped('x', refresh); refresh();`. Just
  // pass the renderer and we'll prime the view on mount.
  schedule();

  const unsub = live(tableOrStar, () => schedule());

  // Visibility hook: when the tab returns to foreground, fire a
  // fresh fetch - many SSE events get dropped by browsers that
  // sleep the page while it's backgrounded. An earlier app build built
  // this manually; bake in.
  let visibilityHandler = null;
  if (typeof document !== 'undefined') {
    visibilityHandler = () => {
      if (!document.hidden) schedule();
    };
    document.addEventListener('visibilitychange', visibilityHandler);
  }

  return () => {
    unsub();
    if (pendingTimer != null) {
      clearTimeout(pendingTimer);
      pendingTimer = null;
    }
    if (visibilityHandler && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', visibilityHandler);
    }
  };
};

// =================================================================
//  6. Rooms - WebSocket room broadcast (chat, presence, WebRTC signaling)
//
// As of v2.7.10 broadcasts deliver cross-user in same-app scenarios.
// Multi-tenant isolation (groups: config) still applies.
//
// Usage:
//   const room = bm.room('lobby');
//   room.on('hello',   (payload, from) => greet(from));
//   room.onAny((payload, from) => log(payload));
//   room.send({ kind: 'hello' });
//   room.leave();
// =================================================================

export function room(name) {
  if (!name || typeof name !== 'string') {
    throw new Error('bm.room(name) requires a string room name');
  }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  const namedHandlers = new Map(); // kind -> Set<fn>
  const anyHandlers = new Set();
  let queue = [];
  let open = false;

  ws.onopen = () => {
    open = true;
    ws.send(JSON.stringify({ type: 'join', room: name }));
    queue.forEach(p => ws.send(JSON.stringify({ type: 'broadcast', room: name, payload: p })));
    queue = null;
  };
  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.type !== 'message' && msg.type !== 'presence') return;
    const payload = msg.payload || {};
    const from = msg.from;
    const kind = payload.kind || msg.type; // 'presence' has no kind
    const set = namedHandlers.get(kind);
    if (set) set.forEach(fn => { try { fn(payload, from); } catch (e) { console.error(e); } });
    anyHandlers.forEach(fn => { try { fn(payload, from, kind); } catch (e) { console.error(e); } });
  };

  return {
    name,
    on(kind, fn) {
      if (!namedHandlers.has(kind)) namedHandlers.set(kind, new Set());
      namedHandlers.get(kind).add(fn);
      return this;
    },
    onAny(fn) { anyHandlers.add(fn); return this; },
    off(kind, fn) {
      namedHandlers.get(kind)?.delete(fn);
      return this;
    },
    send(payload) {
      if (open) {
        ws.send(JSON.stringify({ type: 'broadcast', room: name, payload }));
      } else {
        queue.push(payload);
      }
    },
    leave() {
      if (open) ws.send(JSON.stringify({ type: 'leave', room: name }));
      ws.close();
    },
    raw: ws,
  };
}

// =================================================================
//  7. Flows - per-flow methods generated from flows.yaml
//
// At runtime there's no per-flow client - the agent calls
// bm.flows.<flowName>(params, body), which routes to the URL by
// looking up a runtime registry written by the type generator at
// /_internal/flows.json. We Proxy() the lookup so unknown names
// throw a clear runtime error to match the TS error.
// =================================================================

let _flowsRegistry = null;
async function loadFlowsRegistry() {
  if (_flowsRegistry !== null) return _flowsRegistry;
  try {
    const r = await fetch('/_internal/flows.json', { credentials: 'same-origin' });
    if (r.ok) _flowsRegistry = await r.json();
    else _flowsRegistry = {};
  } catch { _flowsRegistry = {}; }
  return _flowsRegistry;
}

export const flows = new Proxy({}, {
  get(_target, flowName) {
    if (typeof flowName !== 'string') return undefined;
    return async (params = {}, body) => {
      const reg = await loadFlowsRegistry();
      const entry = reg[flowName];
      if (!entry) throw new Error(`bm.flows.${flowName} is not declared in flows.yaml`);
      // Substitute :path params.
      let path = entry.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`:${k}`, encodeURIComponent(String(v)));
      }
      const method = (entry.method || 'POST').toUpperCase();
      const res = await request(method, path, body);
      if (!res.ok) {
        const err = new Error(res.data?.error || `flow ${flowName} failed (${res.status})`);
        err.status = res.status; err.body = res.data;
        throw err;
      }
      // Async flows return {job_id, status_url} - wrap into a Job handle.
      if (res.data && res.data.job_id && res.data.status_url) {
        return makeJob(res.data.job_id, res.data.status_url);
      }
      return res.data;
    };
  }
});

// =================================================================
//  8. Workflows - typed state-machine client
//     bm.workflow('orders', 7).transitionTo('shipped')
//     bm.workflow('orders', 7).available()
//     bm.workflow('orders', 7).current()
// =================================================================

export function workflow(table, id) {
  if (!table || id === undefined || id === null) {
    throw new Error('bm.workflow(table, id) requires both args');
  }
  const base = `/api/${encodeURIComponent(table)}/${encodeURIComponent(String(id))}`;
  return {
    table,
    id,
    // Server expects { to: <newState> } (workflows.go handleTransition).
    transitionTo: (state) => api.post(`${base}/transition`, { to: state }),
    available:    () => api.get(`${base}/transitions`),
    current:      async () => {
      const row = await api.get(`/api/${encodeURIComponent(table)}/${encodeURIComponent(String(id))}`);
      return row.state ?? row.status;
    },
  };
}

// =================================================================
//  9. Aggregates - materialized SQL values
//     bm.aggregate('total_revenue')   → scalar
//     bm.aggregates.all()              → { name: value, ... }
// =================================================================

// The framework exposes /api/_aggregates as a single list endpoint -
// no per-name route. We fetch the whole list (cheap, ~N rows) and
// pick out the one the caller asked for. The list is cached on the
// server side so this is one round-trip then a hash lookup.
export async function aggregate(name) {
  const r = await api.get('/api/_aggregates');
  const list = (r && (r.aggregates || r)) || [];
  if (Array.isArray(list)) {
    const hit = list.find(a => a && a.name === name);
    return hit ? (hit.value ?? null) : null;
  }
  // Map shape: { name: value }
  return (r && r[name] !== undefined) ? r[name] : null;
}

export const aggregates = {
  get: aggregate,
  async all() {
    const r = await api.get('/api/_aggregates');
    const list = (r && (r.aggregates || r)) || [];
    if (!Array.isArray(list)) return r;
    return Object.fromEntries(list.map(a => [a.name, a.value]));
  },
};

// =================================================================
//  10. Jobs - async-flow status + wait helper
// =================================================================

function makeJob(jobId, statusUrl) {
  return {
    job_id: jobId,
    status_url: statusUrl,
    status: () => api.get(`/api/_jobs/${encodeURIComponent(jobId)}/status`),
    wait: (opts = {}) => waitForJob(jobId, opts),
  };
}

async function waitForJob(jobId, { intervalMs = 1000, timeoutMs = 5 * 60 * 1000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const status = await api.get(`/api/_jobs/${encodeURIComponent(jobId)}/status`);
    if (status.status === 'completed') return status.result;
    if (status.status === 'failed') {
      const err = new Error(status.error || `job ${jobId} failed`);
      err.status = status; throw err;
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new Error(`job ${jobId} timed out after ${timeoutMs}ms`);
}

export const jobs = {
  status: (jobId) => api.get(`/api/_jobs/${encodeURIComponent(jobId)}/status`),
  wait: waitForJob,
};

// =================================================================
//  11. Notifications - in-app inbox
// =================================================================

export const notifications = {
  async list(opts = {}) {
    const qs = new URLSearchParams();
    if (opts.limit)  qs.set('limit',  String(opts.limit));
    if (opts.offset) qs.set('offset', String(opts.offset));
    if (opts.unread) qs.set('unread', '1');
    const path = '/api/_notifications' + (qs.toString() ? '?' + qs : '');
    const r = await api.get(path);
    return Array.isArray(r) ? r : (r.notifications || []);
  },
  markRead:    (id) => api.patch(`/api/_notifications/${encodeURIComponent(id)}/read`),
  markAllRead: ()   => api.post('/api/_notifications/read-all'),
  delete:      (id) => api.delete(`/api/_notifications/${encodeURIComponent(id)}`),
  onNew(cb) {
    return live('_benmore_notifications', (ev) => {
      if (ev.action === 'insert') cb(ev.row);
    });
  },
};

// =================================================================
//  12. Upload - multipart file upload
// =================================================================

// The framework's upload handler accepts CSRF in EITHER the header
// OR a `_csrf` form field. Sending both makes the call work whether
// the deployed framework version honors header-CSRF for multipart
// (newer) or only form-CSRF (older).
export async function upload(file, opts = {}) {
  const csrf = CSRF_META();
  const fd = new FormData();
  fd.append('file', file, opts.filename || (file.name || 'upload'));
  if (opts.kind) fd.append('kind', opts.kind);
  if (csrf) fd.append('_csrf', csrf);
  const res = await fetch('/api/_upload', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': csrf },
    body: fd,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`upload failed (${res.status}): ${text}`);
  }
  return res.json();
}

// =================================================================
//  13. Audit log (admin endpoint)
// =================================================================

export const audit = {
  async list(filter = {}) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(filter)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
    }
    const path = '/api/_audit' + (qs.toString() ? '?' + qs : '');
    const r = await api.get(path);
    return Array.isArray(r) ? r : (r.entries || []);
  },
};

// =================================================================
//  14. Permissions - per-row ACLs
// =================================================================

// Permission enum matches the framework's permissionLevel map:
// 'view' | 'edit' | 'delete' | 'admin' (see permissions.go).
// Body shape: { email, permission, expires_at? }.
export const permissions = {
  share:  (table, id, email, permission = 'view', expires_at) =>
    api.post(`/api/${encodeURIComponent(table)}/${encodeURIComponent(String(id))}/share`,
             { email, permission, ...(expires_at ? { expires_at } : {}) }),
  revoke: (table, id, email) =>
    api.delete(`/api/${encodeURIComponent(table)}/${encodeURIComponent(String(id))}/permissions/${encodeURIComponent(email)}`),
  list:   (table, id) =>
    api.get(`/api/${encodeURIComponent(table)}/${encodeURIComponent(String(id))}/permissions`),
};

// =================================================================
//  15. Signed URLs - time-limited file access
// =================================================================

// The framework exposes GET /api/_signed_url?path=...&expires_in=...
// (signed_urls.go). Older docs spelled this `/api/_signed-url` (POST);
// stay aligned with the live shape.
// signedUrl(path, opts) - mint a time-limited URL for a file.
//   opts can be a number (ttlSeconds, back-compat) OR
//   { ttlSeconds?, record?: { table, id } }.
// PRIVATE files on the platform media CDN REQUIRE `record` - the row that
// owns the file. The server authorizes the signature against THAT record's
// access policy (roles, perms, scopes, group/owner/ACL), not just a logged-in
// session, then signs. Public / local files don't need it.
//   await bm.signedUrl(doc.file_url, { record: { table: 'documents', id: doc.id } })
export async function signedUrl(path, opts = 300) {
  let ttlSeconds = 300, record = null;
  if (typeof opts === 'number') ttlSeconds = opts;
  else if (opts && typeof opts === 'object') { ttlSeconds = opts.ttlSeconds ?? opts.ttl ?? 300; record = opts.record || null; }
  const qs = new URLSearchParams({ path: String(path), expires_in: String(ttlSeconds) });
  if (record && record.table && record.id != null) {
    qs.set('record_table', String(record.table));
    qs.set('record_id', String(record.id));
  }
  const r = await api.get('/api/_signed_url?' + qs.toString());
  // Prefer the ROOT-RELATIVE path: it inherits the page's scheme/host, so
  // it works on https (the absolute `url` is built http:// behind CF/TLS
  // termination and would be blocked as mixed-content + CSP img-src 'self').
  return r.path || r.url || r;
}

// =================================================================
//  16. I18n - typed translation helper
//
// At runtime, the framework injects the active language's dictionary
// as window.__bm_i18n.strings via the per-page bootstrap. bm.t reads
// from there and falls back to the raw key when missing.
// =================================================================

export function t(key, vars) {
  const dict = (typeof window !== 'undefined' && window.__bm_i18n?.strings) || {};
  let out = dict[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      out = out.replace(new RegExp(`\\{\\{\\s*${k}\\s*\\}\\}`, 'g'), String(v));
    }
  }
  return out;
}

// =================================================================
//  17. MFA - TOTP enrollment + verification
// =================================================================

// =================================================================
//  13b. Broadcast - SFU-backed 1:N livestream (v2.7.29+)
//
// Peer-mesh WebRTC chokes at ~5 viewers because the publisher uploads
// N copies of their media (one per viewer). bm.broadcast routes media
// through Cloudflare Realtime SFU - publisher uploads ONCE, the SFU
// fans out. Scales to hundreds of viewers; sub-second latency.
//
// Usage:
//
//   // Publisher (the streamer):
//   const stream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});
//   const broadcast = await bm.broadcast.publish('my-stream-slug', stream);
//   // … broadcast.stop() when done
//
//   // Subscriber (every viewer):
//   const subscription = await bm.broadcast.subscribe('my-stream-slug');
//   videoElement.srcObject = subscription.stream;
//   // … subscription.stop() when leaving
//
//   // Stats (anyone, for "N watching" pills):
//   const { live, viewers } = await bm.broadcast.stats('my-stream-slug');
//
// Falls back gracefully when the platform operator hasn't configured
// an SFU app - bm.broadcast.publish() throws { status: 503,
// reason: 'SFU not configured' } and apps can recover to peer-mesh.
// =================================================================

async function broadcastIceServers() {
  // Re-use the same TURN/STUN resolver - SFU sessions still need ICE.
  try { return await webrtc.iceServers(); }
  catch { return [{ urls: ['stun:stun.l.google.com:19302'] }]; }
}

// waitForICEGathering blocks until the PC has finished gathering ICE
// candidates (or a timeout fires). Without this the SDP we send to
// CF's SFU has no ICE candidates → CF can't establish the UDP
// connection → SDP exchange succeeds but media never flows.
// 2s timeout: ICE gathering on a healthy network completes in <500ms;
// the timeout is a backstop in case `iceGatheringState === 'complete'`
// never fires (rare browser bug - Firefox <90 with certain TURN setups).
function waitForICEGathering(pc) {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise(resolve => {
    let done = false;
    const finish = () => { if (done) return; done = true; resolve(); };
    pc.addEventListener('icegatheringstatechange', () => {
      if (pc.iceGatheringState === 'complete') finish();
    });
    setTimeout(finish, 2000);
  });
}

async function broadcastSDPExchange(path, slug, sdpOffer) {
  const res = await request('POST', path, { slug, sdp: sdpOffer });
  if (!res.ok) {
    const err = new Error(res.data?.error || 'broadcast: SDP exchange failed');
    err.status = res.status;
    err.body = res.data;
    throw err;
  }
  return res.data; // { sdp, session_id, slug }
}

// subscribeWithPolicy is the workhorse behind bm.broadcast.subscribe.
// First call uses iceTransportPolicy: 'all' (default) - tries direct
// path, then reflexive, then relay. If ICE state hits 'failed' or
// stalls in 'checking' for >10s (typical cellular symptom - UDP packets
// silently dropped by carrier NAT), we tear down and retry with
// iceTransportPolicy: 'relay'. That forces every candidate to go through
// TURN, which CF can ALWAYS reach because TURN gives the subscriber a
// stable, externally-reachable allocation address.
//
// Why subscribers need this more than publishers: publishers send a
// constant stream of RTP packets to CF, keeping the NAT mapping fresh.
// Subscribers send only sparse RTCP feedback, so address-restricted
// cone NATs (common on cellular) often refuse CF's RTP responses after
// the first few seconds. TURN solves this by holding a stable allocation.
async function subscribeWithPolicy(slug, policy, attempt = 1) {
  const ice = await broadcastIceServers();
  const pc = new RTCPeerConnection({ iceServers: ice, iceTransportPolicy: policy });

  pc.addTransceiver('video', { direction: 'recvonly' });
  pc.addTransceiver('audio', { direction: 'recvonly' });

  const remoteStream = new MediaStream();
  pc.ontrack = (ev) => {
    if (ev.streams && ev.streams[0]) {
      ev.streams[0].getTracks().forEach(t => remoteStream.addTrack(t));
    } else {
      remoteStream.addTrack(ev.track);
    }
  };

  // ICE connection-state probe. If we hit 'failed' OR stay stuck in
  // 'checking' / 'new' for too long, retry once with relay-only. Most
  // cellular failures show up as 'checking' that never advances -
  // UDP packets just get dropped at the carrier.
  let resolved = false;
  const failurePromise = new Promise((_, reject) => {
    const watchdog = setTimeout(() => {
      if (!resolved) reject(new Error(`subscribe ICE timeout (state=${pc.iceConnectionState}, policy=${policy})`));
    }, 10000);
    pc.addEventListener('iceconnectionstatechange', () => {
      const s = pc.iceConnectionState;
      if (s === 'connected' || s === 'completed') {
        resolved = true;
        clearTimeout(watchdog);
      } else if (s === 'failed' || s === 'disconnected') {
        clearTimeout(watchdog);
        reject(new Error(`subscribe ICE ${s} (policy=${policy})`));
      }
    });
  });

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await waitForICEGathering(pc);

  const sdpExchange = await broadcastSDPExchange('/api/_broadcast/subscribe', slug, pc.localDescription.sdp);
  await pc.setRemoteDescription({ type: 'answer', sdp: sdpExchange.sdp });

  // Race ICE-success against the failure/timeout watchdog. If the
  // browser can't establish a path within 10s, retry over TURN-relay
  // ONLY. Don't retry forever - second failure means the network is
  // genuinely unreachable and we surface the error.
  try {
    await Promise.race([
      failurePromise,
      new Promise(resolve => {
        if (pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed') {
          resolved = true;
          resolve();
        } else {
          const check = () => {
            const s = pc.iceConnectionState;
            if (s === 'connected' || s === 'completed') {
              resolved = true;
              pc.removeEventListener('iceconnectionstatechange', check);
              resolve();
            }
          };
          pc.addEventListener('iceconnectionstatechange', check);
        }
      }),
    ]);
  } catch (e) {
    try { pc.close(); } catch {}
    if (attempt === 1 && policy !== 'relay') {
      console.warn('[bm.broadcast] direct/STUN subscribe failed, retrying via TURN relay:', e?.message || e);
      return subscribeWithPolicy(slug, 'relay', 2);
    }
    throw e;
  }

  let stopped = false;
  return {
    slug,
    sessionId: sdpExchange.session_id,
    pc,
    stream: remoteStream,
    policy,
    stop() {
      if (stopped) return;
      stopped = true;
      try { pc.close(); } catch {}
    },
  };
}

export const broadcast = {
  /**
   * Publish a MediaStream to the SFU under `slug`. Returns a handle
   * with .stop() to tear down. Throws when SFU isn't configured -
   * caller can catch and fall back to peer-mesh.
   */
  async publish(slug, mediaStream) {
    const ice = await broadcastIceServers();
    const pc = new RTCPeerConnection({ iceServers: ice });

    // Add every track from the supplied stream. CF infers the
    // direction (recv/send) from the SDP, so just sendonly tracks
    // for a publisher.
    for (const track of mediaStream.getTracks()) {
      pc.addTransceiver(track, { direction: 'sendonly', streams: [mediaStream] });
    }

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    // CRITICAL: wait for ICE gathering to finish so pc.localDescription
    // has the candidate lines baked in. Without this, CF receives an
    // offer with no candidates → no UDP path → media never flows even
    // though SDP exchange succeeds. Classic WebRTC race; symptom is
    // "black screen but everything looks fine in the logs".
    await waitForICEGathering(pc);

    const { sdp, session_id } = await broadcastSDPExchange('/api/_broadcast/publish', slug, pc.localDescription.sdp);
    await pc.setRemoteDescription({ type: 'answer', sdp });

    let stopped = false;
    return {
      slug,
      sessionId: session_id,
      pc,
      async stop() {
        if (stopped) return;
        stopped = true;
        try { pc.close(); } catch {}
        try { await request('POST', '/api/_broadcast/stop', { slug }); } catch {}
      },
    };
  },

  /**
   * Subscribe to a published slug. Returns { stream, pc, stop() }.
   * `stream` is a MediaStream you can wire into <video>.srcObject.
   *
   * Options:
   *   waitForPublisher: ms to keep retrying when no publisher is live
   *                     yet (404 / 503). Defaults to 30000. Set to 0
   *                     to fail fast on the first call (legacy behavior).
   *                     Multiple apps had to hand-roll
   *                     this loop because the SDK threw on the publisher
   *                     race ("A subscribes to B before B's publish
   *                     finishes ICE gathering" - both viewer-side and
   *                     huddle-second-joiner cases).
   *   signal:           AbortSignal to cancel the retry loop early.
   */
  async subscribe(slug, opts = {}) {
    const waitMs = opts.waitForPublisher === undefined ? 30000 : opts.waitForPublisher;
    const signal = opts.signal;
    const deadline = Date.now() + waitMs;
    let attempt = 0;
    let lastErr;
    while (true) {
      if (signal && signal.aborted) {
        throw new Error('bm.broadcast.subscribe aborted');
      }
      try {
        return await subscribeWithPolicy(slug, 'all');
      } catch (e) {
        lastErr = e;
        // Only retry on "no publisher yet" shapes: 404 (slug not in
        // _benmore_broadcasts), 503 ({reason: 'publisher not live'}),
        // or a 503-like 4xx where the server's stats endpoint would
        // report live:false. ICE failures, network drops, auth 401s,
        // CSP rejections - all propagate immediately.
        const status = e?.status;
        const transient = status === 404 || status === 503;
        if (!transient || Date.now() >= deadline) throw e;
        // Backoff: 500ms, 1s, 2s, 4s, capped at 4s. Total wait inside
        // waitMs naturally.
        const delay = Math.min(500 * Math.pow(2, attempt), 4000);
        attempt++;
        await new Promise(r => setTimeout(r, delay));
      }
    }
    /* eslint-disable-next-line no-unreachable */
    throw lastErr;
  },

  /**
   * Returns { live: bool, viewers: number, started_at?: string }.
   * Safe to poll; cheap (one indexed lookup).
   */
  async stats(slug) {
    const res = await request('GET', `/api/_broadcast/stats/${encodeURIComponent(slug)}`);
    return res.data || { live: false, viewers: 0 };
  },
};

// =================================================================
//  14. WebRTC - ICE servers (STUN + optional TURN)
//
// Agents building peer-to-peer apps (livestream, voice, screen-share)
// should NEVER hand-roll ICE config. STUN alone fails for ~30-50% of
// real-world connections (symmetric NAT on cellular, double-NAT homes).
// `bm.webrtc.iceServers()` returns whatever the framework has been
// configured to mint - STUN by default, plus TURN when the operator
// sets TURN_PROVIDER + creds via `benmore env set` on the deployed app.
//
// Cached in-memory per-tab for 30min (TURN creds typically last 1h
// server-side; we refresh before they expire).
// =================================================================

let _iceCache = null;
let _iceCacheUntil = 0;

export const webrtc = {
  /**
   * Returns the configured ICE servers array, suitable to pass directly
   * to `new RTCPeerConnection({ iceServers: ... })`.
   *
   * Always includes STUN. Includes TURN when the operator configured
   * one (TURN_PROVIDER + TURN_CF_APP_ID/TURN_CF_APP_TOKEN for Cloudflare,
   * or TURN_URL/TURN_USERNAME/TURN_CREDENTIAL for a static provider).
   */
  async iceServers() {
    if (_iceCache && Date.now() < _iceCacheUntil) return _iceCache;
    const res = await request('GET', '/api/_webrtc/ice');
    const list = res.data?.iceServers || [{ urls: ['stun:stun.l.google.com:19302'] }];
    _iceCache = list;
    _iceCacheUntil = Date.now() + 30 * 60 * 1000;
    return list;
  },
};

export const mfa = {
  enroll:  ()         => api.post('/api/_auth/mfa/setup'),
  verify:  (code)     => api.post('/api/_auth/mfa/verify', { code }),
  disable: (password) => api.post('/api/_auth/mfa/disable', { password }),
};

// =================================================================
//  18. Soft-delete restore + versioning helpers - patched onto the
//      table() return value when the table has the feature. Pure
//      runtime: when the developer hits .restore on a table that
//      doesn't have deleted_at, the server returns a clear error.
//      The TS types stop the call at compile time.
// =================================================================

// (Already inside table() factory above for runtime - the type
// declaration in bm.d.ts gates compile-time access.)

// =================================================================
//  Default export
// =================================================================

// =================================================================
//  bm.html - XSS-safe tagged template literal (v2.7.66+)
//
//  Every interpolated value gets HTML-escaped automatically. Stop
//  writing manual escapeHtml() calls; stop forgetting them. Use this
//  for ALL innerHTML / template-literal HTML construction.
//
//    el.innerHTML = bm.html`<li>${user.name}</li>`;        // safe
//    el.innerHTML = bm.html`<a href="${url}">${title}</a>`; // both escaped
//
//  Opt-out per-value via bm.raw(html) when the value is ALREADY safe
//  HTML (component output, sanitized markdown, framework-rendered icons):
//
//    el.innerHTML = bm.html`<div>${bm.raw(iconHtml)}${user.name}</div>`;
//
//  Arrays of strings are joined automatically, so a render loop reads:
//
//    el.innerHTML = bm.html`<ul>${rows.map(r => bm.html`<li>${r.name}</li>`)}</ul>`;
//
//  Notes:
//   - Returns a plain string - drop-in replacement for normal template
//     literals; nothing else changes about the calling code.
//   - Escapes the 5 XSS-relevant characters: & < > " '
//   - Nested bm.html`…` values are NOT double-escaped (they're tagged
//     as raw via a hidden symbol so the outer template knows they're
//     already safe). Same idea as React/lit's html`` tag.
//   - null / undefined render as empty string (matches lit / Preact).
// =================================================================

const _bmHtmlSafe = Symbol('bm.html.safe');

function _escForHtml(s) {
  const str = String(s);
  // Single-pass replace via charCodeAt is faster than chained .replace
  // for typical short strings; the difference matters in render loops
  // that hit thousands of cells per second.
  let out = '';
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if      (c === 38) out += '&amp;';   // &
    else if (c === 60) out += '&lt;';    // <
    else if (c === 62) out += '&gt;';    // >
    else if (c === 34) out += '&quot;';  // "
    else if (c === 39) out += '&#39;';   // '
    else               out += str[i];
  }
  return out;
}

function _interpolate(v) {
  if (v == null) return '';
  // Already-safe HTML (from bm.raw / nested bm.html / Array of either).
  if (typeof v === 'object' && v[_bmHtmlSafe] === true) return v.value;
  if (Array.isArray(v)) {
    let out = '';
    for (const item of v) out += _interpolate(item);
    return out;
  }
  return _escForHtml(v);
}

export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    out += _interpolate(values[i]) + strings[i + 1];
  }
  // Tag the result so it can be nested into another bm.html`...`
  // without being escaped a second time.
  return { [_bmHtmlSafe]: true, value: out, toString() { return out; } };
}

/** Mark a string as already-safe HTML - escapes the surrounding
 *  bm.html`...` interpolation but trusts THIS value verbatim. Use for
 *  component output, sanitized markdown, framework icon helpers. */
export function raw(htmlString) {
  return { [_bmHtmlSafe]: true, value: String(htmlString ?? '') };
}

// markdown - async loader for /_internal/markdown.js. Imported lazily
// on first call so apps that don't render markdown don't pay the
// download cost. The renderer escapes HTML before parsing, allowlists
// http/https/mailto link schemes, and supports **bold** / *italic* /
// `code` / ```fenced``` / [links](url) / lists / blockquotes. Chat,
// notes, comments - anywhere user-provided text becomes display HTML.
//
//   const html = await bm.markdown(messageText);
//   messageEl.innerHTML = html;
let _mdImpl = null;
async function markdown(text) {
  if (_mdImpl == null) {
    const m = await import('/_internal/markdown.js');
    _mdImpl = m.markdown || m.default;
  }
  return _mdImpl(text);
}

// =================================================================
//  presence - "who is live in <slug> right now"
//
//  Wraps the three-layer pattern every chat / huddle / live app
//  hand-rolled before v2.7.35:
//    - 20s heartbeat PATCH so the server knows the tab is alive
//    - pagehide + sendBeacon to mark "I've left" on tab close
//    - server cron that sweeps expired rows (presence.go)
//
//  Usage:
//    const p = bm.presence('huddle:42');  // joins, starts heartbeat
//    p.members();                          // → [{user_id, joined_at,...}]
//    p.leave();                            // explicit; pagehide auto-fires
//
//  Stays subscribed to `_benmore_presence` SSE events so any change
//  (anyone joining / leaving / sweep expiry) triggers an updated count.
// =================================================================

function presence(slug) {
  if (typeof slug !== 'string' || !slug) {
    throw new Error('bm.presence(slug) requires a non-empty string');
  }
  let left = false;
  let heartbeatTimer = null;
  let onChangeUnsub = null;

  const post = (action) => api.post('/api/_presence/heartbeat', { slug, action }).catch(() => {});
  const sendBeaconLeave = () => {
    // Beacon survives tab close - fetch with keepalive is the right
    // primitive but sendBeacon is the only one with universal support.
    if (left) return;
    left = true;
    try {
      const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
      const blob = new Blob(
        [JSON.stringify({ slug, action: 'leave', _csrf: csrf })],
        { type: 'application/json' }
      );
      navigator.sendBeacon?.('/api/_presence/heartbeat', blob);
    } catch {}
  };

  // Initial join + start the 18s heartbeat (slightly under the 20s
  // the server advertises so we're never close to the boundary).
  post('join');
  heartbeatTimer = setInterval(() => { if (!left) post('heartbeat'); }, 18000);

  // pagehide is more reliable than beforeunload across browsers.
  // Both fire when the tab is closed; pagehide also fires on bfcache.
  if (typeof window !== 'undefined') {
    window.addEventListener('pagehide', sendBeaconLeave);
    window.addEventListener('beforeunload', sendBeaconLeave);
  }

  return {
    slug,
    async members() {
      const res = await api.get('/api/_presence?slug=' + encodeURIComponent(slug));
      return Array.isArray(res?.members) ? res.members : [];
    },
    async count() {
      const res = await api.get('/api/_presence?slug=' + encodeURIComponent(slug));
      return typeof res?.count === 'number' ? res.count : 0;
    },
    // Subscribe to SSE invalidations on the presence table; callback
    // fires after any join/leave/sweep so the caller can refresh.
    onChange(fn) {
      if (typeof fn !== 'function') return () => {};
      onChangeUnsub = live('_benmore_presence', () => fn());
      return onChangeUnsub;
    },
    leave() {
      if (left) return;
      left = true;
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
      if (onChangeUnsub) { onChangeUnsub(); onChangeUnsub = null; }
      post('leave');
    },
  };
}

// =================================================================
//  cache - self-busting sessionStorage / localStorage helper
//
//  One app.s pre-paint pattern (a sessionStorage cache key) went
//  stale when v=6 → v=7 because the cache version was hardcoded and
//  never tied to the actual bundle's mtime. Result: agents shipped a
//  new sidebar, browsers painted the OLD cached one, debugging cost
//  hours.
//
//  bm.cache.namespaced(name, version) returns a 4-method client whose
//  storage key includes the version. On version change, the old key
//  reads as miss (it's there but invisible) and a subsequent write
//  lands at the new key - the old entry GCs naturally when storage
//  pressure hits, or you can call .purgeOld() to evict eagerly.
//
//  Usage:
//    const shell = bm.cache.namespaced('shell', staticAssetVersion);
//    shell.get();              // → cached value or undefined
//    shell.set(html);          // store
//    shell.clear();            // current-version only
//    shell.purgeOld();         // drop every prior version of this name
// =================================================================

function makeCacheNamespace(storage, name, version) {
  if (!storage || typeof name !== 'string' || !name) return null;
  const ver = String(version || 'v0');
  const key = `bm:${name}:${ver}`;
  const prefix = `bm:${name}:`;
  return {
    name, version: ver,
    get() {
      try { return storage.getItem(key) ?? undefined; } catch { return undefined; }
    },
    set(value) {
      try { storage.setItem(key, String(value)); } catch {}
    },
    clear() {
      try { storage.removeItem(key); } catch {}
    },
    purgeOld() {
      try {
        for (let i = storage.length - 1; i >= 0; i--) {
          const k = storage.key(i);
          if (k && k.startsWith(prefix) && k !== key) storage.removeItem(k);
        }
      } catch {}
    },
  };
}

const cache = {
  /** Session-scoped self-busting cache. Survives the tab but not the
   * browser process. The right choice for "pre-paint the shell" and
   * other this-session ephemera. */
  namespaced(name, version) {
    if (typeof sessionStorage === 'undefined') return null;
    return makeCacheNamespace(sessionStorage, name, version);
  },
  /** Persistent self-busting cache. Survives reloads + browser
   * restarts. Use for "remember the user's last filter" - anything
   * useful across sessions but invalidatable per-deploy. */
  persistent(name, version) {
    if (typeof localStorage === 'undefined') return null;
    return makeCacheNamespace(localStorage, name, version);
  },
};

const bm = {
  api, auth, users, table, live, room,
  flows, workflow, aggregate, aggregates, jobs,
  notifications, upload, audit, permissions, signedUrl,
  t, mfa, webrtc, broadcast, markdown, presence, cache,
  html, raw,
};
export default bm;

// Optional global for plain-JS pages without an import map.
if (typeof window !== 'undefined') window.bm = bm;

// =================================================================
//  Client error capture → POST /api/_errors → _benmore_client_errors.
//  Powers the get_client_errors MCP tool + Sentry/Slack forwarding.
//  Installs window.onerror + unhandledrejection (the two ways JS
//  surfaces an uncaught failure - the 404-from-a-fetch case is an
//  unhandled rejection, so BOTH are required). Throttled + deduped so
//  an error loop can't spam the endpoint.
// =================================================================
if (typeof window !== 'undefined') {
  let _errSent = 0, _errLast = '';
  const _ERR_CAP = 25;
  const _postErr = (p) => {
    if (_errSent >= _ERR_CAP) return;
    const key = (p.message || '') + '|' + (p.source || '') + '|' + (p.line || 0);
    if (key === _errLast) return; // collapse immediate duplicates
    _errLast = key; _errSent++;
    try {
      fetch('/api/_errors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(p),
        keepalive: true,
        credentials: 'same-origin',
      }).catch(() => {}); // never let reporting throw (would loop)
    } catch (_) {}
  };
  window.addEventListener('error', (e) => {
    // Resource-load errors (img/script 404s) have no .message - skip them.
    if (!e || !e.message) return;
    _postErr({
      kind: 'error',
      message: String(e.message).slice(0, 2000),
      stack: e.error && e.error.stack ? String(e.error.stack).slice(0, 8000) : '',
      source: e.filename || '',
      line: e.lineno || 0,
      col: e.colno || 0,
      url: location.href,
    });
  });
  window.addEventListener('unhandledrejection', (e) => {
    const r = e && e.reason;
    const msg = r && r.message ? r.message : (typeof r === 'string' ? r : 'Unhandled promise rejection');
    _postErr({
      kind: 'unhandledrejection',
      message: String(msg).slice(0, 2000),
      stack: r && r.stack ? String(r.stack).slice(0, 8000) : '',
      source: '',
      line: 0,
      col: 0,
      url: location.href,
    });
  });
}
