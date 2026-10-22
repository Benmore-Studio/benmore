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

async function request(method, path, body, options) {
  const headers = new Headers({ Accept: 'application/json' });
  if (options?.headers) {
    new Headers(options.headers).forEach((value, name) => headers.set(name, value));
  }
  const init = { method, credentials: 'same-origin', headers };
  if (options?.signal !== undefined) init.signal = options.signal;
  if (body !== undefined && body !== null) {
    headers.set('Content-Type', 'application/json');
    init.body = JSON.stringify(body);
  }
  if (method !== 'GET' && method !== 'HEAD') {
    headers.set('X-CSRF-Token', CSRF_META());
  }
  const res = await fetch(path, init);
  if (res.status === 204) {
    observeSessionResponse(method, path, true, null);
    return { ok: true, status: 204, data: null };
  }
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
  observeSessionResponse(method, path, res.ok, data);
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
    get:    (p, o)    => request('GET',    p, undefined, o),
    post:   (p, b, o) => request('POST',   p, b, o),
    patch:  (p, b, o) => request('PATCH',  p, b, o),
    delete: (p, o)    => request('DELETE', p, undefined, o),
  },
  // Convenience forms - throw on !ok, return data directly.
  get:    async (p, o)    => unwrap(await request('GET',    p, undefined, o)),
  post:   async (p, b, o) => unwrap(await request('POST',   p, b, o)),
  patch:  async (p, b, o) => unwrap(await request('PATCH',  p, b, o)),
  delete: async (p, o)    => unwrap(await request('DELETE', p, undefined, o)),

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
let _authRevision = 0;
const _sessionListeners = new Set();

function resetSessionState(profile = undefined) {
  _authRevision++;
  _meCache = profile;
  resetSessionQueries();
  const bus = _liveConns.get('__bus__');
  if (bus) bus.reconnect(profile !== null);
  _sessionListeners.forEach(reset => reset(profile !== null));
}

// These native endpoints change the cookie session or its active tenant. A
// successful password/passkey proof that still needs OTP/MFA is not a session.
// Custom auth routes can explicitly finish with auth.refreshMe().
function observeSessionResponse(method, path, ok, data) {
  if (!ok || typeof path !== 'string') return;
  const route = path.split(/[?#]/, 1)[0];
  if (route === '/api/_auth/act_as' && (method === 'POST' || method === 'DELETE')) {
    resetSessionState();
    return;
  }
  if (method !== 'POST') return;
  if (route === '/logout') resetSessionState(null);
  else if (['/login', '/signup', '/api/_auth/passkeys/login'].includes(route)) {
    if (data?.user?.id != null) resetSessionState();
  } else if (route === '/api/_auth/mfa/verify') {
    if (data?.token && data?.user_id != null) resetSessionState();
  } else if (['/api/_switch_group', '/api/_groups/create', '/api/_auth/impersonate', '/api/_auth/end-impersonation', '/verify-mfa', '/verify-otp'].includes(route)) {
    if (!data?.otp_required && !data?.mfa_required && !data?.mfa_setup_required) resetSessionState();
  }
}

async function me() {
  if (_meCache !== undefined) return _meCache;
  const revision = _authRevision;
  const res = await request('GET', '/api/_auth/profile');
  if (revision !== _authRevision) return me();
  _meCache = res.ok ? res.data : null;
  return _meCache;
}

async function signOut() {
  // Framework's logout endpoint is registered at app.Paths.Logout (default /logout).
  await unwrap(await request('POST', '/logout'));
}

// Force-refresh the profile cache (useful right after signup).
async function refreshMe() {
  resetSessionState();
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
  return res.data?.user || null;
}

// =================================================================
//  Passkeys - sign in with Face ID, Touch ID, Windows Hello or a phone.
// =================================================================
//   await bm.auth.passkey.register('MacBook', { password })   // signed in: add a passkey
//   await bm.auth.passkey.signIn()              // signed out: sign in
//   await bm.auth.passkey.list(); await bm.auth.passkey.remove(id)
// bm.auth.passkey.supported() is false where the browser has no WebAuthn.

function _b64uToBuf(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function _bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function _passkeyCall(method, path, body, fallback) {
  const res = await request(method, path, body);
  if (!res.ok) {
    const err = new Error(res.data?.error || fallback);
    err.status = res.status;
    err.body = res.data;
    throw err;
  }
  return res.data;
}

const passkey = {
  supported() {
    return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
  },
  async register(name, proof) {
    // proof: { password } or { mfa_code } - adding a passkey re-confirms the account.
    // Optional within 10 minutes of signing in on this browser (e.g. with Google).
    const o = await _passkeyCall('POST', '/api/_auth/passkeys/register/options', proof || {}, 'Could not start passkey setup');
    const cred = await navigator.credentials.create({ publicKey: {
      ...o,
      challenge: _b64uToBuf(o.challenge),
      user: { ...o.user, id: _b64uToBuf(o.user.id) },
      excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: _b64uToBuf(c.id) })),
    } });
    const r = cred.response;
    return (await _passkeyCall('POST', '/api/_auth/passkeys/register', {
      id: cred.id, rawId: _bufToB64u(cred.rawId), type: cred.type, name: name || '',
      response: {
        clientDataJSON: _bufToB64u(r.clientDataJSON),
        attestationObject: _bufToB64u(r.attestationObject),
      },
    }, 'Could not save the passkey')).passkey;
  },
  async signIn() {
    const o = await _passkeyCall('POST', '/api/_auth/passkeys/login/options', {}, 'Could not start passkey sign-in');
    const cred = await navigator.credentials.get({ publicKey: {
      ...o,
      challenge: _b64uToBuf(o.challenge),
      allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: _b64uToBuf(c.id) })),
    } });
    const r = cred.response;
    const data = await _passkeyCall('POST', '/api/_auth/passkeys/login', {
      id: cred.id, rawId: _bufToB64u(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: _bufToB64u(r.clientDataJSON),
        authenticatorData: _bufToB64u(r.authenticatorData),
        signature: _bufToB64u(r.signature),
        userHandle: r.userHandle ? _bufToB64u(r.userHandle) : '',
      },
    }, 'Passkey sign-in failed');
    return data.user || null;
  },
  async list() {
    return (await _passkeyCall('GET', '/api/_auth/passkeys', undefined, 'Could not list passkeys')).passkeys || [];
  },
  async remove(id) {
    await _passkeyCall('DELETE', '/api/_auth/passkeys/' + _seg(id), undefined, 'Could not remove the passkey');
  },
};

export const auth = { me, signOut, refreshMe, signIn, signUp, passkey };

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
    return api.get(`/api/_auth/users/${_rowRef(id)}`);
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

// A row id goes into the path as written (apps pass `id + '?include=...'`),
// so an id taken from a URL param such as `../_auth/tokens/7` aimed the
// CSRF-bearing PATCH/DELETE/POST at another endpoint once the browser
// resolved the dot segments. Refuse dot segments and backslashes, judged
// after removing tab, LF and CR the way the URL parser does (`.\t.` is `..`).
function _rowRef(id) {
  const s = String(id);
  const path = s.split(/[?#]/, 1)[0].replace(/[\t\n\r]/g, '');
  if (path.includes('\\') || /(^|\/)(\.|%2e){1,2}(\/|$)/i.test(path)) {
    throw new Error('bm.table: invalid row id ' + JSON.stringify(s));
  }
  return s;
}

// One encoded path segment. encodeURIComponent leaves '.' alone, so an id of
// '..' still removed the segment before it (DELETE /api/docs/../permissions/x
// is DELETE /api/permissions/x).
function _seg(v) {
  const e = encodeURIComponent(String(v));
  if (e === '.' || e === '..') throw new Error('bm: invalid path segment ' + JSON.stringify(String(v)));
  return e;
}

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
      if (opts.cursor != null) qs.set('cursor', String(opts.cursor));
      if (opts.q)      qs.set('q',      String(opts.q));
      if (opts.sort)   qs.set('sort',   String(opts.sort));
      if (opts.order)  qs.set('order',  String(opts.order));
      if (opts.where) {
        for (const [k, v] of Object.entries(opts.where)) qs.set(k, String(v));
      }
      const path = base + (qs.toString() ? '?' + qs : '');
      const r = await api.get(path);
      // Offset lists are bare arrays; cursor/page lists use { data: [...] }.
      // Retain { rows: [...] } compatibility for existing table adapters.
      return Array.isArray(r) ? r : (r.rows || r.data || []);
    },
    get(id) {
      _runHooks('read', { id }, { table: t, op: 'get' });
      return api.get(`${base}/${_rowRef(id)}`);
    },
    create(body) {
      const opts = _runHooks('write', { body }, { table: t, op: 'create' });
      return api.post(base, opts.body ?? body);
    },
    update(id, body) {
      const opts = _runHooks('write', { id, body }, { table: t, op: 'update' });
      return api.patch(`${base}/${_rowRef(opts.id ?? id)}`, opts.body ?? body);
    },
    delete(id) {
      _runHooks('write', { id }, { table: t, op: 'delete' });
      return api.delete(`${base}/${_rowRef(id)}`);
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
    restore:  (id)               => api.post(`${base}/${_rowRef(id)}/restore`),
    versions: (id)               => api.get(`${base}/${_rowRef(id)}/versions`),
    revertTo: (id, version)      => api.post(`${base}/${_rowRef(id)}/revert/${_rowRef(version)}`),
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
  if (_liveConns.has('__bus__')) {
    const bus = _liveConns.get('__bus__');
    bus.ensure();
    return bus;
  }
  const subs = new Set();
  let es = null;
  const reconnect = (connect = true) => {
    if (es) es.close();
    es = null;
    if (!connect) return;
    const current = es = new EventSource('/sse/events');
    const fire = (raw) => {
      if (es !== current) return; // queued event from a previous session
      let data;
      try { data = JSON.parse(raw); } catch { return; }
      subs.forEach(fn => { try { fn(data); } catch (e) { console.error(e); } });
    };
    current.addEventListener('change', e => fire(e.data));
    current.onmessage = e => fire(e.data);
    current.onerror = () => { /* EventSource auto-reconnects */ };
  };
  const bus = { subs, reconnect, ensure: () => { if (!es) reconnect(); }, close: () => reconnect(false) };
  reconnect();
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
//   - **Serialized callbacks**: one fetchAndRender runs at a time per
//     subscription. Events during a pending callback queue one trailing
//     refresh, so an older callback cannot overwrite a newer callback's
//     render. The returned promise must cover all fetch and render work.
//
//   - **Trailing-edge debounce**: bursts of events coalesce into a
//     single fetch fired `debounce` ms after the LAST event. Avoids
//     N round-trips for N events; the framework's SSE fan-out is
//     intentionally chatty (every CRUD mutation emits) so debouncing
//     downstream is the right pattern.
//
// `fetchAndRender` is called with no args; it should read whatever
// data it needs (auto-CRUD list, custom flow, whatever) and update
// the DOM. Its returned promise is awaited; other values are ignored.
// Errors are caught + logged. Detached work and separate subscriptions
// are not serialized. A callback that never settles blocks its queue.
//
// Returns an unsubscribe function. Calling it stops the SSE
// subscription AND cancels pending/queued fetches. An already-running
// callback cannot be cancelled; callers must guard its teardown effects.
//
//   const unsub = bm.live.scoped('messages', refreshChat, { debounce: 60 });
//   // ... later
//   unsub();
live.scoped = function liveScoped(tableOrStar, fetchAndRender, opts) {
  if (typeof fetchAndRender !== 'function') {
    throw new Error('bm.live.scoped(table, fetchAndRender, opts) requires a function');
  }
  const debounceMs = (opts && typeof opts.debounce === 'number') ? opts.debounce : 60;
  let running = false, queued = false, stopped = false;
  let pendingTimer = null;

  const runFetch = async () => {
    pendingTimer = null;
    if (stopped) return;
    if (running) { queued = true; return; }
    running = true;
    try {
      const result = fetchAndRender();
      if (result && typeof result.then === 'function') {
        await result;
      }
    } catch (err) {
      console.warn('[bm.live.scoped] fetchAndRender threw:', err);
    } finally {
      running = false;
      if (queued && !stopped) {
        queued = false;
        schedule();
      }
    }
  };

  const schedule = () => {
    if (stopped) return;
    if (pendingTimer != null) clearTimeout(pendingTimer);
    pendingTimer = setTimeout(runFetch, debounceMs);
  };

  // Prime through the debounce window so the caller doesn't need to
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
    stopped = true;
    queued = false;
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
    const r = await fetch('/_internal/flows.json', { credentials: 'same-origin', cache: 'no-store' });
    if (r.ok) _flowsRegistry = await r.json();
    else _flowsRegistry = {};
  } catch { _flowsRegistry = {}; }
  return _flowsRegistry;
}

// Registry keys are camelCase (company_setup / company-setup → companySetup).
// Accept snake_case and kebab-case aliases too - agents naturally write
// bm.flows.company_setup when the file is flows/company-setup.yaml, and
// making the obvious spelling work beats making them learn the mapping.
function camelizeFlowName(name) {
  return name.replace(/[-_]+([a-zA-Z0-9])/g, (_, c) => c.toUpperCase());
}

export const flows = new Proxy({}, {
  get(_target, flowName) {
    if (typeof flowName !== 'string') return undefined;
    return async (params = {}, body) => {
      let reg = await loadFlowsRegistry();
      let entry = reg[flowName] || reg[camelizeFlowName(flowName)];
      if (!entry) {
        // The registry lists only flows THIS caller may call, so one loaded
        // before sign-in (or before a role grant) can be missing the flow.
        // Refetch once before reporting it as undeclared.
        _flowsRegistry = null;
        reg = await loadFlowsRegistry();
        entry = reg[flowName] || reg[camelizeFlowName(flowName)];
      }
      if (!entry) {
        const available = Object.keys(reg).sort();
        const listing = available.length
          ? `Available flows: ${available.map(n => `bm.flows.${n}()`).join(', ')}.`
          : 'No flows are registered (flows.yaml / flows/*.yaml define none with on.request triggers).';
        throw new Error(
          `bm.flows.${flowName} is not declared in flows.yaml. ${listing} ` +
          `Note: a single-job file flows/company-setup.yaml registers as bm.flows.companySetup ` +
          `(file name, camelCased) - snake/kebab spellings of the same name also resolve.`
        );
      }
      // Substitute :path params, each one encoded segment (never '.'/'..').
      let path = entry.path;
      for (const [k, v] of Object.entries(params)) {
        if (path.includes(`:${k}`)) path = path.replace(`:${k}`, _seg(v));
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
  const base = `/api/${_seg(table)}/${_seg(id)}`;
  return {
    table,
    id,
    // Server expects { to: <newState> } (workflows.go handleTransition).
    transitionTo: (state) => api.post(`${base}/transition`, { to: state }),
    available:    () => api.get(`${base}/transitions`),
    current:      async () => {
      const row = await api.get(base);
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
  const statusPath = statusUrl || `/api/_jobs/${_seg(jobId)}/status`;
  return {
    job_id: jobId,
    status_url: statusUrl,
    status: () => api.get(statusPath),
    wait: (opts = {}) => waitForJob(jobId, { ...opts, statusUrl }),
  };
}

async function waitForJob(jobId, { intervalMs = 1000, timeoutMs = 5 * 60 * 1000, statusUrl = '' } = {}) {
  const statusPath = statusUrl || `/api/_jobs/${_seg(jobId)}/status`;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const status = await api.get(statusPath);
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
  // statusUrl is the tokenized URL returned by an async flow's submit
  // response. Without it, the bare /api/_jobs/{id}/status path 404s for any
  // non-admin caller (the status endpoint requires the capability token), so
  // always pass through the server-issued status_url when polling outside an
  // admin session.
  status: (jobId, statusUrl) =>
    api.get(statusUrl || `/api/_jobs/${_seg(jobId)}/status`),
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
  markRead:    (id) => api.patch(`/api/_notifications/${_seg(id)}/read`),
  markAllRead: ()   => api.post('/api/_notifications/read-all'),
  delete:      (id) => api.delete(`/api/_notifications/${_seg(id)}`),
  // Events carry no rows. Drain an ID cursor (including rows already marked
  // read by another tab), coalescing insert events into one paginated fetch.
  onNew(cb) {
    let active = true, current;
    const isCurrent = state => active && current === state && state.revision === _authRevision;
    const initialize = state => api.get('/api/_notifications?limit=1')
      .then((result) => {
        if (isCurrent(state) && Number.isSafeInteger(result.latest_id) && result.latest_id >= 0) {
          state.lastSeen = result.latest_id;
        }
      })
      .catch(() => {});
    // Each session owns its baseline, cursor and pending drain. A delayed old
    // response must neither publish private rows nor stall the next account.
    const reset = (enabled = true) => {
      const state = current = { revision: _authRevision, enabled, lastSeen: null, pending: false, running: false };
      state.ready = enabled ? initialize(state) : Promise.resolve();
    };
    _sessionListeners.add(reset);
    reset();
    const drain = async state => {
      if (state.running || !isCurrent(state)) return;
      state.running = true;
      try {
        await state.ready;
        if (!isCurrent(state)) return;
        if (state.lastSeen === null) {
          state.ready = initialize(state);
          await state.ready;
          if (!isCurrent(state) || state.lastSeen === null) return;
        }
        while (isCurrent(state) && state.pending) {
          state.pending = false;
          while (isCurrent(state)) {
            const result = await api.get(`/api/_notifications?limit=100&after_id=${state.lastSeen}`);
            if (!isCurrent(state)) return;
            const rows = result.notifications || [];
            let advanced = false;
            for (const n of rows) {
              if (!isCurrent(state)) return;
              if (!Number.isSafeInteger(n.id) || n.id <= state.lastSeen) continue;
              state.lastSeen = n.id; advanced = true;
              try { cb(n); } catch (e) { console.error(e); }
            }
            if (rows.length < 100 || !advanced) break;
          }
        }
      } catch (_) { /* Retry from the last delivered ID on the next event. */ }
      finally { state.running = false; }
    };
    const stop = live('_benmore_notifications', (ev) => {
      if (ev.action !== 'insert' || !current.enabled) return;
      current.pending = true;
      void drain(current);
    });
    return () => { active = false; _sessionListeners.delete(reset); stop(); };
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
    api.post(`/api/${_seg(table)}/${_seg(id)}/share`,
             { email, permission, ...(expires_at ? { expires_at } : {}) }),
  revoke: (table, id, email) =>
    api.delete(`/api/${_seg(table)}/${_seg(id)}/permissions/${_seg(email)}`),
  list:   (table, id) =>
    api.get(`/api/${_seg(table)}/${_seg(id)}/permissions`),
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
  const out = Object.prototype.hasOwnProperty.call(dict, key) ? (dict[key] ?? key) : key;
  if (!vars) return out;
  // Match the original placeholders once. Variable names and inserted values
  // are literal data: no regex metacharacters, replacement-dollar semantics,
  // inherited keys, or recursive expansion of newly inserted placeholders.
  return out.replace(/\{\{\s*([^{}]*?)\s*\}\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match);
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
    // Keep the slug claimed while live: a publisher that stops
    // heartbeating is treated as crashed and its slug can be taken over.
    const heartbeat = setInterval(() => {
      if (!stopped) request('POST', '/api/_broadcast/heartbeat', { slug }).catch(() => {});
    }, 60000);
    return {
      slug,
      sessionId: session_id,
      pc,
      async stop() {
        if (stopped) return;
        stopped = true;
        clearInterval(heartbeat);
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
    const res = await request('GET', `/api/_broadcast/stats/${_seg(slug)}`);
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
  // Signed-in enrollment re-proves the current password; the login-issued
  // setup token path (require_mfa_for_roles) needs none.
  enroll:  (password) => api.post('/api/_auth/mfa/setup', password ? { password } : {}),
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

// A value that starts a URL attribute can't be made safe by escaping:
// href="javascript:..." still runs. Same rule as server-rendered pages
// (template_context.go dangerousURL): javascript:, vbscript:, livescript:
// and data: other than a raster image become #blocked-unsafe-url, with the
// scheme read as the URL parser reads it (leading control characters and any
// tab or newline ignored). bm.raw(url) opts out.
const _urlAttrOpen = /\s(?:href|src|action|formaction|xlink:href|poster|data|cite|background)\s*=\s*["']?$/i;
const _rasterDataURL = /^data:\s*image\/(png|gif|jpe?g|webp|avif|bmp|x-icon|vnd\.microsoft\.icon)[;,]/i;
function _scriptURL(v) {
  const u = String(v).replace(/^[\x00-\x20]+/, '').replace(/[\t\n\r]/g, '');
  const m = /^([^:/?#]+):/.exec(u);
  if (!m) return false;
  const scheme = m[1].toLowerCase();
  return scheme === 'javascript' || scheme === 'vbscript' || scheme === 'livescript' ||
    (scheme === 'data' && !_rasterDataURL.test(u));
}

export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    let v = values[i];
    if (v != null && typeof v !== 'object' && _urlAttrOpen.test(strings[i]) && _scriptURL(v)) v = '#blocked-unsafe-url';
    out += _interpolate(v) + strings[i + 1];
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
// markdown renders via the server-side benmark engine
// (POST /_internal/markdown): robust CommonMark + GFM + syntax highlighting,
// mermaid diagrams, and media embeds - one renderer shared with every other
// framework surface. Results are cached per text. On network failure we fall
// back to the tiny offline /_internal/markdown.js subset (and, failing that,
// HTML-escaped plaintext), so a message NEVER renders as raw or unsanitized
// HTML. Pass { inline: true } for the single-line chat subset.
const _mdCache = new Map();
let _mdFallback = null;
async function _mdFallbackFn(text, inline) {
  if (_mdFallback == null) {
    try { const m = await import('/_internal/markdown.js'); _mdFallback = m.markdown || m.default; }
    catch (_) {
      _mdFallback = (t) => String(t == null ? '' : t).replace(
        /[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }
  }
  return _mdFallback(text, inline);
}
async function markdown(text, opts) {
  if (text == null) return '';
  const inline = !!(opts && opts.inline);
  const key = (inline ? '1' : '0') + String(text);
  if (_mdCache.has(key)) return _mdCache.get(key);
  try {
    const res = await fetch('/_internal/markdown', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: String(text), inline }),
    });
    if (!res.ok) throw new Error('markdown ' + res.status);
    const html = await res.text();
    if (_mdCache.size > 500) _mdCache.clear();
    _mdCache.set(key, html);
    return html;
  } catch (_) {
    return _mdFallbackFn(text, inline);
  }
}
// markdownBatch renders many strings in ONE round-trip (POST
// /_internal/markdown/batch) - use it to render a whole message/notes list at
// once. items is an array of strings or { text, inline } objects; returns an
// array of HTML strings aligned by index. Results are added to the cache.
async function markdownBatch(items) {
  const norm = (items || []).map((it) =>
    typeof it === 'string' ? { text: it, inline: false }
      : { text: String((it && it.text) || ''), inline: !!(it && it.inline) });
  if (!norm.length) return [];
  try {
    const res = await fetch('/_internal/markdown/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: norm }),
    });
    if (!res.ok) throw new Error('markdown batch ' + res.status);
    const out = (await res.json()).html || [];
    norm.forEach((n, i) => { if (out[i] != null) _mdCache.set((n.inline ? '1' : '0') + n.text, out[i]); });
    return out;
  } catch (_) {
    return Promise.all(norm.map((n) => markdown(n.text, { inline: n.inline })));
  }
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

// =================================================================
//  store - small app-state primitive (Zustand-shaped, no dependency)
// =================================================================

function shallowEqualObject(a, b) {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  const ak = Object.keys(a), bk = Object.keys(b);
  if (ak.length !== bk.length) return false;
  for (const k of ak) if (!Object.is(a[k], b[k])) return false;
  return true;
}

function resolveStoreCache(persist) {
  if (!persist || !persist.name) return null;
  const kind = persist.storage === 'persistent' ? 'persistent' : 'namespaced';
  return cache[kind](persist.name, persist.version || 'v0');
}

export function createStore(initialState = {}, opts = {}) {
  const base = (initialState && typeof initialState === 'object') ? initialState : {};
  const persist = opts.persist || opts.cache;
  const storage = resolveStoreCache(persist);
  let state = base;
  if (storage) {
    try {
      const raw = storage.get();
      if (raw) {
        // Persisted blobs live in localStorage/sessionStorage and are therefore
        // attacker-controllable on the client. We only accept a plain object and
        // merge it over base; this is not a trust boundary (the server remains
        // authoritative), but it prevents a malformed/non-object blob from
        // replacing state wholesale or injecting a non-object root.
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          state = { ...base, ...parsed };
        }
      }
    } catch {}
  }
  const initial = { ...state };
  const subs = new Set();

  // Each subscriber's listener receives (nextSlice, oldSlice). The previous
  // value passed to listeners is the subscriber's own previously-observed slice
  // (which, for the default whole-state selector, IS the prior whole state), so
  // notify() needs no separate `prev` argument.
  const notify = () => {
    subs.forEach((sub) => {
      let nextSlice;
      try { nextSlice = sub.selector(state); } catch (e) { console.warn('[bm.store] selector threw:', e); return; }
      if (!sub.equal(nextSlice, sub.slice)) {
        const oldSlice = sub.slice;
        sub.slice = nextSlice;
        try { sub.listener(nextSlice, oldSlice); } catch (e) { console.warn('[bm.store] listener threw:', e); }
      }
    });
  };

  const persistState = () => {
    if (!storage) return;
    try { storage.set(JSON.stringify(state)); } catch {}
  };

  return {
    get: () => state,
    set(patch) {
      let next = (typeof patch === 'function') ? patch(state) : patch;
      if (next == null) return state;
      // State is contractually a Record<string, any>; object patches merge
      // shallowly. A patch (including a function result) that is an array or
      // other non-object would replace the whole state and break that contract,
      // so we reject it with a warning instead of silently clobbering state.
      if (typeof next !== 'object' || Array.isArray(next)) {
        console.warn('[bm.store] set() ignored a non-object patch; state must be a plain object');
        return state;
      }
      next = { ...state, ...next };
      if (Object.is(next, state) || shallowEqualObject(next, state)) return state;
      state = next;
      persistState();
      notify();
      return state;
    },
    subscribe(selector, listener, equal = Object.is) {
      if (typeof listener !== 'function') {
        listener = selector;
        selector = (s) => s;
      }
      if (typeof selector !== 'function' || typeof listener !== 'function') {
        throw new Error('bm.createStore().subscribe(selector, listener) requires a listener');
      }
      const sub = { selector, listener, equal, slice: selector(state) };
      subs.add(sub);
      return () => subs.delete(sub);
    },
    reset(nextState) {
      state = nextState && typeof nextState === 'object' ? { ...nextState } : { ...initial };
      persistState();
      notify();
      return state;
    },
  };
}

// =================================================================
//  query - key-based fetch/mutation cache for app data
// =================================================================

function stableStringify(value) {
  if (value == null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

function queryKey(key) {
  return typeof key === 'string' ? key : stableStringify(key);
}

const _queryCache = new Map();
const _queryTableKeys = new Map();
let _queryLiveStop = null;
// Live-invalidation tuning. The '*' SSE subscription fires for every CRUD event
// on every table the app has read, including the client's own writes, so we
// coalesce invalidations per-table over a short window to avoid a refetch
// storm under chatty fan-out. Refetch-on-live is opt-out via _queryLiveConfig.
const _queryLiveConfig = { refetch: true, debounceMs: 50 };
const _queryLiveTimers = new Map();

function queryEntry(key) {
  const k = queryKey(key);
  if (!_queryCache.has(k)) {
    _queryCache.set(k, { key: k, rawKey: key, data: undefined, error: null, updatedAt: 0, promise: null, revision: 0, rollbackOwner: null, fetcher: null, staleTime: 0, subs: new Set() });
  }
  return _queryCache.get(k);
}

function notifyQuery(e) {
  e.subs.forEach((fn) => { try { fn({ data: e.data, error: e.error, updatedAt: e.updatedAt, pending: !!e.promise }); } catch (err) { console.warn('[bm.query] subscriber threw:', err); } });
}

// A fetcher may not support cancellation. Let its caller settle normally, but
// revoke its right to publish data/errors or clear a newer request's pending state.
function supersedeQueryFetch(e) {
  e.revision++;
  e.promise = null;
}

function resetSessionQueries() {
  if (_queryLiveStop) _queryLiveStop();
  _queryTableKeys.clear();
  const entries = [..._queryCache.values()];
  // Clear every entry before notifying: a subscriber may read another key.
  // Retain entries/subscriptions so old promises cannot find a fresh entry and
  // existing views can render the empty state before requesting their new data.
  for (const e of entries) {
    supersedeQueryFetch(e);
    e.rollbackOwner = null;
    e.data = undefined;
    e.error = null;
    e.updatedAt = 0;
    e.fetcher = null;
    e.staleTime = 0;
  }
  for (const e of entries) notifyQuery(e);
}

function setQueryValue(e, data, owner = null) {
  supersedeQueryFetch(e);
  e.rollbackOwner = owner;
  if (owner) owner.revision = e.revision;
  e.data = data;
  e.error = null;
  e.updatedAt = Date.now();
  notifyQuery(e);
  return data;
}

function rememberTableKey(tableName, key) {
  if (!tableName) return;
  const k = queryKey(key);
  if (!_queryTableKeys.has(tableName)) _queryTableKeys.set(tableName, new Set());
  _queryTableKeys.get(tableName).add(k);
}

function ensureQueryLiveInvalidation() {
  if (_queryLiveStop || typeof live !== 'function' || typeof EventSource === 'undefined') return;
  const stop = live('*', (ev) => {
    if (!ev || (!ev.table && ev.action !== 'refresh')) return;
    // Private/member-of events may hide the table name. That refresh hint
    // covers every registered live query, but not unrelated custom caches.
    const table = ev.table || '';
    if (_queryLiveTimers.has('') || _queryLiveTimers.has(table)) return;
    // A generic refresh subsumes already queued table-specific refreshes.
    if (!table) {
      for (const timer of _queryLiveTimers.values()) clearTimeout(timer);
      _queryLiveTimers.clear();
    }
    const t = setTimeout(() => {
      _queryLiveTimers.delete(table);
      const opts = { refetch: _queryLiveConfig.refetch };
      if (table) query.invalidateTable(table, opts);
      else {
        const keys = new Set([..._queryTableKeys.values()].flatMap(keys => [...keys]));
        query.invalidate((_raw, stable) => keys.has(stable), opts);
      }
    }, _queryLiveConfig.debounceMs);
    if (typeof t.unref === 'function') t.unref();
    _queryLiveTimers.set(table, t);
  });
  // Expose a teardown so callers/tests can stop the page-lifetime subscription.
  _queryLiveStop = () => {
    try { if (typeof stop === 'function') stop(); } catch {}
    for (const t of _queryLiveTimers.values()) clearTimeout(t);
    _queryLiveTimers.clear();
    _queryLiveStop = null;
  };
}

export const query = {
  key: queryKey,
  stableStringify,
  get(key) {
    return queryEntry(key).data;
  },
  set(key, data) {
    return setQueryValue(queryEntry(key), data);
  },
  subscribe(key, fn) {
    if (typeof fn !== 'function') throw new Error('bm.query.subscribe(key, fn) requires a function');
    const e = queryEntry(key);
    e.subs.add(fn);
    fn({ data: e.data, error: e.error, updatedAt: e.updatedAt, pending: !!e.promise });
    return () => e.subs.delete(fn);
  },
  async fetch(key, fetcher, opts = {}) {
    if (typeof fetcher !== 'function') throw new Error('bm.query.fetch(key, fetcher) requires a fetcher');
    const e = queryEntry(key);
    const staleTime = Number(opts.staleTime || opts.staleMs || 0);
    if (!opts.force && e.data !== undefined && staleTime > 0 && Date.now() - e.updatedAt < staleTime) return e.data;
    // If a fetch is already in flight, return it without clobbering e.fetcher/
    // e.staleTime: a concurrent caller with a different fetcher must not have
    // its fetcher attached to data it didn't produce, or a later refetch(key)
    // would run the wrong fetcher.
    if (e.promise) return e.promise;
    e.fetcher = fetcher;
    e.staleTime = staleTime;
    const revision = e.revision;
    const pending = Promise.resolve()
      .then(fetcher)
      .then((data) => {
        if (e.revision === revision) {
          e.revision++;
          e.rollbackOwner = null;
          e.data = data;
          e.error = null;
          e.updatedAt = Date.now();
        }
        return data;
      })
      .catch((err) => {
        if (e.revision === revision) {
          e.revision++;
          e.error = err;
        }
        throw err;
      })
      .finally(() => {
        if (e.promise === pending) {
          e.promise = null;
          notifyQuery(e);
        }
      });
    e.promise = pending;
    notifyQuery(e);
    return pending;
  },
  async refetch(key) {
    const e = queryEntry(key);
    if (!e.fetcher) return e.data;
    return query.fetch(e.rawKey, e.fetcher, { force: true, staleTime: e.staleTime });
  },
  invalidate(match, opts = {}) {
    const keys = [];
    // For a non-function match we support exact-key matching plus structural
    // array-prefix matching: ['user'] matches ['user', 1] but NOT ['users'].
    // We deliberately avoid raw string startsWith on the stable-stringified key
    // because that produced false positives (e.g. {a:1} matching {a:1,b:2}, or
    // ['user'] matching ['username']). Array-prefix is predictable for the
    // common ['table', name, spec] / ['query', spec] key shapes used here.
    const matchExact = typeof match !== 'function' ? queryKey(match) : null;
    const matchPrefix = (typeof match !== 'function' && Array.isArray(match)) ? match : null;
    const isArrayPrefix = (prefix, raw) => {
      if (!Array.isArray(raw) || raw.length < prefix.length) return false;
      for (let i = 0; i < prefix.length; i++) {
        if (stableStringify(prefix[i]) !== stableStringify(raw[i])) return false;
      }
      return true;
    };
    const predicate = typeof match === 'function'
      ? match
      : (raw, stable) => stable === matchExact || (matchPrefix !== null && isArrayPrefix(matchPrefix, raw));
    for (const [stable, e] of _queryCache.entries()) {
      if (!predicate(e.rawKey, stable)) continue;
      supersedeQueryFetch(e);
      e.rollbackOwner = null;
      e.updatedAt = 0;
      keys.push(stable);
      notifyQuery(e);
      if (opts.refetch && e.fetcher) query.refetch(e.rawKey).catch(() => {});
    }
    return keys;
  },
  tableKey(tableName, spec = {}) {
    return ['table', tableName, spec];
  },
  async read(spec, opts = {}) {
    if (!spec || !spec.table) throw new Error('bm.query.read({ table, ... }) requires table');
    const key = opts.key || ['query', spec];
    if (opts.live !== false) {
      rememberTableKey(spec.table, key);
      ensureQueryLiveInvalidation();
    }
    return query.fetch(key, async () => {
      const r = await api.post('/api/_query', spec);
      return Array.isArray(r) ? r : (r.rows || []);
    }, opts);
  },
  table(tableName, opts = {}) {
    // Separate client control options (which never affect the server result)
    // from the server-affecting query spec. Only the spec may influence the
    // cache key, otherwise two identical reads that differ only in staleTime/
    // force/live would fragment into distinct cache entries and defeat dedupe.
    const { staleTime, staleMs, force, live, key, ...serverOpts } = opts;
    const spec = { ...serverOpts, table: tableName };
    // Route through read() with the same ['query', spec] key shape so that a
    // bm.query.table('posts') and bm.query.read({ table: 'posts' }) targeting
    // identical rows collapse onto one shared cache entry. Forward every client
    // control option (staleTime/staleMs/force/live) so none are silently dropped.
    return query.read(spec, { key: key, staleTime, staleMs, force, live });
  },
  invalidateTable(tableName, opts = {}) {
    const keys = _queryTableKeys.get(tableName);
    if (!keys) return [];
    return query.invalidate((_raw, stable) => keys.has(stable), opts);
  },
  async mutate(opts = {}) {
    const authRevision = _authRevision;
    if (typeof opts.request !== 'function') throw new Error('bm.query.mutate({ request }) requires request');
    const keys = Array.isArray(opts.keys) ? opts.keys : (opts.key ? [opts.key] : []);
    // Snapshot the full prior entry (data + updatedAt + error), not just data,
    // so a failed mutation can be restored exactly without stamping a fresh
    // updatedAt or clearing a pre-existing error the way set() would.
    const snapshots = [...new Map(keys.map(key => [queryKey(key), key])).values()].map((key) => {
      const e = queryEntry(key);
      return { key, data: e.data, updatedAt: e.updatedAt, error: e.error,
        revision: e.revision, previous: e.rollbackOwner, state: 'pending', applied: false };
    });
    try {
      if (typeof opts.apply === 'function') {
        for (const snap of snapshots) {
          const data = opts.apply(snap.data, snap.key);
          snap.applied = true;
          setQueryValue(queryEntry(snap.key), data, snap);
        }
      }
      const result = await opts.request();
      if (authRevision !== _authRevision) return result;
      for (const snap of snapshots) {
        snap.state = 'succeeded';
        snap.previous = null;
        const e = queryEntry(snap.key);
        if (e.rollbackOwner === snap) e.rollbackOwner = null;
      }
      if (opts.invalidate) query.invalidate(opts.invalidate, { refetch: opts.refetch !== false });
      return result;
    } catch (err) {
      if (authRevision !== _authRevision) throw err;
      for (const snap of snapshots) snap.state = 'failed';
      for (const snap of snapshots) {
        const e = queryEntry(snap.key);
        // A later set, fetch, invalidation or edit owns its state. Neither a
        // default nor an application rollback may overwrite that newer work.
        if (snap.applied ? e.rollbackOwner !== snap : e.revision !== snap.revision) continue;
        // A newer failed edit may have snapshotted another pending edit. Skip
        // ancestors that also failed; restore a still-pending ancestor's
        // ownership so it can unwind if its own request subsequently fails.
        let prior = snap;
        while (prior.previous && prior.previous.state === 'failed') prior = prior.previous;
        const owner = prior.previous?.state === 'pending' ? prior.previous : null;
        if (typeof opts.rollback === 'function') {
          const data = opts.rollback(prior.data, err, snap.key);
          // The callback itself may publish a newer cache value.
          if (snap.applied ? e.rollbackOwner !== snap : e.revision !== snap.revision) continue;
          // A read begun after the optimistic edit can still supply its
          // authoritative result. Rolling back data must not cancel that read.
          if (!e.promise) supersedeQueryFetch(e);
          e.rollbackOwner = owner;
          if (owner) owner.revision = e.revision;
          e.data = data;
          e.updatedAt = Date.now();
          notifyQuery(e);
        } else if (snap.applied) {
          // Preserve the original timestamp and error, including stale state.
          if (!e.promise) supersedeQueryFetch(e);
          e.rollbackOwner = owner;
          if (owner) owner.revision = e.revision;
          e.data = prior.data;
          e.updatedAt = prior.updatedAt;
          if (e.error === null) e.error = prior.error;
          notifyQuery(e);
        }
      }
      throw err;
    }
  },
};

const bm = {
  api, auth, users, table, live, room,
  flows, workflow, aggregate, aggregates, jobs,
  notifications, upload, audit, permissions, signedUrl,
  t, mfa, webrtc, broadcast, markdown, markdownBatch, presence, cache,
  createStore, query, html, raw,
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
