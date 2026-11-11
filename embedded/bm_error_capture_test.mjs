import assert from 'node:assert/strict';

const original = {};
for (const key of ['window', 'document', 'location', 'history', 'fetch']) original[key] = globalThis[key];
const originalNow = Date.now,
  originalWarn = console.warn,
  originalError = console.error;
let now = 1000000;
Date.now = () => now;
const events = new Map(),
  domEvents = new Map(),
  sent = [],
  sentHeaders = [],
  requests = [];
let responseStatus = 200,
  networkFailure = false,
  bodyFailure = false,
  warnCalls = 0;
console.warn = () => {
  warnCalls++;
};
console.error = () => {};
globalThis.location = {
  href: 'https://app.example/start?private=yes#secret',
  origin: 'https://app.example',
  pathname: '/start',
};
globalThis.history = {
  pushState(_state, _title, url) {
    location.href = new URL(url, location.href).href;
    location.pathname = new URL(location.href).pathname;
  },
  replaceState(_state, _title, url) {
    this.pushState(_state, _title, url);
  },
};
globalThis.document = {
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener: (name, fn) => domEvents.set(name, fn),
  readyState: 'complete',
};
globalThis.window = {
  location,
  history,
  document,
  addEventListener: (name, fn) => events.set(name, fn),
  removeEventListener() {},
};
globalThis.fetch = async (path, init) => {
  if (path === '/api/_errors') {
    sentHeaders.push(init.headers);
    sent.push(JSON.parse(init.body));
    return { ok: true, status: 204 };
  }
  requests.push({ path, init });
  if (networkFailure) throw new TypeError('Network unavailable');
  return {
    ok: responseStatus < 400,
    status: responseStatus,
    headers: {
      get: (name) =>
        name.toLowerCase() === 'content-type' ? 'application/json' : name.toLowerCase() === 'x-request-id' ? 'abcdef0123456789' : null,
    },
    text: async () => {
      if (bodyFailure) throw new TypeError('Response stream interrupted');
      return JSON.stringify({
        error: 'failed',
        request_id: '1234567890abcdef',
      });
    },
  };
};
try {
  const { default: bm } = await import('./bm.js?error-capture-test');
  assert.equal(typeof bm.captureError, 'function');
  assert.equal(typeof bm.captureMessage, 'function');
  assert.equal(typeof bm.setTag, 'function');
  bm.setTag('screen.name', 'editor');
  bm.setTag('BAD TAG', 'ignored');
  bm.setTag('too.long', 'x'.repeat(201));
  for (let i = 0; i < 15; i++) bm.setTag(`tag${i}`, String(i));
  const error = new Error('manual failure');
  error.stack = 'Error: manual failure\n at editor (https://app.example/static/app.js?v=abc:2:3)';
  bm.captureError(error);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].message, 'manual failure');
  assert.ok(sent[0].stack.includes('editor'));
  assert.equal(sent[0].tags['screen.name'], 'editor');
  assert.ok(Object.keys(sent[0].tags).length <= 10);
  assert.equal(sent[0].tags['BAD TAG'], undefined);
  assert.equal(sent[0].tags['too.long'], undefined);

  const reason = Object.assign(new Error('request failed'), {
    status: 502,
    body: { request_id: 'abcdef0123456789' },
  });
  events.get('unhandledrejection')({ reason });
  assert.equal(sent.at(-1).status, 502);
  assert.equal(sent.at(-1).request_id, 'abcdef0123456789');

  responseStatus = 404;
  const before404 = sent.length;
  await bm.api.raw.get('/api/missing?private=yes');
  assert.equal(sent.length, before404, '4xx should only add a breadcrumb');
  responseStatus = 500;
  await bm.api.raw.get('/api/broken?private=yes#secret');
  assert.equal(sent.at(-1).kind, 'http');
  assert.equal(sent.at(-1).status, 500);
  assert.equal(sent.at(-1).path, '/api/broken');
  assert.equal(sent.at(-1).request_id, '1234567890abcdef');
  const beforeCrossOrigin = sent.length;
  await bm.api.raw.get('https://other.example/broken');
  assert.equal(sent.length, beforeCrossOrigin);
  networkFailure = true;
  await assert.rejects(bm.api.raw.get('/api/offline?secret=yes'));
  networkFailure = false;
  assert.equal(sent.at(-1).kind, 'http');
  assert.equal(sent.at(-1).path, '/api/offline');
  bodyFailure = true;
  await assert.rejects(bm.api.raw.get('/api/interrupted'));
  bodyFailure = false;
  assert.equal(sent.at(-1).path, '/api/interrupted');
  assert.equal(sent.at(-1).request_id, 'abcdef0123456789');

  // Even a failed request to the reporting endpoint cannot recurse.
  const realFetch = globalThis.fetch;
  let reportCalls = 0;
  globalThis.fetch = async () => {
    reportCalls++;
    throw new Error('report endpoint down');
  };
  await assert.rejects(bm.api.raw.get('/api/_errors'));
  await Promise.resolve();
  assert.equal(reportCalls, 1);
  globalThis.fetch = realFetch;

  for (let i = 0; i < 35; i++) history.pushState({}, '', `/screen/${i}?private=yes`);
  history.replaceState({}, '', '/replaced?private=yes');
  events.get('popstate')({});
  domEvents.get('click')({
    target: {
      tagName: 'BUTTON',
      id: 'save',
      textContent: 'PRIVATE LABEL',
      value: 'PRIVATE VALUE',
      className: 'PRIVATE CLASS',
      getAttribute: (name) => (name === 'data-testid' ? 'save-button' : null),
    },
  });
  console.warn('warning breadcrumb');
  bm.captureMessage('breadcrumb snapshot', 'warning');
  const crumbs = sent.at(-1).breadcrumbs;
  assert.equal(crumbs.length, 30);
  assert.equal(sent.at(-1).level, 'warning');
  assert.equal(warnCalls, 1, 'wrapped console must call the original');
  assert.ok(JSON.stringify(crumbs).includes('save-button'));
  assert.ok(!JSON.stringify(crumbs).includes('PRIVATE'));
  assert.ok(!JSON.stringify(crumbs).includes('private=yes'));

  now += 600001;
  const beforeEscalation = sent.length;
  bm.captureMessage('escalating failure', 'warning');
  bm.captureMessage('escalating failure', 'fatal');
  bm.captureMessage('escalating failure', 'fatal');
  assert.equal(sent.length - beforeEscalation, 2, 'warning must not dedupe the later fatal event');
  now += 600001;
  const beforeFlood = sent.length;
  for (let i = 0; i < 40; i++) bm.captureMessage(`flood ${i}`);
  assert.equal(sent.length - beforeFlood, 25);
  now += 600001;
  bm.captureMessage('after rolling window');
  assert.equal(sent.length - beforeFlood, 26);
  bm.captureMessage('after rolling window');
  assert.equal(sent.length - beforeFlood, 26, 'same message/top frame dedupes');

  // A report is background traffic: it must not keep an idle session alive.
  assert.equal(sentHeaders.at(-1)['X-Benmore-Background'], '1');

  // Signing out ends the error context: the next account's report carries
  // none of the previous session's breadcrumbs, tags or dedupe window.
  now += 600001;
  console.warn('PREVIOUS SESSION console text');
  bm.captureMessage('across sessions', 'error');
  assert.equal(sent.at(-1).tags['screen.name'], 'editor');
  assert.ok(JSON.stringify(sent.at(-1).breadcrumbs).includes('PREVIOUS SESSION'));
  responseStatus = 200;
  await bm.api.raw.post('/logout', {});
  const beforeNextSession = sent.length;
  bm.captureMessage('across sessions', 'error');
  assert.equal(sent.length - beforeNextSession, 1, 'the dedupe window belongs to the previous session');
  assert.equal(sent.at(-1).tags['screen.name'], undefined);
  assert.ok(!JSON.stringify(sent.at(-1).breadcrumbs).includes('PREVIOUS SESSION'));

  // API availability does not depend on a browser or a fetch implementation.
  delete globalThis.window;
  delete globalThis.document;
  delete globalThis.fetch;
  const { default: ssr } = await import('./bm.js?error-capture-ssr');
  assert.equal(typeof ssr.captureError, 'function');
  assert.doesNotThrow(() => ssr.captureError(new Error('SSR')));
  assert.doesNotThrow(() => ssr.captureMessage('SSR'));
} finally {
  for (const [key, value] of Object.entries(original)) {
    if (value === undefined) delete globalThis[key];
    else globalThis[key] = value;
  }
  Date.now = originalNow;
  console.warn = originalWarn;
  console.error = originalError;
}
console.log('all bm error capture assertions passed');
