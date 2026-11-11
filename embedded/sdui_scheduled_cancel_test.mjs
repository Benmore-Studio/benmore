// The Reminder and ScheduleAction components against the real cancel
// endpoint. Run via `node embedded/sdui_scheduled_cancel_test.mjs` from the Go
// test TestSDUIScheduledCancelShowsStoredStatus, which serves a real app at
// BM_TEST_URL (BM_TEST_TOKEN is the task owner's session) plus two fixture
// routes that move a task on the server while a component still lists it as
// pending: POST /__fixture/sweep (one real sweep) and
// POST /__fixture/tasks/{id}/{state}.
//
// DELETE /api/_scheduled/{id} answered 200 "cancelled" whatever happened, so
// the components re-read the list and nothing told the user that the reminder
// had already fired. It now answers 404 or 409 with the stored status; the
// components show that answer and re-read the list.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import bm from './bm.js';

const fetchHTTP = globalThis.fetch;
const answers = [];
let transportError = '';
globalThis.fetch = async (path, init = {}) => {
  if (transportError) throw new Error(transportError);
  const url = new URL(path, process.env.BM_TEST_URL);
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${process.env.BM_TEST_TOKEN}`);
  const response = await fetchHTTP(url, { ...init, headers });
  answers.push({ method: init.method || 'GET', path: url.pathname, status: response.status });
  return response;
};
const fixture = async (path) => {
  const response = await fetchHTTP(new URL(path, process.env.BM_TEST_URL), { method: 'POST' });
  assert.equal(response.status, 204, `fixture route ${path}`);
};

// ─── a minimal DOM: the mounted list, its Cancel buttons and Toast ───
const toasts = [];
const fakeEl = (tag) => {
  const el = {
    tag, style: {}, attrs: {}, id: '', textContent: '',
    setAttribute(k, v) { this.attrs[k] = v; if (k === 'data-bm-toast') toasts.push(this); },
    appendChild(c) { return c; }, addEventListener() {}, remove() {},
  };
  let html = '';
  Object.defineProperty(el, 'innerHTML', { get: () => html, set: (v) => { html = v; } });
  return el;
};
const byId = { 'bm-sdui-styles': fakeEl('style'), 'bm-toasts': fakeEl('div') };
globalThis.document = { body: fakeEl('body'), createElement: fakeEl, getElementById: (id) => byId[id] || null, querySelector: () => null };
const mount = () => {
  const form = { addEventListener() {} }, error = { hidden: true };
  return {
    html: '', buttons: [],
    set innerHTML(value) {
      this.html = value;
      this.buttons = Array.from(value.matchAll(/data-cancel="([^"]*)"/g), (match) => ({
        id: Number(match[1]), handler: null,
        getAttribute() { return match[1]; },
        addEventListener(name, handler) { assert.equal(name, 'click'); this.handler = handler; },
        click() { return this.handler(); },
      }));
    },
    get innerHTML() { return this.html; },
    querySelector(selector) { return selector === 'form' ? form : error; },
    querySelectorAll(selector) { assert.equal(selector, '[data-cancel]'); return this.buttons; },
    // What the list shows: title -> status, and the ids that offer Cancel.
    shown() { return Object.fromEntries(Array.from(this.html.matchAll(/<span class="font-medium">([^<]*)<\/span> <span class="text-zinc-500">[^<]* · ([^<]*)<\/span>/g), (m) => [m[1], m[2]])); },
    cancellable() { return this.buttons.map((b) => b.id).sort((a, b) => a - b); },
    button(id) { const b = this.buttons.find((x) => x.id === id); assert.ok(b, `no Cancel button for task ${id}`); return b; },
  };
};
const errorToasts = () => toasts.filter((t) => t.attrs['data-bm-toast'] === 'error').map((t) => t.innerHTML.replace(/<[^>]*>/g, ''));
const lastDelete = () => answers.filter((a) => a.method === 'DELETE').at(-1);

const source = fs.readFileSync(new URL('./sdui.js', import.meta.url), 'utf8')
  .replace("import bm from 'bm';", `import bm from ${JSON.stringify(new URL('./bm.js', import.meta.url).href)};`);
const { Reminder, ScheduleAction } = await import('data:text/javascript;base64,' + Buffer.from(source + '\n//# sourceURL=sdui-scheduled-cancel-fixture.js').toString('base64'));

const id = Object.fromEntries((await bm.api.get('/api/_scheduled')).tasks.map((t) => [t.title, t.id]));

// ─── Reminder ───
const reminders = mount();
await Reminder(reminders, {});
assert.deepEqual(reminders.shown(), { 'Call Dana': 'pending', 'Send invoice': 'pending', 'Renew licence': 'pending' });
assert.deepEqual(reminders.cancellable(), [id['Call Dana'], id['Send invoice'], id['Renew licence']].sort((a, b) => a - b));

// The reminder fires while the list still offers to cancel it.
await fixture('/__fixture/sweep');
await reminders.button(id['Call Dana']).click();
assert.deepEqual(lastDelete(), { method: 'DELETE', path: `/api/_scheduled/${id['Call Dana']}`, status: 409 });
assert.deepEqual(errorToasts(), ['scheduled task already done'], 'the user is told the reminder already fired');
assert.equal(reminders.shown()['Call Dana'], 'done', 'the list is re-read and shows the stored status');
assert.deepEqual(reminders.cancellable(), [id['Send invoice'], id['Renew licence']].sort((a, b) => a - b), 'a fired reminder no longer offers Cancel');

// A task that no longer exists.
await fixture(`/__fixture/tasks/${id['Renew licence']}/gone`);
await reminders.button(id['Renew licence']).click();
assert.equal(lastDelete().status, 404);
assert.deepEqual(errorToasts(), ['scheduled task already done', 'scheduled task not found']);
assert.deepEqual(reminders.shown(), { 'Call Dana': 'done', 'Send invoice': 'pending' }, 'a task that is gone leaves the list');

// A cancel that worked raises nothing.
await reminders.button(id['Send invoice']).click();
assert.equal(lastDelete().status, 200);
assert.equal(errorToasts().length, 2, 'a successful cancel shows no error');
assert.deepEqual(reminders.shown(), { 'Call Dana': 'done', 'Send invoice': 'cancelled' });
assert.deepEqual(reminders.cancellable(), []);

// ─── ScheduleAction ───
const actions = mount();
await ScheduleAction(actions, { flow: 'nightly_sync', label: 'Nightly sync' });
assert.deepEqual(actions.shown(), { 'Nightly sync': 'pending', 'Close books': 'pending', 'Export ledger': 'pending' });

// The scheduled flow has started.
await fixture(`/__fixture/tasks/${id['Nightly sync']}/running`);
await actions.button(id['Nightly sync']).click();
assert.equal(lastDelete().status, 409);
assert.equal(errorToasts().at(-1), 'scheduled task already running');
assert.equal(actions.shown()['Nightly sync'], 'running');
assert.deepEqual(actions.cancellable(), [id['Close books'], id['Export ledger']].sort((a, b) => a - b));

// A second click on the same Cancel button: the task is cancelled, which is
// what was asked, so the 409 raises no error.
const twice = actions.button(id['Close books']);
await twice.click();
assert.equal(lastDelete().status, 200);
const before = errorToasts().length;
await twice.click();
assert.deepEqual(lastDelete(), { method: 'DELETE', path: `/api/_scheduled/${id['Close books']}`, status: 409 });
assert.equal(errorToasts().length, before, 'cancelling a cancelled task is not shown as an error');
assert.equal(actions.shown()['Close books'], 'cancelled');

// A request that got no answer says so and keeps the list as it was.
transportError = 'network down';
await actions.button(id['Export ledger']).click();
transportError = '';
assert.equal(errorToasts().at(-1), 'network down');
assert.equal(actions.shown()['Export ledger'], 'pending', 'a failed request does not blank the list');
await actions.button(id['Export ledger']).click();
assert.equal(lastDelete().status, 200);
assert.deepEqual(actions.shown(), { 'Nightly sync': 'running', 'Close books': 'cancelled', 'Export ledger': 'cancelled' });

console.log('scheduled cancel components passed');
process.exit(0);
