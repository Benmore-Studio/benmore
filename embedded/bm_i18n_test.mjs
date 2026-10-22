import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import bm from './bm.js';

// Execute the exact script emitted by Go, rather than constructing a JSON
// dictionary here: JavaScript object literals discard a string __proto__ key.
if (process.argv.includes('--bootstrap')) {
  globalThis.window = {};
  new Function('window', readFileSync(0, 'utf8'))(window);
  const strings = window.__bm_i18n.strings;
  for (const [key, expected] of Object.entries({
    ['__proto__']: 'Declared prototype name', constructor: 'Declared constructor name', toString: 'Declared function name',
  })) {
    assert.equal(Object.hasOwn(strings, key), true, 'bootstrap own key ' + key);
    assert.equal(bm.t(key), expected, 'bootstrap lookup ' + key);
  }
  assert.equal(Object.getPrototypeOf(strings), Object.prototype);
  console.log('emitted bootstrap own-key assertions passed');
  process.exit(0);
}

let failures = 0;
function check(name, fn) {
  try { fn(); } catch (error) { failures++; console.error(name, error.message); }
}
globalThis.window = { __bm_i18n: { lang: 'en', strings: {
  created: 'Requested: {{title}}', spaced: 'Requested: {{ title }}',
  dotted: '{{user.name}} | {{userXname}}', repeated: '{{title}} then {{title}}',
  nested: '{{title}} | {{second}}', empty: '',
} } };
check('ordinary value', () => assert.equal(bm.t('created', { title: 'Planning' }), 'Requested: Planning'));
check('spaced placeholder', () => assert.equal(bm.t('spaced', { title: 'Planning' }), 'Requested: Planning'));
for (const title of ['$&', '$`', "$'", '$$', '$1', '<img src=x onerror="synthetic()">']) {
  check('literal ' + title, () => assert.equal(bm.t('repeated', { title }), title + ' then ' + title));
}
check('literal variable name', () => assert.equal(bm.t('dotted', { 'user.name': 'Avery' }), 'Avery | {{userXname}}'));
check('replacement text is not recursively expanded', () => assert.equal(bm.t('nested', { title: '{{second}}', second: 'second value' }), '{{second}} | second value'));
check('missing vars stay unchanged', () => assert.equal(bm.t('nested', {}), '{{title}} | {{second}}'));
check('inherited vars stay unchanged', () => assert.equal(bm.t('nested', Object.create({ title: 'not an own value' })), '{{title}} | {{second}}'));
check('empty translation remains empty', () => assert.equal(bm.t('empty'), ''));
check('numeric and bool values remain strings', () => assert.equal(bm.t('nested', { title: 0, second: false }), '0 | false'));
check('ordinary missing key', () => assert.equal(bm.t('missing'), 'missing'));
for (const key of ['toString', 'constructor', '__proto__']) {
  check('missing own key ' + key, () => assert.equal(bm.t(key), key));
}
window.__bm_i18n.strings = JSON.parse('{"__proto__":"Declared prototype name","constructor":"Declared constructor name"}');
check('own prototype-named translations', () => assert.equal(bm.t('__proto__'), 'Declared prototype name'));
check('own constructor translation', () => assert.equal(bm.t('constructor'), 'Declared constructor name'));
delete globalThis.window;
check('no browser dictionary fallback', () => assert.equal(bm.t('constructor'), 'constructor'));
if (failures) process.exit(1);
console.log('all i18n literal-value assertions passed');
