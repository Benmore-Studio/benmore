// sdui.js - Schema-Driven UI. Framework-owned components that render
// from /api/_schema (the per-user descriptor: control per field, which
// fields are masked/writable, which ops the caller may perform).
//
// THE THESIS: the backend is deterministic because schema → REST is a
// total function the framework re-derives on every boot. These
// components make the FRONTEND deterministic the same way - they
// re-derive the UI from the schema on every render, and the framework
// (not the app) owns that rendering. App code declares WHAT table; this
// layer derives HOW it renders.
//
// Split: BEHAVIOR (schema fetch, data wiring, live refresh, lifecycle)
// lives here and is fixed. PRESENTATION is a swappable skin registry -
// registerSkin({...}) replaces the look without forking the behavior.
// That's how an app ships its own design library.
//
// Shipped in the binary at /_internal/sdui.js, like bm.js. Import via
// the auto-injected importmap:  import { DataTable } from 'sdui'
import bm from 'bm';

// ─── escaping ────────────────────────────────────────────────────────
// Framework-internal; builds trusted HTML strings from untrusted data.
function esc(v) {
  if (v == null) return '';
  return String(v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ─── schema descriptor (cached per session) ──────────────────────────
let _schema = null;
export async function schema() {
  if (_schema) return _schema;
  const res = await fetch('/api/_schema', { credentials: 'same-origin' });
  if (!res.ok) throw new Error('sdui: GET /api/_schema → ' + res.status + ' (are you logged in?)');
  _schema = (await res.json()).tables || {};
  return _schema;
}
export function clearSchemaCache() { _schema = null; }

function tableDesc(s, name) {
  const t = s[name];
  if (!t) throw new Error(`sdui: table "${name}" not in /api/_schema (unknown table, or no read access for this user)`);
  return t;
}
// Visible fields = everything the descriptor didn't mark hidden.
const visible = (desc) => desc.fields.filter((f) => f.control !== 'hidden');
const editable = (desc) => desc.fields.filter((f) => f.control !== 'hidden' && f.writable);

// Pick a human label column for a related table (for relation pickers).
function labelField(desc) {
  if (!desc) return 'id';
  const names = desc.fields.map((f) => f.name);
  for (const cand of ['name', 'title', 'label', 'email', 'slug']) if (names.includes(cand)) return cand;
  const firstText = desc.fields.find((f) => f.control === 'text');
  return firstText ? firstText.name : 'id';
}

// <option> list for an FK field - rows of the related table, labelled.
async function relationOptions(relTable, selected) {
  try {
    const s = await schema();
    const lf = labelField(s[relTable]);
    const rows = await bm.table(relTable).list({ limit: 200 });
    return rows.map((r) =>
      `<option value="${esc(r.id)}" ${String(selected) === String(r.id) ? 'selected' : ''}>${esc(r[lf] ?? r.id)}</option>`
    ).join('');
  } catch (_) { return ''; } // no read access → empty picker, server still enforces
}

// Build a CRUD list querystring (sort/order beyond what bm.table.list
// passes) and normalize the array-or-{rows} response. Keeps DataTable/
// Cards/Board on one read path that honors server-side sort + paging.
async function listRows(table, { limit, offset, q, where, sort, order } = {}) {
  const qs = new URLSearchParams();
  if (limit != null)  qs.set('limit', String(limit));
  if (offset)         qs.set('offset', String(offset));
  if (q)              qs.set('q', String(q));
  if (sort)         { qs.set('sort', String(sort)); qs.set('order', order === 'desc' ? 'desc' : 'asc'); }
  if (where) for (const [k, v] of Object.entries(where)) qs.set(k, String(v));
  const r = await bm.api.get(`/api/${table}` + (qs.toString() ? '?' + qs : ''));
  return Array.isArray(r) ? r : (r.rows || []);
}

// ─── skin registry ───────────────────────────────────────────────────
// Each primitive returns an HTML string. The default skin is Tailwind +
// semantic data-bm-* attributes so a CSS-only skin also works. Override
// any subset via registerSkin().
// NO `dark:` variants here on purpose. The Tailwind Play CDN keys `dark:`
// off the visitor's OS (media) unless darkMode:'class' takes hold - which is
// unreliable via post-load config - so `dark:bg-zinc-900` was firing on
// OS-dark machines and painting inputs/selects black. The default skin is
// explicitly LIGHT (bg + text + the `.bm-ctl` rule below pins color-scheme so
// native <select>/date controls render light too). Dark apps reskin via
// registerSkin(); the recurring real-world bug is black-on-light, never the
// reverse.
const inputCls = 'bm-ctl block w-full border border-zinc-300 bg-white text-zinc-900 focus:outline-none focus:ring-2 focus:ring-blue-500';
const defaultSkin = {
  field: ({ label, required, inner, inline }) =>
    inline
      ? `<label class="flex items-center gap-2 py-2" data-bm-field>${inner}<span class="text-sm font-medium">${esc(label)}</span></label>`
      : `<label class="block space-y-1" data-bm-field><span class="text-sm font-medium">${esc(label)}${required ? ' <span class="text-red-500">*</span>' : ''}</span>${inner}</label>`,
  input: ({ name, type, value, required, control }) =>
    `<input name="${esc(name)}" type="${esc(type)}" value="${esc(value)}" ${required ? 'required' : ''} data-bm-control="${esc(control)}" class="${inputCls}">`,
  textarea: ({ name, value, required }) =>
    `<textarea name="${esc(name)}" rows="3" ${required ? 'required' : ''} data-bm-control="textarea" class="${inputCls}">${esc(value)}</textarea>`,
  checkbox: ({ name, checked }) =>
    `<input name="${esc(name)}" type="checkbox" ${checked ? 'checked' : ''} value="1" data-bm-control="checkbox" class="h-4 w-4 rounded border-zinc-300 bm-accent-text focus:ring-blue-500">`,
  button: ({ label, variant }) =>
    `<button type="submit" data-bm-button="${esc(variant || 'primary')}" class="px-4 py-2 rounded-md bm-accent-bg font-medium hover:bm-accent-bg">${esc(label)}</button>`,
  error: (msg) => `<div data-bm-error class="text-sm text-red-600 dark:text-red-400" ${msg ? '' : 'hidden'}>${esc(msg || '')}</div>`,
  table: ({ head, body }) =>
    `<div class="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800" data-bm-table><table class="w-full text-sm"><thead class="bg-zinc-50 dark:bg-zinc-900/50">${head}</thead><tbody class="divide-y divide-zinc-200 dark:divide-zinc-800">${body}</tbody></table></div>`,
  th: (label) => `<th class="text-left font-medium px-4 py-2.5 text-zinc-600 dark:text-zinc-400">${esc(label)}</th>`,
  tr: ({ cells, clickable }) => `<tr data-bm-row ${clickable ? 'class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50 cursor-pointer"' : ''}>${cells}</tr>`,
  cell: (inner) => `<td class="px-4 py-2.5 align-top">${inner}</td>`,
  emptyState: (msg) => `<p class="text-sm text-zinc-500 px-4 py-6" data-bm-empty>${esc(msg)}</p>`,
};
let skin = { ...defaultSkin };
export function registerSkin(overrides) { skin = { ...skin, ...overrides }; }
export function resetSkin() { skin = { ...defaultSkin }; }

// setAccent(color, textColor?) - brand the accent (buttons, links, active
// states, sparkbars, online dots, …) across EVERY component in one call.
// All components read var(--bm-accent); this sets it on :root. The default
// is #2563eb. textColor is the foreground on accent fills (default #fff).
// e.g. setAccent('#16d645', '#06270f') for a custom brand color.
export function setAccent(color, textColor) {
  if (typeof document === 'undefined') return;
  let s = document.getElementById('bm-accent-style');
  if (!s) { s = document.createElement('style'); s.id = 'bm-accent-style'; document.head.appendChild(s); }
  s.textContent = `:root{--bm-accent:${color}${textColor ? `;--bm-accent-text:${textColor}` : ''}}`;
}

// ─── lucide() - inlined Lucide icon SVGs (no emoji placeholders) ─────
// Inlined (not <i data-lucide> + createIcons) so there's no node-swap click
// bug; currentColor + pointer-events:none so the parent is the click target.
const _lucidePaths = {
  image: '<rect width="18" height="18" x="3" y="3" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>',
  'file-text': '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>',
  bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
  'check-circle': '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
  'alert-triangle': '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  'x-circle': '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
};
function lucide(name, size = 16) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;vertical-align:middle;flex-shrink:0">${_lucidePaths[name] || ''}</svg>`;
}

// ─── control → form input (driven by descriptor.control) ─────────────
// Upload field for image/file columns - a file PICKER (→ bm.upload → the
// stored URL), never a "paste a URL" text box. The real value lives in a
// hidden input named after the column so RecordForm's FormData picks it up.
function previewInner(v, isImage) {
  if (isImage) return v ? `<img src="${esc(v)}" alt="" style="width:52px;height:52px;border-radius:8px;object-fit:cover">` : `<span style="display:inline-flex;align-items:center;justify-content:center;width:52px;height:52px;border-radius:8px;background:rgba(128,128,128,.12);opacity:.45">${lucide('image', 22)}</span>`;
  return v ? `<a href="${esc(v)}" target="_blank" rel="noopener" style="font-size:13px;color:var(--bm-accent,#2563eb)">${esc(String(v).split('/').pop())}</a>` : `<span style="font-size:13px;opacity:.5">No file</span>`;
}
function uploadFieldHTML(f, v, isImage) {
  return `<div data-bm-upload-field data-img="${isImage ? 1 : 0}" style="display:flex;align-items:center;gap:10px"><input type="hidden" name="${esc(f.name)}" value="${esc(v)}"><span data-prev>${previewInner(v, isImage)}</span><button type="button" data-up style="font-size:13px;padding:6px 12px;border:1px solid rgba(128,128,128,.3);border-radius:7px;background:none;cursor:pointer">${v ? 'Replace' : (isImage ? 'Upload image' : 'Upload file')}</button></div>`;
}
// Bind upload fields within a freshly-rendered form. Called by RecordForm/WizardForm.
function wireUploadFields(scope) {
  scope.querySelectorAll('[data-bm-upload-field]').forEach((field) => {
    const hidden = field.querySelector('input[type=hidden]'), btn = field.querySelector('[data-up]'), prev = field.querySelector('[data-prev]');
    const isImage = field.getAttribute('data-img') === '1';
    btn.addEventListener('click', () => {
      const inp = document.createElement('input'); inp.type = 'file'; if (isImage) inp.accept = 'image/*';
      inp.onchange = async () => {
        if (!inp.files || !inp.files[0]) return;
        const t = btn.textContent; btn.textContent = 'Uploading…'; btn.disabled = true;
        try { const r = await bm.upload(inp.files[0]); const url = r.url || r.path || ''; hidden.value = url; if (prev) prev.innerHTML = previewInner(url, isImage); btn.textContent = 'Replace'; }
        catch (ex) { Toast(ex?.message || 'Upload failed', { type: 'error' }); btn.textContent = t; }
        btn.disabled = false;
      };
      inp.click();
    });
  });
}

function controlHTML(f, value, relOptions) {
  // FK column with a relation → a picker of the related table's rows.
  if (f.relation && relOptions != null) {
    return `<select name="${esc(f.name)}" ${f.required ? 'required' : ''} data-bm-control="relation" class="${inputCls}"><option value="">- none -</option>${relOptions}</select>`;
  }
  const v = value ?? f.default ?? '';
  switch (f.control) {
    case 'image': case 'file': return uploadFieldHTML(f, v, f.control === 'image');
    case 'textarea': return skin.textarea({ name: f.name, value: v, required: f.required });
    case 'checkbox': return skin.checkbox({ name: f.name, checked: !!Number(v) });
    case 'number':   return skin.input({ name: f.name, type: 'number', value: v, required: f.required, control: 'number' });
    case 'email':    return skin.input({ name: f.name, type: 'email', value: v, required: f.required, control: 'email' });
    case 'tel':      return skin.input({ name: f.name, type: 'tel', value: v, required: f.required, control: 'tel' });
    case 'url':      return skin.input({ name: f.name, type: 'url', value: v, required: f.required, control: 'url' });
    case 'date':     return skin.input({ name: f.name, type: 'date', value: String(v).slice(0, 10), required: f.required, control: 'date' });
    default:         return skin.input({ name: f.name, type: 'text', value: v, required: f.required, control: 'text' });
  }
}

// ─── control → table cell (mirror of the form mapping) ───────────────
// Format a numeric cell from the schema, deterministically:
//   • integers render exact (no thousands commas - years/scores/IDs stay sane)
//   • floats round to ≤4 decimals (so a raw REAL like 9.573472175289766 → 9.5735)
//   • percent-ish columns (name ends _pct/_percent or is/ends _irr) → 2dp + "%"
// Richer units (currency, explicit per-column formats) are opt-in; this is the
// safe default so a float column never dumps 15 digits.
function formatNumber(f, value) {
  const n = Number(value);
  if (!isFinite(n)) return esc(value);
  const name = String(f.name || '').toLowerCase();
  // *_cents columns store money as integer cents - render as currency.
  if (name.endsWith('_cents')) return esc('$' + (n / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }));
  const isPct = /(_pct|_percent|percent)$/.test(name) || name === 'irr' || name.endsWith('_irr');
  if (Number.isInteger(n) && !isPct) return esc(n);
  const dp = isPct ? 2 : 4;
  const rounded = Math.round(n * 10 ** dp) / 10 ** dp;
  return esc(rounded.toString() + (isPct ? '%' : ''));
}

function cellHTML(f, value) {
  if (f.masked) return '<span class="text-zinc-400">••••</span>';
  if (value == null || value === '') return '<span class="text-zinc-300 dark:text-zinc-600">-</span>';
  switch (f.control) {
    case 'image': return `<img src="${esc(value)}" alt="" style="width:32px;height:32px;border-radius:6px;object-fit:cover;vertical-align:middle">`;
    case 'file':  return `<a href="${esc(value)}" target="_blank" rel="noopener" class="bm-accent-text hover:underline">${esc(String(value).split('/').pop())}</a>`;
    case 'checkbox':
      return Number(value)
        ? '<span class="inline-flex px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">✓</span>'
        : '<span class="text-zinc-400">✗</span>';
    case 'email': return `<a href="mailto:${esc(value)}" class="bm-accent-text hover:underline">${esc(value)}</a>`;
    case 'url':   return `<a href="${esc(value)}" target="_blank" rel="noopener" class="bm-accent-text hover:underline">${esc(value)}</a>`;
    case 'date': {
      const d = new Date(String(value));
      return isNaN(d.getTime()) ? esc(value) : `<span class="text-zinc-500">${d.toLocaleDateString()}</span>`;
    }
    case 'number': return `<span class="tabular-nums">${formatNumber(f, value)}</span>`;
    default:       return esc(value);
  }
}

function resolveEl(target) {
  ensureStyles(); // guarantees .bm-ctl (control color-scheme) etc. before any mount
  const el = typeof target === 'string' ? document.querySelector(target) : target;
  if (!el) throw new Error(`sdui: mount target not found: ${target}`);
  return el;
}

// ─── DataTable ────────────────────────────────────────────────────────
// DataTable(target, { table, columns?, perPage?, where?, onRowClick?,
//                     sortable?, search?, paginate? }) → { refresh, destroy }
// Server-side sort (click a header) + paging + ?q= search - all derived
// from the descriptor. Live-refreshes on any mutation to the table.
export async function DataTable(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const desc = tableDesc(s, opts.table);
  let cols = visible(desc);
  if (opts.columns) {
    const want = opts.columns.split(',').map((c) => c.trim());
    cols = want.map((n) => desc.fields.find((f) => f.name === n)).filter(Boolean);
  }
  const perPage   = opts.perPage || opts.limit || 25;
  const sortable  = opts.sortable !== false;
  const paginate  = opts.paginate !== false;
  const searchable = !!opts.search;
  let offset = 0, sortField = opts.sortField || null, sortOrder = opts.sortOrder || 'asc', q = '';
  let total = null;

  el.innerHTML = `<div data-bm-datatable class="space-y-3">
    ${searchable ? `<input type="search" data-bm-search placeholder="Search…" class="${inputCls} max-w-xs">` : ''}
    <div data-bm-tablebody></div>
    ${paginate ? `<div data-bm-pager class="flex items-center justify-between text-sm text-zinc-500"></div>` : ''}
  </div>`;
  const bodyEl   = el.querySelector('[data-bm-tablebody]');
  const pagerEl  = el.querySelector('[data-bm-pager]');
  const searchEl = el.querySelector('[data-bm-search]');

  const render = (rows) => {
    if (!rows.length) { bodyEl.innerHTML = skin.emptyState(q ? 'No matches.' : 'Nothing here yet.'); return; }
    const head = skin.tr({ cells: cols.map((c) => skin.th(c.label)).join(''), clickable: false });
    const body = rows.map((row) => {
      const cells = cols.map((c) => skin.cell(cellHTML(c, row[c.name]))).join('');
      return skin.tr({ cells, clickable: !!opts.onRowClick }).replace('<tr ', `<tr data-bm-id="${esc(row.id)}" `);
    }).join('');
    bodyEl.innerHTML = skin.table({ head, body });
    // Sort: bind by header position (skin-agnostic - no contract change).
    if (sortable) {
      bodyEl.querySelectorAll('thead th').forEach((th, i) => {
        const col = cols[i];
        if (!col) return;
        th.style.cursor = 'pointer';
        th.setAttribute('data-bm-sort', col.name);
        if (sortField === col.name) th.insertAdjacentHTML('beforeend', sortOrder === 'desc' ? ' ↓' : ' ↑');
        th.addEventListener('click', () => {
          if (sortField === col.name) sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
          else { sortField = col.name; sortOrder = 'asc'; }
          offset = 0; refresh();
        });
      });
    }
    if (opts.onRowClick) {
      bodyEl.querySelectorAll('[data-bm-row][data-bm-id]').forEach((tr) => {
        tr.addEventListener('click', () => opts.onRowClick(tr.getAttribute('data-bm-id')));
      });
    }
  };

  const drawPager = () => {
    if (!pagerEl) return;
    const from = total === 0 ? 0 : offset + 1;
    const to = Math.min(offset + perPage, total ?? offset + perPage);
    pagerEl.innerHTML =
      `<span>${from}-${to}${total != null ? ' of ' + total : ''}</span>` +
      `<span class="flex gap-2">
        <button data-pg="prev" class="px-2 py-1 rounded border border-zinc-300 dark:border-zinc-700 disabled:opacity-40" ${offset === 0 ? 'disabled' : ''}>Prev</button>
        <button data-pg="next" class="px-2 py-1 rounded border border-zinc-300 dark:border-zinc-700 disabled:opacity-40" ${total != null && to >= total ? 'disabled' : ''}>Next</button>
      </span>`;
    pagerEl.querySelector('[data-pg="prev"]')?.addEventListener('click', () => { offset = Math.max(0, offset - perPage); refresh(); });
    pagerEl.querySelector('[data-pg="next"]')?.addEventListener('click', () => { offset += perPage; refresh(); });
  };

  let whereOverride;
  const refresh = async () => {
    const where = whereOverride !== undefined ? whereOverride : opts.where;
    // Search: client-side substring across visible columns so it works on
    // ANY table (the server ?q= only filters tables with @@fulltext).
    if (q) {
      const all = await listRows(opts.table, { limit: 1000, where, sort: sortField, order: sortOrder });
      const needle = q.toLowerCase();
      const matches = all.filter((r) => cols.some((c) => String(r[c.name] ?? '').toLowerCase().includes(needle)));
      render(matches.slice(0, 200));
      if (pagerEl) pagerEl.innerHTML = `<span>${matches.length} match${matches.length === 1 ? '' : 'es'} for “${esc(q)}”</span>`;
      return;
    }
    const rows = await listRows(opts.table, { limit: perPage, offset: paginate ? offset : undefined, where, sort: sortField, order: sortOrder });
    render(rows);
    if (paginate) {
      try { total = await bm.table(opts.table).count({ where }); } catch (_) { total = null; }
      drawPager();
    }
  };

  if (searchEl) {
    let t;
    searchEl.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { q = searchEl.value.trim(); offset = 0; refresh(); }, 250); });
  }
  await refresh();
  // Live: re-fetch on any mutation to this table (debounced + deduped).
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => refresh()) : bm.live(opts.table, () => refresh());
  // setWhere lets a FilterBar push a new filter set and re-query live.
  const setWhere = (w) => { whereOverride = w || {}; offset = 0; if (searchEl) { searchEl.value = ''; q = ''; } return refresh(); };
  return { refresh, setWhere, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// ─── Cards - same descriptor, card grid instead of rows ──────────────
// Cards(target, { table, where?, limit?, title?, subtitle?, badge?,
//                 onCardClick? }) → { refresh, destroy }
// title/subtitle/badge name columns; defaults derive from the schema.
export async function Cards(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const desc = tableDesc(s, opts.table);
  const titleCol = opts.title || labelField(desc);
  const fields = visible(desc).filter((f) => f.name !== titleCol);
  const subCol  = opts.subtitle || (fields.find((f) => ['email','company','subtitle','summary'].includes(f.name)) || {}).name;
  const badgeCol = opts.badge || (fields.find((f) => ['status','state','kind','type'].includes(f.name)) || {}).name;
  const metaCols = fields.filter((f) => f.name !== subCol && f.name !== badgeCol).slice(0, 3);

  const render = (rows) => {
    if (!rows.length) { el.innerHTML = skin.emptyState('Nothing here yet.'); return; }
    el.innerHTML = `<div data-bm-cards class="grid gap-3" style="grid-template-columns:repeat(auto-fill,minmax(220px,1fr))">` +
      rows.map((row) => `<div data-bm-card data-bm-id="${esc(row.id)}" class="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 ${opts.onCardClick ? 'cursor-pointer hover:border-zinc-400 dark:hover:border-zinc-600' : ''}">
        <div class="flex items-start justify-between gap-2">
          <div class="font-medium truncate">${esc(row[titleCol] ?? '-')}</div>
          ${badgeCol && row[badgeCol] != null && row[badgeCol] !== '' ? Badge(row[badgeCol], { variant: 'neutral' }) : ''}
        </div>
        ${subCol && row[subCol] ? `<div class="text-sm text-zinc-500 truncate mt-0.5">${esc(row[subCol])}</div>` : ''}
        ${metaCols.length ? `<dl class="mt-3 space-y-1 text-xs text-zinc-500">` + metaCols.map((c) => `<div class="flex justify-between gap-2"><dt>${esc(c.label)}</dt><dd class="text-zinc-700 dark:text-zinc-300">${bm.raw ? cellHTML(c, row[c.name]) : esc(row[c.name])}</dd></div>`).join('') + `</dl>` : ''}
      </div>`).join('') + `</div>`;
    if (opts.onCardClick) el.querySelectorAll('[data-bm-card]').forEach((c) => c.addEventListener('click', () => opts.onCardClick(c.getAttribute('data-bm-id'))));
  };
  const refresh = async () => render(await listRows(opts.table, { limit: opts.limit || 60, where: opts.where }));
  await refresh();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => refresh()) : bm.live(opts.table, () => refresh());
  return { refresh, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// ─── Board - kanban grouped by a column, drag to re-assign ───────────
// Board(target, { table, groupBy, groups?, title?, onMove? }) → { refresh, destroy }
// groups: explicit ordered lane values (recommended - enums aren't in
// the descriptor). Without it, lanes derive from values present in data.
export async function Board(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const desc = tableDesc(s, opts.table);
  const groupBy = opts.groupBy || (visible(desc).find((f) => ['status','state','stage','kind'].includes(f.name)) || {}).name;
  if (!groupBy) throw new Error('sdui: Board needs a groupBy column (status/state/stage)');
  const titleCol = opts.title || labelField(desc);

  const render = (rows) => {
    let lanes = opts.groups ? opts.groups.slice() : [...new Set(rows.map((r) => r[groupBy] ?? '').map(String))];
    if (!lanes.length) lanes = [''];
    const byLane = Object.fromEntries(lanes.map((l) => [l, []]));
    rows.forEach((r) => { const k = String(r[groupBy] ?? ''); (byLane[k] || (byLane[k] = [])).push(r); });
    for (const k of Object.keys(byLane)) if (!lanes.includes(k)) lanes.push(k);
    el.innerHTML = `<div data-bm-board class="flex gap-4 overflow-x-auto pt-1 pb-2">` + lanes.map((lane) => `
      <div data-bm-lane="${esc(lane)}" class="flex-shrink-0 w-64 rounded-lg bg-zinc-50 dark:bg-zinc-900/40 p-2">
        <div class="flex items-center justify-between px-1 py-1.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">
          <span>${esc(humanize(lane) || '-')}</span><span>${byLane[lane].length}</span>
        </div>
        <div data-bm-lane-body class="space-y-2 min-h-[40px]">${byLane[lane].map((r) => `
          <div draggable="true" data-bm-card data-bm-id="${esc(r.id)}" class="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-2.5 text-sm cursor-grab">${esc(r[titleCol] ?? r.id)}</div>`).join('')}</div>
      </div>`).join('') + `</div>`;
    let dragId = null;
    el.querySelectorAll('[data-bm-card]').forEach((c) => {
      c.addEventListener('dragstart', () => { dragId = c.getAttribute('data-bm-id'); });
    });
    el.querySelectorAll('[data-bm-lane]').forEach((lane) => {
      // Inset highlight - a Tailwind `ring` draws OUTSIDE the box and gets
      // clipped by the overflow-x container at the top; an inset shadow
      // stays within the lane so it's never cropped.
      lane.addEventListener('dragover', (e) => { e.preventDefault(); lane.style.boxShadow = 'inset 0 0 0 2px #60a5fa'; });
      lane.addEventListener('dragleave', () => { lane.style.boxShadow = ''; });
      lane.addEventListener('drop', async (e) => {
        e.preventDefault(); lane.style.boxShadow = '';
        const to = lane.getAttribute('data-bm-lane');
        if (dragId == null) return;
        try {
          // A kanban over a workflow-governed column must MOVE via the state
          // machine (CRUD strips workflow-protected fields). Pass transition:true.
          if (opts.transition) await bm.workflow(opts.table, dragId).transitionTo(to);
          else await bm.table(opts.table).update(dragId, { [groupBy]: to });
          if (opts.onMove) opts.onMove(dragId, to); await refresh();
        } catch (ex) { Toast(ex?.message || 'Move failed', { type: 'error' }); }
      });
    });
  };
  const refresh = async () => render(await listRows(opts.table, { limit: opts.limit || 200, where: opts.where }));
  await refresh();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => refresh()) : bm.live(opts.table, () => refresh());
  return { refresh, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// ─── RecordForm ───────────────────────────────────────────────────────
// RecordForm(target, { table, id?, onSaved? }) → { destroy }
// Renders only fields the caller may write (descriptor.writable). On
// submit: create (no id) or update (id) via the typed CRUD SDK.
export async function RecordForm(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const desc = tableDesc(s, opts.table);
  const fields = editable(desc);
  const existing = opts.id != null ? await bm.table(opts.table).get(opts.id) : {};

  // Pre-fetch <option> lists for any FK fields (relation pickers).
  const relOpts = {};
  for (const f of fields) {
    if (f.relation) relOpts[f.name] = await relationOptions(f.relation.table, existing[f.name]);
  }

  const fieldHtml = (f) => skin.field({ label: f.label, required: f.required, inner: controlHTML(f, existing[f.name], relOpts[f.name]), inline: f.control === 'checkbox' });
  // sections: [{title, fields:'a,b'}] groups fields under titled headings
  // (all visible - unlike WizardForm's one-at-a-time steps). Unlisted
  // fields fall into a trailing untitled group so none are dropped.
  let body;
  if (opts.sections && opts.sections.length) {
    const byName = Object.fromEntries(fields.map((f) => [f.name, f]));
    const used = new Set();
    body = opts.sections.map((sec) => {
      const fs = String(sec.fields).split(',').map((n) => byName[n.trim()]).filter(Boolean);
      fs.forEach((f) => used.add(f.name));
      return `<fieldset style="border:none;padding:0;margin:0 0 18px"><legend style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;opacity:.55;margin-bottom:10px;padding:0">${esc(sec.title || '')}</legend>${fs.map(fieldHtml).join('')}</fieldset>`;
    }).join('');
    const leftover = fields.filter((f) => !used.has(f.name));
    if (leftover.length) body += `<fieldset style="border:none;padding:0;margin:0 0 18px">${leftover.map(fieldHtml).join('')}</fieldset>`;
  } else {
    body = fields.map(fieldHtml).join('');
  }
  el.innerHTML = `<form data-bm-form class="space-y-4">${skin.error('')}${body}<div>${skin.button({ label: opts.id != null ? 'Save' : 'Create' })}</div></form>`;

  const form = el.querySelector('form');
  wireUploadFields(form); // image/file controls → upload pickers
  const errEl = el.querySelector('[data-bm-error]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errEl) errEl.hidden = true;
    const fd = new FormData(form);
    const payload = {};
    for (const f of fields) {
      if (f.control === 'checkbox') { payload[f.name] = fd.get(f.name) ? 1 : 0; continue; }
      const val = fd.get(f.name);
      if (val === null) continue;
      payload[f.name] = f.control === 'number' && val !== '' ? Number(val) : val;
    }
    try {
      const saved = opts.id != null
        ? await bm.table(opts.table).update(opts.id, payload)
        : await bm.table(opts.table).create(payload);
      if (opts.id == null) form.reset();
      if (opts.onSaved) opts.onSaved(saved);
    } catch (ex) {
      if (errEl) { errEl.textContent = ex?.message || 'Save failed'; errEl.hidden = false; }
    }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── WizardForm - multi-step RecordForm ─────────────────────────────
// WizardForm(target, { table, steps, id?, onSaved? }) → { destroy }
// steps: [{ title, fields: "name,email" }, { title, fields: "company,status" }]
// Step GROUPING is a UX choice the schema can't carry - you declare it.
// Everything else (controls, relation pickers, per-step validation,
// create/update) is still derived. With no steps it's a one-step form.
export async function WizardForm(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const desc = tableDesc(s, opts.table);
  const all = editable(desc);
  const byName = Object.fromEntries(all.map((f) => [f.name, f]));
  const existing = opts.id != null ? await bm.table(opts.table).get(opts.id) : {};

  const groups = (opts.steps && opts.steps.length)
    ? opts.steps.map((st) => ({ title: st.title || '', fields: String(st.fields).split(',').map((n) => byName[n.trim()]).filter(Boolean) }))
    : [{ title: '', fields: all }];
  const flat = groups.flatMap((g) => g.fields);

  const relOpts = {};
  for (const f of flat) if (f.relation) relOpts[f.name] = await relationOptions(f.relation.table, existing[f.name]);

  const stepHTML = groups.map((g, i) =>
    `<div data-bm-step="${i}" ${i === 0 ? '' : 'hidden'}>` +
    (g.title ? `<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;opacity:.55;margin-bottom:12px">${esc(g.title)}</div>` : '') +
    g.fields.map((f) => skin.field({ label: f.label, required: f.required, inner: controlHTML(f, existing[f.name], relOpts[f.name]), inline: f.control === 'checkbox' })).join('') +
    `</div>`).join('');

  el.innerHTML = `<form data-bm-wizard class="space-y-4">${skin.error('')}
    <div data-bm-progress style="font-size:12px;opacity:.6;margin-bottom:4px"></div>
    ${stepHTML}
    <div data-bm-nav style="display:flex;justify-content:space-between;gap:8px;margin-top:8px"></div></form>`;

  const form = el.querySelector('form');
  wireUploadFields(form); // image/file controls → upload pickers
  const errEl = el.querySelector('[data-bm-error]');
  const nav = form.querySelector('[data-bm-nav]');
  const progress = form.querySelector('[data-bm-progress]');
  const navBtn = 'font-size:14px;padding:8px 16px;border-radius:6px;border:1px solid currentColor;background:transparent;opacity:.65;cursor:pointer';
  let cur = 0;

  const draw = () => {
    groups.forEach((_, i) => { const d = form.querySelector(`[data-bm-step="${i}"]`); if (d) d.hidden = i !== cur; });
    progress.textContent = `Step ${cur + 1} of ${groups.length}` + (groups[cur].title ? ` · ${groups[cur].title}` : '');
    const back = cur > 0 ? `<button type="button" data-nav="back" style="${navBtn}">Back</button>` : `<span></span>`;
    const fwd = cur < groups.length - 1
      ? `<button type="button" data-nav="next" style="${navBtn};opacity:1">Next</button>`
      : skin.button({ label: opts.id != null ? 'Save' : 'Create' });
    nav.innerHTML = back + fwd;
    nav.querySelector('[data-nav="back"]')?.addEventListener('click', () => { cur--; draw(); });
    nav.querySelector('[data-nav="next"]')?.addEventListener('click', () => {
      const stepEl = form.querySelector(`[data-bm-step="${cur}"]`);
      const bad = [...stepEl.querySelectorAll('input,select,textarea')].find((x) => !x.checkValidity());
      if (bad) { bad.reportValidity(); return; }
      cur++; draw();
    });
  };
  draw();

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errEl) errEl.hidden = true;
    const fd = new FormData(form);
    const payload = {};
    for (const f of flat) {
      if (f.control === 'checkbox') { payload[f.name] = fd.get(f.name) ? 1 : 0; continue; }
      const val = fd.get(f.name);
      if (val === null) continue;
      payload[f.name] = f.control === 'number' && val !== '' ? Number(val) : val;
    }
    try {
      const saved = opts.id != null
        ? await bm.table(opts.table).update(opts.id, payload)
        : await bm.table(opts.table).create(payload);
      if (opts.id == null) { cur = 0; draw(); form.reset(); }
      if (opts.onSaved) opts.onSaved(saved);
    } catch (ex) {
      if (errEl) { errEl.textContent = ex?.message || 'Save failed'; errEl.hidden = false; }
    }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── Detail - read-only record view + embedded child tables ──────────
// Detail(target, { table, id, children? }) → { destroy }
// Renders the record's fields, then embeds a DataTable for each
// one-to-many child relation (reverse FKs, from descriptor.children).
export async function Detail(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const desc = tableDesc(s, opts.table);
  const row = await bm.table(opts.table).get(opts.id);
  const dl = visible(desc).map((f) =>
    `<div class="py-2 border-b border-zinc-100 dark:border-zinc-800/60"><dt class="text-xs uppercase tracking-wide text-zinc-500">${esc(f.label)}</dt><dd class="mt-0.5">${cellHTML(f, row[f.name])}</dd></div>`
  ).join('');
  el.innerHTML = `<dl class="text-sm" data-bm-detail>${dl}</dl>`;
  const all = desc.children || [];
  const children = opts.children
    ? opts.children.split(',').map((t) => all.find((c) => c.table === t.trim())).filter(Boolean)
    : all;
  const subs = [];
  for (const c of children) {
    const wrap = document.createElement('div');
    wrap.className = 'mt-6 space-y-2';
    wrap.innerHTML = `<h3 class="text-sm font-semibold uppercase tracking-wide text-zinc-500">${esc(humanize(c.table))}</h3><div data-bm-child></div>`;
    el.appendChild(wrap);
    subs.push(await DataTable(wrap.querySelector('[data-bm-child]'), { table: c.table, where: { [c.column]: opts.id } }));
  }
  return { destroy: () => { subs.forEach((x) => x && x.destroy && x.destroy()); el.innerHTML = ''; } };
}

// ─── helpers for the B/C components ──────────────────────────────────
function humanize(s) {
  return String(s).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

let _flows = null;
async function flowsRegistry() {
  if (_flows) return _flows;
  const res = await fetch('/_internal/flows.json', { credentials: 'same-origin' });
  _flows = res.ok ? await res.json() : {};
  return _flows;
}

let _me;
async function currentUser() {
  if (_me === undefined) _me = await bm.auth.me();
  return _me;
}

// Resolve a user_id → { name, src(avatar), email } for author chips/avatars.
// Fast-path the current user (no extra request); otherwise hit the user
// directory (GET /api/_auth/users/{id}, works when the app opts into
// access._benmore_users.read: group|everyone) and gracefully fall back to
// initials if the directory is private. Cached per id (stores the promise).
const _userCache = new Map();
function userDisplay(u) {
  if (!u) return null;
  const name = u.name || [u.first_name, u.last_name].filter(Boolean).join(' ').trim() || u.username || u.email || null;
  const src = u.avatar || u.avatar_url || u.photo || u.image || u.picture || null;
  return { name, src, email: u.email || null };
}
async function resolveAuthor(userId) {
  if (userId == null || userId === '') return null;
  const key = String(userId);
  if (_userCache.has(key)) return _userCache.get(key);
  const p = (async () => {
    try { const me = await currentUser(); if (me && String(me.id) === key) return userDisplay(me); } catch (_) {}
    try { const u = await bm.api.get('/api/_auth/users/' + encodeURIComponent(key)); return userDisplay(u && u.user ? u.user : u); } catch (_) { return null; }
  })();
  _userCache.set(key, p);
  return p;
}
// Resolve a batch of ids → { [id]: {name,src,email} }.
async function resolveAuthors(ids) {
  const uniq = [...new Set(ids.filter((v) => v != null && v !== ''))];
  const out = {};
  await Promise.all(uniq.map(async (id) => { out[id] = await resolveAuthor(id); }));
  return out;
}

// control for a declared flow input (inputs carry their own enum values,
// unlike table columns - so enum renders a real <select>).
function flowControlHTML(name, inp) {
  const v = inp.default ?? '';
  switch (inp.type) {
    case 'enum':
      return `<select name="${esc(name)}" class="${inputCls}">` +
        (inp.values || []).map((o) => `<option value="${esc(o)}" ${String(v) === String(o) ? 'selected' : ''}>${esc(o)}</option>`).join('') +
        `</select>`;
    case 'bool':     return skin.checkbox({ name, checked: !!v });
    case 'textarea': return skin.textarea({ name, value: v, required: inp.required });
    case 'number': {
      const mm = (inp.min != null ? ` min="${esc(inp.min)}"` : '') + (inp.max != null ? ` max="${esc(inp.max)}"` : '');
      return `<input name="${esc(name)}" type="number" value="${esc(v)}" ${inp.required ? 'required' : ''}${mm} class="${inputCls}">`;
    }
    case 'date':  return skin.input({ name, type: 'date', value: String(v).slice(0, 10), required: inp.required, control: 'date' });
    case 'email': return skin.input({ name, type: 'email', value: v, required: inp.required, control: 'email' });
    default:      return skin.input({ name, type: 'text', value: v, required: inp.required, control: 'text' });
  }
}

// ─── FlowForm - derive a form from a flow's declared inputs ───────────
// FlowForm(target, { flow, params?, onResult? }) → { destroy }
// Renders the flow's inputs: block, calls bm.flows.<flow>(), auto-polls
// when the flow is mode: async, and renders the response.
export async function FlowForm(target, opts) {
  const el = resolveEl(target);
  const reg = await flowsRegistry();
  const def = reg[opts.flow];
  if (!def) throw new Error(`sdui: flow "${opts.flow}" not in /_internal/flows.json`);
  const inputs = def.inputs || {};
  const names = Object.keys(inputs).sort();
  const body = names.map((n) => {
    const inp = inputs[n];
    return skin.field({ label: inp.label || humanize(n), required: !!inp.required, inner: flowControlHTML(n, inp), inline: inp.type === 'bool' });
  }).join('');
  el.innerHTML = `<form data-bm-flowform class="space-y-4">${skin.error('')}${body}<div>${skin.button({ label: 'Submit' })}</div><div data-bm-result class="text-sm mt-2"></div></form>`;
  const form = el.querySelector('form');
  wireUploadFields(form); // image/file controls → upload pickers
  const errEl = el.querySelector('[data-bm-error]');
  const resultEl = el.querySelector('[data-bm-result]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errEl) errEl.hidden = true;
    const fd = new FormData(form);
    const payload = {};
    for (const n of names) {
      const inp = inputs[n];
      if (inp.type === 'bool') { payload[n] = !!fd.get(n); continue; }
      const val = fd.get(n);
      if (val === null || val === '') continue;
      payload[n] = inp.type === 'number' ? Number(val) : val;
    }
    resultEl.textContent = 'Working…';
    try {
      let res = await bm.flows[opts.flow](opts.params || {}, payload);
      if (res && typeof res.wait === 'function') { resultEl.textContent = 'Processing…'; res = await res.wait(); }
      resultEl.innerHTML = `<pre class="bg-zinc-50 dark:bg-zinc-900 rounded-md p-3 overflow-x-auto text-xs">${esc(JSON.stringify(res, null, 2))}</pre>`;
      if (opts.onResult) opts.onResult(res);
    } catch (ex) {
      resultEl.textContent = '';
      if (errEl) { errEl.textContent = ex?.message || 'Flow failed'; errEl.hidden = false; }
    }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── Transitions - workflow state machine buttons ────────────────────
// Transitions(target, { table, id, onTransition? }) → { refresh, destroy }
export async function Transitions(target, opts) {
  const el = resolveEl(target);
  const wf = bm.workflow(opts.table, opts.id);
  const render = async () => {
    let avail = [];
    try { avail = await wf.available(); } catch (_) { avail = []; }
    const list = Array.isArray(avail) ? avail : (avail?.transitions || avail?.available || []);
    if (!list.length) { el.innerHTML = skin.emptyState('No transitions available.'); return; }
    el.innerHTML = `<div class="flex flex-wrap gap-2" data-bm-transitions>` + list.map((s) => {
      const to = typeof s === 'string' ? s : (s.to || s.state || s.name);
      return `<button data-to="${esc(to)}" class="px-3 py-1.5 rounded-md border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-sm font-medium">${esc(humanize(to))}</button>`;
    }).join('') + `</div>`;
    el.querySelectorAll('[data-to]').forEach((b) => b.addEventListener('click', async () => {
      const to = b.getAttribute('data-to');
      try { await wf.transitionTo(to); if (opts.onTransition) opts.onTransition(to); await render(); }
      catch (ex) { alert(ex?.message || 'Transition failed'); }
    }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}

// ─── Gate / can / hasRole - policy decorators (Category C) ───────────
export async function can(perm) {
  const u = await currentUser();
  if (!u) return false;
  const perms = u.permissions || [];
  if (perms.includes('*') || perms.includes('*:*')) return true;
  if (perms.includes(perm)) return true;
  const [res, act] = String(perm).split(':');
  if (perms.includes(res + ':*')) return true;
  if (act === 'read' && perms.includes(res + ':write')) return true; // write implies read
  return false;
}
export async function hasRole(role) {
  const u = await currentUser();
  if (!u) return false;
  const roles = u.roles || (u.role ? [u.role] : []);
  if (roles.includes('admin')) return true;
  return String(role).split(',').some((r) => roles.includes(r.trim()));
}
// Gate(target, { perm? | role? }) - hides the element unless allowed.
export async function Gate(target, opts) {
  const el = resolveEl(target);
  let ok = true;
  if (opts.perm) ok = await can(opts.perm);
  else if (opts.role) ok = await hasRole(opts.role);
  if (ok) el.removeAttribute('hidden'); else el.setAttribute('hidden', '');
  return ok;
}

// ─── Uploader - capability wrapper over bm.upload (Category B) ───────
// Pattern for the other B wrappers (Broadcast/Presence/NotificationBell):
// thin DOM + one bm.* primitive.
export async function Uploader(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<input type="file" data-bm-upload class="block text-sm"><div data-bm-upload-status class="text-sm text-zinc-500 mt-1"></div>`;
  const input = el.querySelector('input');
  const status = el.querySelector('[data-bm-upload-status]');
  input.addEventListener('change', async () => {
    if (!input.files || !input.files.length) return;
    status.textContent = 'Uploading…';
    try {
      const r = await bm.upload(input.files[0]);
      status.textContent = 'Uploaded ✓';
      if (opts.onUpload) opts.onUpload(r);
    } catch (ex) { status.textContent = 'Upload failed: ' + (ex?.message || ''); }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── shared UI helpers for the display + primitive components ────────
function ensureStyles() {
  if (typeof document === 'undefined' || document.getElementById('bm-sdui-styles')) return;
  const st = document.createElement('style');
  st.id = 'bm-sdui-styles';
  st.textContent = `
@keyframes bm-spin{to{transform:rotate(360deg)}}
@keyframes bm-shimmer{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes bm-toast-in{from{transform:translateY(8px);opacity:0}to{transform:translateY(0);opacity:1}}
@keyframes bm-pulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.55)}70%{box-shadow:0 0 0 6px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}
.bm-spin{animation:bm-spin .7s linear infinite}
.bm-ctl{color-scheme:light;background-color:#fff;color:#18181b;padding:var(--bm-input-py,8px) var(--bm-input-px,12px);font-size:var(--bm-input-fs,inherit);border-radius:var(--bm-input-radius,6px)}
.bm-ctl::placeholder{color:#9ca3af}
select.bm-ctl{padding-right:30px}
/* accent fill: color comes from the var (no !important) so apps can layer a
   gradient/custom background via normal specificity. Only token-driven SIZING
   keeps !important (it has to beat the components' inline Tailwind utilities). */
.bm-accent-bg{background:var(--bm-accent,#2563eb);color:var(--bm-accent-text,#fff)}
.bm-accent-text{color:var(--bm-accent,#2563eb)}
/* Accent BUTTONS also read sizing from tokens, so an app's button system
   (height/padding/font/radius) matches without per-component overrides.
   Override per-app: :root{--bm-btn-px:14px;--bm-btn-py:7px;--bm-btn-fs:12.5px;--bm-btn-radius:6px} */
button.bm-accent-bg{padding:var(--bm-btn-py,8px) var(--bm-btn-px,14px)!important;font-size:var(--bm-btn-fs,14px)!important;border-radius:var(--bm-btn-radius,8px)!important;border:none!important;cursor:pointer;font-weight:600;line-height:1.2}
.bm-online{animation:bm-pulse 2s ease-out infinite}
[data-bm-skeleton]{animation:bm-shimmer 1.4s ease-in-out infinite;background:rgba(130,130,130,.25);border-radius:6px}
[data-bm-toast]{animation:bm-toast-in .18s ease-out}`;
  document.head.appendChild(st);
}
// content may be an HTML string, a DOM Node, or a function(el) that
// mounts into el (and may return an HTML string).
function setContent(el, content) {
  if (content == null) return;
  if (typeof content === 'function') { const r = content(el); if (typeof r === 'string') el.innerHTML = r; }
  else if (typeof Node !== 'undefined' && content instanceof Node) el.appendChild(content);
  else el.innerHTML = String(content);
}

// ─── Stat - a single metric tile (count / aggregate / custom) ────────
// Stat(target, { table, where?, q?, aggregate?, value?, label?, format? })
export async function Stat(target, opts) {
  const el = resolveEl(target);
  const render = (val) => {
    el.innerHTML = `<div data-bm-stat class="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4">
      <div class="text-xs uppercase tracking-wide text-zinc-500">${esc(opts.label || humanize(opts.table || opts.aggregate || 'Value'))}</div>
      <div class="text-2xl font-semibold mt-1 tabular-nums">${esc(opts.format ? opts.format(val) : val)}</div>
    </div>`;
  };
  const compute = async () => {
    if (opts.aggregate) return await bm.aggregate(opts.aggregate);
    if (opts.value != null) return typeof opts.value === 'function' ? await opts.value() : opts.value;
    return await bm.table(opts.table).count({ where: opts.where, q: opts.q });
  };
  const refresh = async () => { try { render(await compute()); } catch (_) { render('-'); } };
  await refresh();
  let stop = null;
  if (opts.table && opts.live !== false) stop = bm.live.scoped ? bm.live.scoped(opts.table, () => refresh()) : bm.live(opts.table, () => refresh());
  return { refresh, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// ─── Chart - Chart.js over a table group-by (or explicit data) ───────
// Chart(target, { type?, table, groupBy, value?, data?, label?, height? })
// value: 'count' (default) or 'sum:<col>'. data: {labels,values} bypasses derivation.
let _chartLib = null, _chartLoading = null;
function loadChart() {
  if (_chartLib) return Promise.resolve(_chartLib);
  if (typeof window !== 'undefined' && window.Chart) return Promise.resolve(_chartLib = window.Chart);
  if (!_chartLoading) _chartLoading = new Promise((res, rej) => {
    const sc = document.createElement('script');
    sc.src = '/_internal/chart.js';
    sc.onload = () => res(window.Chart);
    sc.onerror = () => rej(new Error('sdui: failed to load /_internal/chart.js'));
    document.head.appendChild(sc);
  });
  return _chartLoading.then((c) => (_chartLib = c));
}
const _chartPalette = ['var(--bm-accent,#2563eb)','#16a34a','#d97706','#dc2626','#7c3aed','#0891b2','#db2777','#65a30d'];
export async function Chart(target, opts) {
  const el = resolveEl(target);
  const ChartLib = await loadChart();
  el.innerHTML = `<div data-bm-chart style="position:relative;height:${opts.height || 260}px"><canvas></canvas></div>`;
  const canvas = el.querySelector('canvas');
  let chart = null;
  const computeData = async () => {
    if (opts.data) return { labels: opts.data.labels || Object.keys(opts.data), values: opts.data.values || Object.values(opts.data) };
    const rows = await listRows(opts.table, { limit: opts.limit || 1000, where: opts.where });
    const sumCol = opts.value && String(opts.value).startsWith('sum:') ? opts.value.slice(4) : null;
    const map = new Map();
    for (const r of rows) { const k = String(r[opts.groupBy] ?? '-'); map.set(k, (map.get(k) || 0) + (sumCol ? (Number(r[sumCol]) || 0) : 1)); }
    return { labels: [...map.keys()], values: [...map.values()] };
  };
  const refresh = async () => {
    const { labels, values } = await computeData();
    const type = opts.type || 'bar';
    const isPie = type === 'pie' || type === 'doughnut';
    const ds = { label: opts.label || '', data: values, backgroundColor: isPie ? labels.map((_, i) => _chartPalette[i % _chartPalette.length]) : (opts.color || _chartPalette[0]), borderColor: isPie ? '#fff' : (opts.color || _chartPalette[0]), borderWidth: isPie ? 1 : 0, borderRadius: isPie ? 0 : 4 };
    if (chart) {
      // Skip a no-op redraw, and when data DID change update without
      // replaying the entry animation - otherwise every live refresh
      // (e.g. an unrelated mutation to the same table) re-animates.
      const same = JSON.stringify(chart.data.labels) === JSON.stringify(labels) && JSON.stringify(chart.data.datasets[0].data) === JSON.stringify(values);
      if (!same) { chart.data.labels = labels; chart.data.datasets[0].data = values; chart.update('none'); }
    }
    else chart = new ChartLib(canvas.getContext('2d'), { type, data: { labels, datasets: [ds] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: isPie } }, scales: isPie ? {} : { y: { beginAtZero: true } } } });
  };
  await refresh();
  let stop = null;
  if (opts.table && opts.live !== false) stop = bm.live.scoped ? bm.live.scoped(opts.table, () => refresh()) : bm.live(opts.table, () => refresh());
  return { refresh, destroy: () => { try { stop && stop(); } catch (_) {} if (chart) chart.destroy(); el.innerHTML = ''; } };
}

// ─── Modal / Drawer - overlay primitives ─────────────────────────────
// Modal({ title?, content, size?, onClose?, dismissable? }) → { close, el, panel }
// `el` is the body container - mount any component into it.
export function Modal(opts = {}) {
  ensureStyles();
  const back = document.createElement('div');
  back.setAttribute('data-bm-modal', '');
  back.style.cssText = 'position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.5);display:flex;align-items:flex-start;justify-content:center;padding:8vh 16px;overflow:auto';
  const panel = document.createElement('div');
  const sizes = { sm: '420px', md: '560px', lg: '760px', xl: '960px' };
  panel.style.cssText = `background:var(--card,#fff);color:inherit;border-radius:12px;width:100%;max-width:${sizes[opts.size] || sizes.md};box-shadow:0 24px 64px rgba(0,0,0,.35)`;
  panel.innerHTML = `${opts.title ? `<div style="padding:16px 20px;border-bottom:1px solid rgba(128,128,128,.2);display:flex;justify-content:space-between;align-items:center"><h2 style="font-weight:600;font-size:16px">${esc(opts.title)}</h2><button data-bm-close style="font-size:22px;line-height:1;background:none;border:none;cursor:pointer;opacity:.5">×</button></div>` : ''}<div data-bm-body style="padding:20px"></div>`;
  back.appendChild(panel);
  const body = panel.querySelector('[data-bm-body]');
  setContent(body, opts.content);
  document.body.appendChild(back);
  const close = () => { back.remove(); window.removeEventListener('keydown', onKey); if (opts.onClose) opts.onClose(); };
  const onKey = (e) => { if (e.key === 'Escape' && opts.dismissable !== false) close(); };
  window.addEventListener('keydown', onKey);
  back.addEventListener('mousedown', (e) => { if (e.target === back && opts.dismissable !== false) close(); });
  panel.querySelector('[data-bm-close]')?.addEventListener('click', close);
  return { close, el: body, panel };
}
// Drawer({ side?, width?, title?, content, onClose? }) → { close, el, panel }
export function Drawer(opts = {}) {
  ensureStyles();
  const side = opts.side === 'left' ? 'left' : 'right';
  const back = document.createElement('div');
  back.setAttribute('data-bm-drawer', '');
  back.style.cssText = 'position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.4)';
  const panel = document.createElement('div');
  panel.style.cssText = `position:absolute;top:0;${side}:0;height:100%;width:min(${opts.width || '420px'},90vw);background:var(--card,#fff);box-shadow:0 0 40px rgba(0,0,0,.3);display:flex;flex-direction:column;transform:translateX(${side === 'right' ? '100%' : '-100%'});transition:transform .2s ease`;
  panel.innerHTML = `${opts.title ? `<div style="padding:16px 20px;border-bottom:1px solid rgba(128,128,128,.2);display:flex;justify-content:space-between;align-items:center"><h2 style="font-weight:600">${esc(opts.title)}</h2><button data-bm-close style="font-size:22px;background:none;border:none;cursor:pointer;opacity:.5">×</button></div>` : ''}<div data-bm-body style="padding:20px;overflow:auto;flex:1"></div>`;
  back.appendChild(panel);
  const body = panel.querySelector('[data-bm-body]');
  setContent(body, opts.content);
  document.body.appendChild(back);
  requestAnimationFrame(() => { panel.style.transform = 'translateX(0)'; });
  const close = () => { panel.style.transform = `translateX(${side === 'right' ? '100%' : '-100%'})`; setTimeout(() => back.remove(), 200); window.removeEventListener('keydown', onKey); if (opts.onClose) opts.onClose(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  window.addEventListener('keydown', onKey);
  back.addEventListener('mousedown', (e) => { if (e.target === back) close(); });
  panel.querySelector('[data-bm-close]')?.addEventListener('click', close);
  return { close, el: body, panel };
}

// ─── Tabs / Accordion - layout primitives ────────────────────────────
// Tabs(target, { tabs:[{label, content}], active? }) → { select, destroy }
export function Tabs(target, opts) {
  const el = resolveEl(target);
  const tabs = opts.tabs || [];
  el.innerHTML = `<div data-bm-tabs><div data-bm-tablist role="tablist" style="display:flex;gap:4px;border-bottom:1px solid rgba(128,128,128,.2);margin-bottom:16px">${tabs.map((t, i) => `<button data-tab="${i}" style="padding:8px 14px;font-size:14px;font-weight:500;background:none;border:none;border-bottom:2px solid transparent;cursor:pointer;opacity:.6">${esc(t.label)}</button>`).join('')}</div><div data-bm-panel></div></div>`;
  const panel = el.querySelector('[data-bm-panel]');
  const select = (i) => {
    el.querySelectorAll('[data-tab]').forEach((b, j) => { const on = j === i; b.style.opacity = on ? '1' : '.6'; b.style.borderBottomColor = on ? 'currentColor' : 'transparent'; });
    panel.innerHTML = ''; setContent(panel, tabs[i] && tabs[i].content);
  };
  el.querySelectorAll('[data-tab]').forEach((b, i) => b.addEventListener('click', () => select(i)));
  select(opts.active || 0);
  return { select, destroy: () => { el.innerHTML = ''; } };
}
// Accordion(target, { items:[{title, content, open?}], multi? }) → { destroy }
export function Accordion(target, opts) {
  const el = resolveEl(target);
  const items = opts.items || [];
  el.innerHTML = `<div data-bm-accordion style="border-top:1px solid rgba(128,128,128,.2)">` + items.map((it, i) => `<div data-bm-acc-item style="border-bottom:1px solid rgba(128,128,128,.2)"><button data-acc="${i}" style="width:100%;text-align:left;padding:12px 4px;font-weight:500;display:flex;justify-content:space-between;background:none;border:none;cursor:pointer"><span>${esc(it.title)}</span><span data-acc-ico style="opacity:.5;transition:transform .15s">▸</span></button><div data-acc-body hidden style="padding:0 4px 12px"></div></div>`).join('') + `</div>`;
  el.querySelectorAll('[data-bm-acc-item]').forEach((item, i) => {
    const body = item.querySelector('[data-acc-body]'), ico = item.querySelector('[data-acc-ico]');
    let loaded = false;
    const toggle = () => {
      const willOpen = body.hidden;
      if (willOpen && !opts.multi) el.querySelectorAll('[data-acc-body]').forEach((b) => { if (b !== body) b.hidden = true; });
      if (willOpen && !opts.multi) el.querySelectorAll('[data-acc-ico]').forEach((x) => { x.style.transform = ''; });
      if (willOpen) { if (!loaded) { setContent(body, items[i].content); loaded = true; } body.hidden = false; ico.style.transform = 'rotate(90deg)'; }
      else { body.hidden = true; ico.style.transform = ''; }
    };
    item.querySelector('[data-acc]').addEventListener('click', toggle);
    if (items[i].open) toggle();
  });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── Toast - transient notification (global stack) ───────────────────
// Toast(message, { type?, duration?, action? }) → { dismiss }
function toastContainer() {
  let c = document.getElementById('bm-toasts');
  if (!c) { c = document.createElement('div'); c.id = 'bm-toasts'; c.style.cssText = 'position:fixed;z-index:9999;bottom:16px;right:16px;display:flex;flex-direction:column;gap:8px;max-width:360px'; document.body.appendChild(c); }
  return c;
}
export function Toast(message, opts = {}) {
  ensureStyles();
  const colors = { info: 'var(--bm-accent,#2563eb)', success: '#16a34a', error: '#dc2626', warning: '#d97706' };
  const t = document.createElement('div');
  t.setAttribute('data-bm-toast', opts.type || 'info');
  t.style.cssText = `background:#18181b;color:#fff;border-left:3px solid ${colors[opts.type] || colors.info};padding:10px 14px;border-radius:8px;font-size:14px;box-shadow:0 6px 24px rgba(0,0,0,.25);display:flex;gap:10px;align-items:center`;
  t.innerHTML = `<span style="flex:1">${esc(message)}</span>`;
  const dismiss = () => { t.style.transition = 'opacity .15s'; t.style.opacity = '0'; setTimeout(() => t.remove(), 160); };
  if (opts.action) { const b = document.createElement('button'); b.textContent = opts.action.label; b.style.cssText = 'color:#93c5fd;font-weight:600;background:none;border:none;cursor:pointer'; b.onclick = () => { opts.action.onClick && opts.action.onClick(); dismiss(); }; t.appendChild(b); }
  toastContainer().appendChild(t);
  const dur = opts.duration ?? 4000;
  if (dur > 0) setTimeout(dismiss, dur);
  return { dismiss };
}

// ─── Dropdown / Tooltip ──────────────────────────────────────────────
// Dropdown(target, { label, items:[{label, onClick?, href?, danger?}] })
export function Dropdown(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-dropdown style="position:relative;display:inline-block"><button data-dd-trigger style="padding:8px 12px;border:1px solid rgba(128,128,128,.3);border-radius:8px;background:none;cursor:pointer;font-size:14px">${esc(opts.label || 'Menu')} ▾</button><div data-dd-menu hidden style="position:absolute;z-index:50;margin-top:4px;min-width:160px;background:var(--card,#fff);border:1px solid rgba(128,128,128,.2);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.15);overflow:hidden">${(opts.items || []).map((it, i) => `<button data-dd-item="${i}" style="display:block;width:100%;text-align:left;padding:8px 12px;font-size:14px;background:none;border:none;cursor:pointer;color:${it.danger ? '#dc2626' : 'inherit'}">${esc(it.label)}</button>`).join('')}</div></div>`;
  const trigger = el.querySelector('[data-dd-trigger]'), menu = el.querySelector('[data-dd-menu]');
  const onDoc = (e) => { if (!el.contains(e.target)) close(); };
  const close = () => { menu.hidden = true; document.removeEventListener('click', onDoc); };
  trigger.addEventListener('click', (e) => { e.stopPropagation(); if (menu.hidden) { menu.hidden = false; setTimeout(() => document.addEventListener('click', onDoc), 0); } else close(); });
  (opts.items || []).forEach((it, i) => el.querySelector(`[data-dd-item="${i}"]`)?.addEventListener('click', () => { close(); if (it.href) location.href = it.href; else if (it.onClick) it.onClick(); }));
  return { close, destroy: () => { el.innerHTML = ''; } };
}
// Tooltip(target, { text }) → { destroy }
export function Tooltip(target, opts) {
  const el = resolveEl(target);
  if (getComputedStyle(el).position === 'static') el.style.position = 'relative';
  let tip = null;
  const show = () => { tip = document.createElement('div'); tip.textContent = opts.text || ''; tip.style.cssText = 'position:absolute;bottom:100%;left:50%;transform:translateX(-50%);margin-bottom:6px;background:#18181b;color:#fff;font-size:12px;padding:4px 8px;border-radius:6px;white-space:nowrap;z-index:60;pointer-events:none'; el.appendChild(tip); };
  const hide = () => { if (tip) tip.remove(); tip = null; };
  el.addEventListener('mouseenter', show); el.addEventListener('mouseleave', hide);
  return { destroy: () => { hide(); el.removeEventListener('mouseenter', show); el.removeEventListener('mouseleave', hide); } };
}

// ─── Atoms - pure presentational helpers (return HTML strings) ───────
// Use inside bm.html`…${bm.raw(Badge('active'))}` or set innerHTML directly.
export function Badge(text, opts = {}) {
  const v = opts.variant || 'neutral';
  const styles = {
    neutral: 'background:rgba(113,113,122,.15);color:#52525b',
    success: 'background:rgba(22,163,74,.15);color:#15803d',
    warning: 'background:rgba(217,119,6,.15);color:#b45309',
    error:   'background:rgba(220,38,38,.15);color:#b91c1c',
    info:    'background:rgba(37,99,235,.15);color:#1d4ed8',
  };
  return `<span data-bm-badge="${esc(v)}" style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:600;${styles[v] || styles.neutral}">${esc(text)}</span>`;
}
export function Avatar(opts = {}) {
  const size = opts.size || 32;
  if (opts.src) return `<img data-bm-avatar src="${esc(opts.src)}" alt="${esc(opts.name || '')}" style="width:${size}px;height:${size}px;border-radius:9999px;object-fit:cover">`;
  const name = String(opts.name || '?').trim();
  const initials = (name.split(/\s+/).map((w) => w[0]).slice(0, 2).join('') || '?').toUpperCase();
  const hue = [...name].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
  return `<span data-bm-avatar style="display:inline-flex;align-items:center;justify-content:center;width:${size}px;height:${size}px;border-radius:9999px;background:hsl(${hue},60%,88%);color:hsl(${hue},50%,30%);font-size:${Math.round(size * 0.38)}px;font-weight:600">${esc(initials)}</span>`;
}
export function Spinner(opts = {}) {
  ensureStyles();
  const size = opts.size || 20;
  return `<span class="bm-spin" data-bm-spinner style="display:inline-block;width:${size}px;height:${size}px;border:2px solid currentColor;border-right-color:transparent;border-radius:9999px;opacity:.6"></span>`;
}
export function Skeleton(opts = {}) {
  ensureStyles();
  const lines = opts.lines || 3;
  return `<div data-bm-skeletons style="display:flex;flex-direction:column;gap:8px">` + Array.from({ length: lines }, (_, i) => `<div data-bm-skeleton style="height:${opts.height || 12}px;width:${i === lines - 1 ? '60%' : (opts.width || '100%')}"></div>`).join('') + `</div>`;
}
export function ProgressBar(value, opts = {}) {
  const max = opts.max || 100;
  const pct = Math.max(0, Math.min(100, (Number(value) / max) * 100));
  return `<div data-bm-progress style="width:100%">${opts.label ? `<div style="display:flex;justify-content:space-between;font-size:12px;opacity:.6;margin-bottom:4px"><span>${esc(opts.label)}</span><span>${Math.round(pct)}%</span></div>` : ''}<div style="height:8px;border-radius:9999px;background:rgba(128,128,128,.2);overflow:hidden"><div style="height:100%;width:${pct}%;background:${esc(opts.color || 'var(--bm-accent,#2563eb)')};border-radius:9999px;transition:width .3s"></div></div></div>`;
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 2 - auth · governance · files · workflow · realtime · ops
//  All over endpoints the framework already exposes (see route map in
//  auth.go/metering.go/webhooks.go/locks.go/permissions.go/oauth_tokens.go).
// ═══════════════════════════════════════════════════════════════════

// small skinned labeled input
function skinField(name, label, { type = 'text', value = '', required = false } = {}) {
  return skin.field({ label, required, inner: skin.input({ name, type, value, required, control: type }) });
}
function formShell(fields, submitLabel, extra = '') {
  return `<form data-bm-form class="space-y-4">${skin.error('')}${fields}${extra}<div>${skin.button({ label: submitLabel })}</div></form>`;
}
const relTime = (v) => {
  const d = new Date(String(v)); if (isNaN(d.getTime())) return esc(v);
  const s = (Date.now() - d.getTime()) / 1000;
  if (s < 60) return 'just now'; if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago'; if (s < 604800) return Math.floor(s / 86400) + 'd ago';
  return d.toLocaleDateString();
};

// ─── Auth ─────────────────────────────────────────────────────────────
// Login(target, { onSuccess?, redirect? }) → { destroy }
export function Login(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = formShell(skinField('identifier', 'Email', { type: 'email', required: true }) + skinField('password', 'Password', { type: 'password', required: true }), 'Sign in');
  const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); errEl.hidden = true;
    const fd = new FormData(form);
    try {
      const user = await bm.auth.signIn(fd.get('identifier'), fd.get('password'));
      if (opts.onSuccess) opts.onSuccess(user); else if (opts.redirect !== false) location.href = opts.redirect || '/';
    } catch (ex) { errEl.textContent = ex?.message || 'Sign-in failed'; errEl.hidden = false; }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}
// Signup(target, { fields?, onSuccess?, redirect? }) - fields: [{name,label,type,required}]
export function Signup(target, opts = {}) {
  const el = resolveEl(target);
  const fields = opts.fields || [{ name: 'email', label: 'Email', type: 'email', required: true }, { name: 'password', label: 'Password', type: 'password', required: true }];
  el.innerHTML = formShell(fields.map((f) => skinField(f.name, f.label || humanize(f.name), { type: f.type || 'text', required: !!f.required })).join(''), 'Create account');
  const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); errEl.hidden = true;
    const fd = new FormData(form); const body = {}; for (const f of fields) body[f.name] = fd.get(f.name);
    try {
      const user = await bm.auth.signUp(body);
      if (opts.onSuccess) opts.onSuccess(user); else if (opts.redirect !== false) location.href = opts.redirect || '/';
    } catch (ex) { errEl.textContent = ex?.message || 'Sign-up failed'; errEl.hidden = false; }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}
// Forgot(target) - POST /forgot-password { email }
export function Forgot(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = formShell(skinField('email', 'Email', { type: 'email', required: true }), 'Send reset link') + `<div data-bm-ok class="text-sm text-green-600 mt-2" hidden>Check your inbox for a reset link.</div>`;
  const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]'), ok = el.querySelector('[data-bm-ok]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); errEl.hidden = true; ok.hidden = true;
    try { await bm.api.post('/forgot-password', { email: new FormData(form).get('email') }); ok.hidden = false; form.reset(); }
    catch (ex) { errEl.textContent = ex?.message || 'Request failed'; errEl.hidden = false; }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}
// Reset(target, { token? }) - POST /reset-password { token, password }
export function Reset(target, opts = {}) {
  const el = resolveEl(target);
  const token = opts.token || new URLSearchParams(location.search).get('token') || '';
  el.innerHTML = formShell(skinField('password', 'New password', { type: 'password', required: true }), 'Reset password') + `<div data-bm-ok class="text-sm text-green-600 mt-2" hidden>Password updated. <a href="/login.html" class="underline">Sign in</a></div>`;
  const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]'), ok = el.querySelector('[data-bm-ok]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); errEl.hidden = true;
    try { await bm.api.post('/reset-password', { token, password: new FormData(form).get('password') }); ok.hidden = false; form.querySelector('button').disabled = true; }
    catch (ex) { errEl.textContent = ex?.message || 'Reset failed'; errEl.hidden = false; }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}
// ProfileForm(target, { onSaved? }) - GET/PATCH /api/_auth/profile
const PROFILE_PROTECTED = new Set(['id', 'role', 'roles', 'permissions', 'verified', 'deactivated_at', 'password_hash', 'created_at', 'updated_at', 'last_login_at', 'group_id', 'user_id', 'mfa_enabled']);
export async function ProfileForm(target, opts = {}) {
  const el = resolveEl(target);
  const me = await bm.api.get('/api/_auth/profile');
  const keys = Object.keys(me).filter((k) => !PROFILE_PROTECTED.has(k) && typeof me[k] !== 'object');
  // avatar/photo/logo → upload picker (not a URL box); file/attachment → file upload.
  const imgKey = (k) => /(^|_)(avatar|photo|image|logo|picture|banner)(_url)?$/.test(k);
  const fileKey = (k) => /(^|_)(file|attachment|document)(_url)?$/.test(k);
  const fieldFor = (k) => (imgKey(k) || fileKey(k))
    ? skin.field({ label: humanize(k), required: false, inner: uploadFieldHTML({ name: k }, me[k] ?? '', imgKey(k)) })
    : skinField(k, humanize(k), { type: k === 'email' ? 'email' : 'text', value: me[k] ?? '' });
  el.innerHTML = formShell(keys.map(fieldFor).join(''), 'Save profile') + `<div data-bm-ok class="text-sm text-green-600 mt-2" hidden>Saved ✓</div>`;
  const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]'), ok = el.querySelector('[data-bm-ok]');
  wireUploadFields(form); // image/file profile fields → upload pickers
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); errEl.hidden = true; ok.hidden = true;
    const fd = new FormData(form); const body = {}; for (const k of keys) body[k] = fd.get(k);
    try { const saved = await bm.api.patch('/api/_auth/profile', body); ok.hidden = false; if (opts.onSaved) opts.onSaved(saved); }
    catch (ex) { errEl.textContent = ex?.message || 'Save failed'; errEl.hidden = false; }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}
// MfaSetup(target) - bm.mfa.enroll/verify/disable
export async function MfaSetup(target, opts = {}) {
  const el = resolveEl(target);
  const render = async () => {
    const me = await bm.auth.me();
    if (me && me.mfa_enabled) {
      el.innerHTML = `<div data-bm-mfa class="space-y-3"><div class="text-sm">Two-factor auth is <b class="text-green-600">enabled</b>.</div><form data-bm-form class="space-y-3">${skin.error('')}${skinField('password', 'Confirm password to disable', { type: 'password', required: true })}<button type="submit" class="px-3 py-1.5 rounded border border-red-300 text-red-600 text-sm">Disable 2FA</button></form></div>`;
      const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
      form.addEventListener('submit', async (e) => { e.preventDefault(); try { await bm.mfa.disable(new FormData(form).get('password')); bm.auth.refreshMe && bm.auth.refreshMe(); render(); } catch (ex) { errEl.textContent = ex?.message; errEl.hidden = false; } });
      return;
    }
    const res = await bm.mfa.enroll(); // { secret, otpauth_url?, qr? }
    el.innerHTML = `<div data-bm-mfa class="space-y-3">
      <div class="text-sm">Add this secret to your authenticator app:</div>
      <code class="block p-2 rounded bg-zinc-100 dark:bg-zinc-800 text-sm break-all">${esc(res.secret || res.otpauth_url || '')}</code>
      <form data-bm-form class="space-y-3">${skin.error('')}${skinField('code', 'Enter the 6-digit code', { required: true })}${skin.button({ label: 'Verify & enable' })}</form></div>`;
    const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
    form.addEventListener('submit', async (e) => { e.preventDefault(); errEl.hidden = true; try { await bm.mfa.verify(new FormData(form).get('code')); bm.auth.refreshMe && await bm.auth.refreshMe(); Toast('2FA enabled ✓', { type: 'success' }); render(); } catch (ex) { errEl.textContent = ex?.message || 'Invalid code'; errEl.hidden = false; } });
  };
  await render();
  return { destroy: () => { el.innerHTML = ''; } };
}
// OAuthConnect(target, { providers? }) - GET/DELETE /api/_auth/oauth-tokens
export async function OAuthConnect(target, opts = {}) {
  const el = resolveEl(target);
  const providers = opts.providers || ['google', 'github', 'microsoft'];
  const render = async () => {
    let connected = [];
    try { const r = await bm.api.get('/api/_auth/oauth-tokens'); connected = (Array.isArray(r) ? r : r.tokens || []).map((t) => t.provider || t); } catch (_) {}
    el.innerHTML = `<div data-bm-oauth class="space-y-2">` + providers.map((p) => {
      const on = connected.includes(p);
      return `<div class="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 px-4 py-3"><span class="font-medium">${esc(humanize(p))}</span>${on ? `<button data-disc="${esc(p)}" class="text-sm text-red-600">Disconnect</button>` : `<a href="/api/_auth/oauth/${esc(p)}" class="text-sm bm-accent-text">Connect</a>`}</div>`;
    }).join('') + `</div>`;
    el.querySelectorAll('[data-disc]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.delete('/api/_auth/oauth-tokens/' + b.getAttribute('data-disc')); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// SessionManager(target) - GET/DELETE /api/_auth/sessions
export async function SessionManager(target, opts = {}) {
  const el = resolveEl(target);
  const render = async () => {
    const r = await bm.api.get('/api/_auth/sessions'); const rows = Array.isArray(r) ? r : (r.sessions || []);
    if (!rows.length) { el.innerHTML = skin.emptyState('No active sessions.'); return; }
    el.innerHTML = `<div data-bm-sessions class="space-y-2">` + rows.map((s) => `<div class="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 px-4 py-3 text-sm"><div><div class="font-medium">${esc(s.user_agent || 'Unknown device')}</div><div class="text-zinc-500">${esc(s.ip || '')} · started ${relTime(s.created_at)}</div></div><button data-revoke="${esc(s.id)}" class="text-red-600">Revoke</button></div>`).join('') + `</div>`;
    el.querySelectorAll('[data-revoke]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.delete('/api/_auth/sessions/' + b.getAttribute('data-revoke')); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// ApiTokenManager(target) - GET/POST/DELETE /api/_auth/api-tokens
export async function ApiTokenManager(target, opts = {}) {
  const el = resolveEl(target);
  const list = document.createElement('div'); list.className = 'space-y-2 mt-4';
  const renderList = async () => {
    const r = await bm.api.get('/api/_auth/api-tokens'); const rows = Array.isArray(r) ? r : (r.tokens || []);
    list.innerHTML = rows.length ? rows.map((t) => `<div class="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 px-4 py-2.5 text-sm"><div><span class="font-medium">${esc(t.name)}</span> <span class="text-zinc-500">${esc(t.scopes || '')}</span></div><button data-del="${esc(t.id)}" class="text-red-600">Revoke</button></div>`).join('') : skin.emptyState('No API tokens.');
    list.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.delete('/api/_auth/api-tokens/' + b.getAttribute('data-del')); renderList(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  el.innerHTML = formShell(skinField('name', 'Token name', { required: true }) + skinField('scopes', 'Scopes', { value: '*' }), 'Create token');
  el.appendChild(list);
  const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); errEl.hidden = true; const fd = new FormData(form);
    try {
      const r = await bm.api.post('/api/_auth/api-tokens', { name: fd.get('name'), scopes: fd.get('scopes') || '*' });
      form.reset();
      Modal({ title: 'Copy your token now - it won\'t be shown again', size: 'md', content: `<code style="display:block;padding:12px;background:rgba(128,128,128,.12);border-radius:8px;word-break:break-all;font-size:13px">${esc(r.token)}</code>` });
      renderList();
    } catch (ex) { errEl.textContent = ex?.message || 'Failed'; errEl.hidden = false; }
  });
  await renderList();
  return { refresh: renderList, destroy: () => { el.innerHTML = ''; } };
}
// ActAs(target) - admin impersonation. POST /api/_auth/impersonate {user_id,password}, /end-impersonation
export async function ActAs(target, opts = {}) {
  const el = resolveEl(target);
  if (!(await hasRole('admin'))) { el.innerHTML = skin.emptyState('Admin only.'); return { destroy: () => { el.innerHTML = ''; } }; }
  let users = [];
  try { users = await bm.users.list({ limit: 200 }); } catch (_) {}
  el.innerHTML = `<form data-bm-form class="space-y-3">${skin.error('')}
    <label class="block space-y-1"><span class="text-sm font-medium">User</span>
      <select name="user_id" class="${inputCls}">${users.map((u) => `<option value="${esc(u.id)}">${esc(u.email || u.username || u.id)}</option>`).join('')}</select></label>
    ${skinField('password', 'Confirm your admin password', { type: 'password', required: true })}
    ${skin.button({ label: 'Act as user' })}</form>
    <button data-end class="mt-3 text-sm text-zinc-500 underline">End impersonation</button>`;
  const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); errEl.hidden = true; const fd = new FormData(form);
    try { await bm.api.post('/api/_auth/impersonate', { user_id: Number(fd.get('user_id')), password: fd.get('password') }); location.reload(); }
    catch (ex) { errEl.textContent = ex?.message || 'Failed'; errEl.hidden = false; }
  });
  el.querySelector('[data-end]').addEventListener('click', async () => { try { await bm.api.post('/api/_auth/end-impersonation'); location.reload(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── Governance ───────────────────────────────────────────────────────
// VersionHistory(target, { table, id, onRevert? }) - bm.table.versions/revertTo
export async function VersionHistory(target, opts) {
  const el = resolveEl(target);
  const render = async () => {
    let versions = [];
    try { const r = await bm.table(opts.table).versions(opts.id); versions = Array.isArray(r) ? r : (r.versions || []); } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'No version history.'); return; }
    if (!versions.length) { el.innerHTML = skin.emptyState('No versions yet.'); return; }
    el.innerHTML = `<ol data-bm-versions class="space-y-2">` + versions.map((v) => `<li class="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 px-4 py-2.5 text-sm"><div><span class="font-medium">v${esc(v.version ?? v.id)}</span> <span class="text-zinc-500">${relTime(v.created_at || v.changed_at)}</span></div><button data-rev="${esc(v.version ?? v.id)}" class="bm-accent-text">Revert</button></li>`).join('') + `</ol>`;
    el.querySelectorAll('[data-rev]').forEach((b) => b.addEventListener('click', async () => { try { await bm.table(opts.table).revertTo(opts.id, b.getAttribute('data-rev')); Toast('Reverted ✓', { type: 'success' }); if (opts.onRevert) opts.onRevert(); render(); } catch (ex) { Toast(ex?.message || 'Revert failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// AuditLog(target, { table?, row_id?, user_id?, action?, limit? }) - bm.audit.list
export async function AuditLog(target, opts = {}) {
  const el = resolveEl(target);
  const render = async () => {
    let rows = [];
    try { rows = await bm.audit.list({ table: opts.table, row_id: opts.row_id, user_id: opts.user_id, action: opts.action, limit: opts.limit || 50 }); } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'No audit access.'); return; }
    if (!rows.length) { el.innerHTML = skin.emptyState('No audit entries.'); return; }
    const head = skin.tr({ cells: ['When', 'Action', 'Table', 'Row', 'User'].map((h) => skin.th(h)).join(''), clickable: false });
    const body = rows.map((r) => skin.tr({ cells: [relTime(r.created_at || r.timestamp), Badge(r.action || '', { variant: r.action === 'delete' ? 'error' : r.action === 'create' ? 'success' : 'neutral' }), esc(r.table_name || r.table || ''), esc(r.row_id ?? ''), esc(r.user_email || r.user_id || '')].map((c) => skin.cell(c)).join(''), clickable: false })).join('');
    el.innerHTML = skin.table({ head, body });
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// RecordLock(target, { table, id }) - GET/POST/DELETE /api/{t}/{id}/lock
export async function RecordLock(target, opts) {
  const el = resolveEl(target);
  const base = `/api/${opts.table}/${opts.id}/lock`;
  const render = async () => {
    let lock = null;
    try { lock = await bm.api.get(base); } catch (_) {}
    const held = lock && (lock.locked || lock.user_id || lock.locked_by);
    el.innerHTML = `<div data-bm-lock class="flex items-center gap-3 text-sm">${held ? `${Badge('Locked', { variant: 'warning' })} <span class="text-zinc-500">by ${esc(lock.user_email || lock.locked_by || lock.user_id || 'someone')}</span> <button data-unlock class="bm-accent-text">Release</button>` : `${Badge('Unlocked', { variant: 'success' })} <button data-lock class="bm-accent-text">Lock</button>`}</div>`;
    el.querySelector('[data-lock]')?.addEventListener('click', async () => { try { await bm.api.post(base); render(); } catch (ex) { Toast(ex?.message || 'Lock failed', { type: 'error' }); } });
    el.querySelector('[data-unlock]')?.addEventListener('click', async () => { try { await bm.api.delete(base); render(); } catch (ex) { Toast(ex?.message || 'Release failed', { type: 'error' }); } });
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// ShareDialog(target, { table, id }) - bm.permissions list/share/revoke
export async function ShareDialog(target, opts) {
  const el = resolveEl(target);
  const render = async () => {
    let rows = [];
    try { const r = await bm.permissions.list(opts.table, opts.id); rows = Array.isArray(r) ? r : (r.permissions || []); } catch (_) {}
    el.innerHTML = `<div data-bm-share class="space-y-3"><form data-bm-form class="flex gap-2 items-end">${skin.error('')}
      <label class="flex-1 space-y-1"><span class="text-sm font-medium">Email</span><input name="email" type="email" required class="${inputCls}"></label>
      <label class="space-y-1"><span class="text-sm font-medium">Access</span><select name="permission" class="${inputCls}"><option value="view">View</option><option value="edit">Edit</option><option value="delete">Delete</option><option value="admin">Admin</option></select></label>
      ${skin.button({ label: 'Share' })}</form>
      <div data-bm-shares class="space-y-1">${rows.map((p) => `<div class="flex items-center justify-between text-sm px-1"><span>${esc(p.email)} · ${esc(p.permission)}</span><button data-revoke="${esc(p.email)}" class="text-red-600">Revoke</button></div>`).join('') || '<p class="text-sm text-zinc-500">Not shared with anyone.</p>'}</div></div>`;
    const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
    form.addEventListener('submit', async (e) => { e.preventDefault(); errEl.hidden = true; const fd = new FormData(form); try { await bm.permissions.share(opts.table, opts.id, fd.get('email'), fd.get('permission')); render(); } catch (ex) { errEl.textContent = ex?.message || 'Share failed'; errEl.hidden = false; } });
    el.querySelectorAll('[data-revoke]').forEach((b) => b.addEventListener('click', async () => { try { await bm.permissions.revoke(opts.table, opts.id, b.getAttribute('data-revoke')); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// DownloadMyData(target, { label? }) - gather every readable table → JSON download
export async function DownloadMyData(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<button data-bm-dl class="px-4 py-2 rounded-md bm-accent-bg font-medium">${esc(opts.label || 'Download my data')}</button>`;
  el.querySelector('button').addEventListener('click', async () => {
    const btn = el.querySelector('button'); const txt = btn.textContent; btn.textContent = 'Gathering…'; btn.disabled = true;
    try {
      const s = await schema(); const out = {};
      for (const t of Object.keys(s)) { try { out[t] = await listRows(t, { limit: 1000 }); } catch (_) { out[t] = []; } }
      const blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'my-data.json'; a.click(); URL.revokeObjectURL(a.href);
    } catch (ex) { Toast(ex?.message || 'Export failed', { type: 'error' }); }
    btn.textContent = txt; btn.disabled = false;
  });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── Files ──────────────────────────────────────────────────────────
// SignedImage(target, { path, ttl?, alt?, class? }) - bm.signedUrl → <img>
export async function SignedImage(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = Spinner();
  try { const url = await bm.signedUrl(opts.path, opts.ttl || 300); el.innerHTML = `<img data-bm-signed src="${esc(url)}" alt="${esc(opts.alt || '')}" class="${esc(opts.class || 'rounded-lg max-w-full')}">`; }
  catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'Could not sign URL'); }
  return { destroy: () => { el.innerHTML = ''; } };
}
// PdfButton(target, { page, label?, query? }) - server-renders /pdf/{page}.
// Opens the PDF when the host has Chrome; otherwise shows a clear note
// instead of navigating to a raw error page (server PDF needs a Chrome/
// Chromium binary on the host - an operator step).
export function PdfButton(target, opts) {
  const el = resolveEl(target);
  const href = `/pdf/${encodeURIComponent(opts.page)}` + (opts.query ? '?' + new URLSearchParams(opts.query) : '');
  el.innerHTML = `<button data-bm-pdf class="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 text-sm font-medium">${lucide('file-text', 16)} ${esc(opts.label || 'Download PDF')}</button><span data-bm-pdf-note class="text-sm text-zinc-500 ml-2"></span>`;
  const btn = el.querySelector('button'), note = el.querySelector('[data-bm-pdf-note]');
  btn.addEventListener('click', async () => {
    note.textContent = 'Generating…'; btn.disabled = true;
    try {
      const res = await fetch(href, { credentials: 'same-origin' });
      const ct = res.headers.get('content-type') || '';
      if (res.ok && ct.includes('pdf')) {
        const url = URL.createObjectURL(await res.blob());
        window.open(url, '_blank'); setTimeout(() => URL.revokeObjectURL(url), 60000);
        note.textContent = '';
      } else if (res.status === 501) {
        note.textContent = 'Server-side PDF needs Chrome installed on the host.';
      } else {
        note.textContent = `PDF unavailable (${res.status}).`;
      }
    } catch (_) { note.textContent = 'PDF request failed.'; }
    btn.disabled = false;
  });
  return { destroy: () => { el.innerHTML = ''; } };
}
// MediaGallery(target, { table, urlField?, captionField?, signed? }) - grid of images from an app table
export async function MediaGallery(target, opts) {
  const el = resolveEl(target);
  const urlField = opts.urlField || 'url';
  const render = async () => {
    const rows = await listRows(opts.table, { limit: opts.limit || 60, where: opts.where });
    if (!rows.length) { el.innerHTML = skin.emptyState('No media yet.'); return; }
    el.innerHTML = `<div data-bm-gallery class="grid gap-3" style="grid-template-columns:repeat(auto-fill,minmax(140px,1fr))">` + rows.map((r) => {
      const src = r[urlField] || '';
      return `<figure class="rounded-lg overflow-hidden border border-zinc-200 dark:border-zinc-800"><img loading="lazy" src="${esc(src)}" alt="${esc(opts.captionField ? r[opts.captionField] : '')}" style="width:100%;height:120px;object-fit:cover">${opts.captionField ? `<figcaption class="text-xs p-1.5 truncate">${esc(r[opts.captionField] || '')}</figcaption>` : ''}</figure>`;
    }).join('') + `</div>`;
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// ─── Workflow / Jobs ─────────────────────────────────────────────────
// FlowButton(target, { flow, params?, body?, label?, confirm?, onResult? })
export function FlowButton(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<button data-bm-flowbtn class="px-4 py-2 rounded-md bm-accent-bg font-medium disabled:opacity-50">${esc(opts.label || humanize(opts.flow))}</button>`;
  const btn = el.querySelector('button');
  btn.addEventListener('click', async () => {
    if (opts.confirm && !confirm(opts.confirm)) return;
    const txt = btn.textContent; btn.disabled = true; btn.textContent = 'Working…';
    try { let res = await bm.flows[opts.flow](opts.params || {}, opts.body); if (res && typeof res.wait === 'function') { btn.textContent = 'Processing…'; res = await res.wait(); } if (opts.onResult) opts.onResult(res); else Toast('Done ✓', { type: 'success' }); }
    catch (ex) { Toast(ex?.message || 'Flow failed', { type: 'error' }); }
    btn.disabled = false; btn.textContent = txt;
  });
  return { destroy: () => { el.innerHTML = ''; } };
}
// WorkflowBadge(target, { table, id }) - current state → Badge, live
export async function WorkflowBadge(target, opts) {
  const el = resolveEl(target);
  const variantFor = (s) => /(done|complete|approv|active|paid|ship)/i.test(s) ? 'success' : /(reject|fail|cancel|churn|error)/i.test(s) ? 'error' : /(pending|wait|review|draft)/i.test(s) ? 'warning' : 'neutral';
  const render = async () => { try { const st = await bm.workflow(opts.table, opts.id).current(); el.innerHTML = st ? Badge(humanize(String(st)), { variant: variantFor(String(st)) }) : ''; } catch (_) { el.innerHTML = ''; } };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}
// JobStatus(target, { jobId, onDone? }) - poll bm.jobs.status
export async function JobStatus(target, opts) {
  const el = resolveEl(target);
  let stopped = false, errors = 0;
  const variant = { completed: 'success', failed: 'error', running: 'info', pending: 'warning', queued: 'warning' };
  const tick = async () => {
    if (stopped) return;
    try {
      const s = await bm.jobs.status(opts.jobId);
      errors = 0;
      const done = s.status === 'completed' || s.status === 'failed';
      el.innerHTML = `<div data-bm-jobstatus class="flex items-center gap-2 text-sm">${done ? '' : Spinner({ size: 14 })} ${Badge(s.status, { variant: variant[s.status] || 'neutral' })}${s.error ? ` <span class="text-red-600">${esc(s.error)}</span>` : ''}</div>`;
      if (done) { if (opts.onDone) opts.onDone(s); return; }
    } catch (ex) {
      if (++errors >= 3) { el.innerHTML = skin.emptyState('Job not found.'); return; } // stop polling a dead/unknown job
    }
    setTimeout(tick, opts.intervalMs || 1500);
  };
  await tick();
  return { destroy: () => { stopped = true; el.innerHTML = ''; } };
}
// JobsDashboard(target) - GET /api/_jobs
export async function JobsDashboard(target, opts = {}) {
  const el = resolveEl(target);
  const variant = { completed: 'success', failed: 'error', running: 'info', pending: 'warning', queued: 'warning' };
  const render = async () => {
    let rows = [];
    try { const r = await bm.api.get('/api/_jobs'); rows = Array.isArray(r) ? r : (r.jobs || []); } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'No jobs access.'); return; }
    if (!rows.length) { el.innerHTML = skin.emptyState('No jobs.'); return; }
    const head = skin.tr({ cells: ['Job', 'Status', 'When', ''].map((h) => skin.th(h)).join(''), clickable: false });
    const body = rows.map((j) => skin.tr({ cells: [esc(j.flow_name || j.name || j.id), Badge(j.status || '', { variant: variant[j.status] || 'neutral' }), relTime(j.created_at || j.started_at), `${j.status === 'failed' ? `<button data-retry="${esc(j.id)}" class="bm-accent-text">Retry</button>` : ''}`].map((c) => skin.cell(c)).join(''), clickable: false })).join('');
    el.innerHTML = skin.table({ head, body });
    el.querySelectorAll('[data-retry]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.post('/api/_jobs/' + b.getAttribute('data-retry') + '/retry'); render(); } catch (ex) { Toast(ex?.message || 'Retry failed', { type: 'error' }); } }));
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped('_benmore_jobs', () => render()) : bm.live('_benmore_jobs', () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// ─── Realtime / Notifications ────────────────────────────────────────
// NotificationBell(target) - bm.notifications inbox + live
export async function NotificationBell(target, opts = {}) {
  const el = resolveEl(target);
  // Default is an INLINED Lucide bell SVG (not a <i data-lucide> placeholder):
  // inlining avoids Lucide createIcons() swapping the node after render - the
  // cause of the "have to click the icon twice" bug - and pointer-events:none
  // makes the BUTTON the click target, never the icon. opts.icon overrides
  // with any emoji or raw SVG/HTML.
  const BELL = lucide('bell', 20);
  el.innerHTML = `<div data-bm-bell style="position:relative;display:inline-block"><button data-bell style="position:relative;background:none;border:none;cursor:pointer;font-size:20px;line-height:1;color:inherit;display:inline-flex;align-items:center">${opts.icon || BELL}<span data-count style="position:absolute;top:-4px;right:-6px;background:#dc2626;color:#fff;font-size:10px;font-weight:700;border-radius:9999px;padding:1px 5px;pointer-events:none" hidden>0</span></button><div data-panel hidden style="position:absolute;right:0;top:100%;margin-top:8px;width:320px;max-height:400px;overflow:auto;background:var(--card,#fff);border:1px solid rgba(128,128,128,.2);border-radius:10px;box-shadow:0 12px 32px rgba(0,0,0,.18);z-index:60"></div></div>`;
  const bell = el.querySelector('[data-bell]'), countEl = el.querySelector('[data-count]'), panel = el.querySelector('[data-panel]');
  const render = async () => {
    let items = []; try { items = await bm.notifications.list({ limit: 20 }); } catch (_) {}
    const unread = items.filter((n) => !n.read_at && !n.read).length;
    countEl.hidden = unread === 0; countEl.textContent = String(unread);
    panel.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid rgba(128,128,128,.15)"><b style="font-size:13px">Notifications</b><button data-readall style="font-size:12px;color:var(--bm-accent,#2563eb);background:none;border:none;cursor:pointer">Mark all read</button></div>` +
      (items.length ? items.map((n) => `<div data-id="${esc(n.id)}" style="padding:10px 14px;border-bottom:1px solid rgba(128,128,128,.1);font-size:13px;${(n.read_at || n.read) ? 'opacity:.55' : 'cursor:pointer'}"><div style="font-weight:${(n.read_at || n.read) ? 400 : 600}">${esc(n.title || n.message || n.body || '')}</div><div style="font-size:11px;opacity:.6">${relTime(n.created_at)}</div></div>`).join('') : `<p style="padding:16px;font-size:13px;opacity:.6">You're all caught up.</p>`);
    panel.querySelector('[data-readall]')?.addEventListener('click', async () => { try { await bm.notifications.markAllRead(); render(); } catch (_) {} });
    panel.querySelectorAll('[data-id]').forEach((d) => d.addEventListener('click', async () => { try { await bm.notifications.markRead(d.getAttribute('data-id')); render(); } catch (_) {} }));
  };
  bell.addEventListener('click', () => { panel.hidden = !panel.hidden; if (!panel.hidden) render(); });
  await render();
  const stop = bm.notifications.onNew(() => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}
// Presence(target, { slug, roster? }) - who's live in <slug>.
// Default: only people currently online (green dot each). roster:true lists
// EVERYONE (bm.users.list) with green = online, hollow grey = offline.
const greenDot = `<span style="position:absolute;bottom:-1px;right:-1px;width:10px;height:10px;border-radius:50%;background:#22c55e;border:2px solid var(--card,#fff)"></span>`;
const greyDot = `<span style="position:absolute;bottom:-1px;right:-1px;width:10px;height:10px;border-radius:50%;background:transparent;border:2px solid #a1a1aa;box-shadow:0 0 0 2px var(--card,#fff)"></span>`;
export async function Presence(target, opts) {
  const el = resolveEl(target);
  ensureStyles();
  const p = bm.presence(opts.slug);
  const nameOf = (m) => m.user_email || m.name || m.email || m.username || ('User ' + (m.user_id ?? m.id ?? ''));
  const render = async () => {
    let members = []; try { members = await p.members(); } catch (_) {}
    const onlineIds = new Set(members.map((m) => String(m.user_id ?? m.id)));

    if (opts.roster) {
      let users = []; try { users = await bm.users.list({ limit: 50 }); } catch (_) {}
      if (!users.length) users = members.map((m) => ({ id: m.user_id, email: m.user_email }));
      const onlineCount = users.filter((u) => onlineIds.has(String(u.id))).length;
      el.innerHTML = `<div data-bm-presence style="display:flex;flex-direction:column;gap:10px">
        <span style="font-size:13px;opacity:.7">${onlineCount} of ${users.length} online</span>
        <div style="display:flex;flex-wrap:wrap;gap:14px">` + users.map((u) => {
        const on = onlineIds.has(String(u.id));
        const name = nameOf(u);
        return `<span style="display:inline-flex;align-items:center;gap:7px;opacity:${on ? 1 : .55}"><span style="position:relative;display:inline-block">${Avatar({ name, src: u.avatar_url || undefined, size: 30 })}${on ? greenDot : greyDot}</span><span style="font-size:12px">${esc(name)}${on ? '' : ' <span style="opacity:.6">· offline</span>'}</span></span>`;
      }).join('') + `</div></div>`;
      return;
    }

    const avatars = members.slice(0, 8).map((m, i) =>
      `<span style="position:relative;display:inline-block;margin-left:${i ? -8 : 0}px">${Avatar({ name: nameOf(m), src: m.avatar_url || undefined, size: 30 })}${greenDot}</span>`
    ).join('');
    const label = members.length
      ? `<span style="font-size:13px;opacity:.7">${members.length} ${members.length === 1 ? 'person' : 'people'} online</span>`
      : `<span style="display:inline-flex;align-items:center;gap:7px;font-size:13px;opacity:.6"><span style="width:9px;height:9px;border-radius:50%;background:#a1a1aa"></span>No one here right now</span>`;
    el.innerHTML = `<div data-bm-presence style="display:flex;align-items:center;gap:12px">${members.length ? `<div style="display:flex">${avatars}</div>` : ''}${members.length > 8 ? `<span style="font-size:13px;opacity:.6">+${members.length - 8}</span>` : ''}${label}</div>`;
  };
  await render();
  const stop = p.onChange(() => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} try { p.leave(); } catch (_) {} el.innerHTML = ''; } };
}
// Chat(target, { table, bodyField?, authorField? }) - table-backed live chat
export async function Chat(target, opts) {
  const el = resolveEl(target);
  const bodyField = opts.bodyField || 'body';
  el.innerHTML = `<div data-bm-chat style="display:flex;flex-direction:column;height:${opts.height || '380px'};border:1px solid rgba(128,128,128,.2);border-radius:10px;overflow:hidden"><div data-msgs style="flex:1;overflow:auto;padding:12px;display:flex;flex-direction:column;gap:8px"></div><form data-send style="display:flex;gap:8px;padding:10px;border-top:1px solid rgba(128,128,128,.15)"><input name="body" placeholder="Message…" autocomplete="off" class="${inputCls}" style="flex:1"><button class="px-4 py-2 rounded-md bm-accent-bg">Send</button></form></div>`;
  const msgs = el.querySelector('[data-msgs]'), form = el.querySelector('[data-send]');
  let me = null; try { me = await bm.auth.me(); } catch (_) {}
  const render = async () => {
    const rows = await listRows(opts.table, { limit: opts.limit || 100, sort: 'created_at', order: 'asc', where: opts.where });
    msgs.innerHTML = rows.map((r) => { const mine = me && (r.user_id == me.id); return `<div style="align-self:${mine ? 'flex-end' : 'flex-start'};max-width:75%"><div style="background:${mine ? 'var(--bm-accent,#2563eb)' : 'rgba(128,128,128,.15)'};color:${mine ? '#fff' : 'inherit'};padding:8px 12px;border-radius:12px;font-size:14px">${esc(r[bodyField] || '')}</div><div style="font-size:10px;opacity:.5;margin-top:2px;text-align:${mine ? 'right' : 'left'}">${relTime(r.created_at)}</div></div>`; }).join('');
    msgs.scrollTop = msgs.scrollHeight;
  };
  form.addEventListener('submit', async (e) => { e.preventDefault(); const inp = form.querySelector('input'); const v = inp.value.trim(); if (!v) return; inp.value = ''; try { await bm.table(opts.table).create({ [bodyField]: v, ...(opts.extra || {}) }); } catch (ex) { Toast(ex?.message || 'Send failed', { type: 'error' }); } });
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}
// CommentThread(target, { table, where, bodyField? }) - comments scoped to a parent
export async function CommentThread(target, opts) {
  const el = resolveEl(target);
  const bodyField = opts.bodyField || 'body';
  el.innerHTML = `<div data-bm-comments class="space-y-3"><div data-list class="space-y-3"></div><form data-add class="flex gap-2"><input name="body" placeholder="Add a comment…" class="${inputCls}" style="flex:1"><button class="px-3 py-2 rounded-md bm-accent-bg text-sm">Post</button></form></div>`;
  const list = el.querySelector('[data-list]'), form = el.querySelector('[data-add]');
  const render = async () => {
    const rows = await listRows(opts.table, { limit: opts.limit || 100, sort: 'created_at', order: 'asc', where: opts.where });
    const authors = await resolveAuthors(rows.map((r) => r.user_id));
    list.innerHTML = rows.length ? rows.map((r) => {
      const a = authors[r.user_id] || {};
      const name = a.name || r.user_email || ('User ' + (r.user_id || '?'));
      return `<div style="display:flex;gap:8px"><span>${Avatar({ name, src: a.src, size: 28 })}</span><div style="min-width:0"><div style="font-size:13px;font-weight:600">${esc(name)}</div><div style="font-size:13px">${esc(r[bodyField] || '')}</div><div style="font-size:11px;opacity:.5">${relTime(r.created_at)}</div></div></div>`;
    }).join('') : '<p class="text-sm text-zinc-500">No comments yet.</p>';
  };
  form.addEventListener('submit', async (e) => { e.preventDefault(); const inp = form.querySelector('input'); const v = inp.value.trim(); if (!v) return; inp.value = ''; try { await bm.table(opts.table).create({ [bodyField]: v, ...(opts.where || {}) }); } catch (ex) { Toast(ex?.message || 'Post failed', { type: 'error' }); } });
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}
// ActivityFeed(target, { table, titleField?, limit? }) - reverse-chron live feed
export async function ActivityFeed(target, opts) {
  const el = resolveEl(target);
  const render = async () => {
    const rows = await listRows(opts.table, { limit: opts.limit || 30, sort: 'created_at', order: 'desc', where: opts.where });
    if (!rows.length) { el.innerHTML = skin.emptyState('Nothing yet.'); return; }
    const tf = opts.titleField || (visible(tableDesc(await schema(), opts.table)).find((f) => ['summary', 'title', 'name', 'message', 'body'].includes(f.name)) || {}).name || 'id';
    const authors = await resolveAuthors(rows.map((r) => r.user_id));
    el.innerHTML = `<ol data-bm-feed class="space-y-3">` + rows.map((r) => { const a = authors[r.user_id] || {}; const name = a.name || r.user_email || ('User ' + (r.user_id || '?')); return `<li style="display:flex;gap:10px"><span style="margin-top:2px">${Avatar({ name, src: a.src, size: 26 })}</span><div style="min-width:0"><div style="font-size:14px">${esc(r[tf] ?? r.id)}</div><div style="font-size:11px;opacity:.5">${relTime(r.created_at)}</div></div></li>`; }).join('') + `</ol>`;
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// ─── Analytics / Ops / Integrations ──────────────────────────────────
// Dashboard(target, { stats?:[StatOpts], charts?:[ChartOpts] }) - composite grid
export async function Dashboard(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<div class="space-y-6"><div data-bm-stats class="grid gap-4" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr))"></div><div data-bm-charts class="grid gap-4" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))"></div></div>`;
  const statsEl = el.querySelector('[data-bm-stats]'), chartsEl = el.querySelector('[data-bm-charts]');
  const subs = [];
  for (const s of (opts.stats || [])) { const d = document.createElement('div'); statsEl.appendChild(d); subs.push(await Stat(d, s)); }
  for (const c of (opts.charts || [])) { const d = document.createElement('div'); d.className = 'panel'; chartsEl.appendChild(d); subs.push(await Chart(d, c)); }
  return { destroy: () => { subs.forEach((x) => x && x.destroy && x.destroy()); el.innerHTML = ''; } };
}
// UsageMeter(target) - GET /api/_usage → metric tiles
export async function UsageMeter(target, opts = {}) {
  const el = resolveEl(target);
  const render = async () => {
    let data = {};
    try { data = await bm.api.get('/api/_usage'); } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'No usage data.'); return; }
    const metrics = data.metrics || data || {};
    const fmt = (k, v) => /bytes/.test(k) ? (Number(v) / 1048576).toFixed(1) + ' MB' : v;
    el.innerHTML = `<div data-bm-usage class="grid gap-4" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">` + Object.entries(metrics).map(([k, v]) => `<div class="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4"><div class="text-xs uppercase tracking-wide text-zinc-500">${esc(humanize(k))}</div><div class="text-2xl font-semibold mt-1 tabular-nums">${esc(fmt(k, v))}</div></div>`).join('') + `</div>`;
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// WebhookManager(target) - GET/POST/DELETE /api/_webhooks
export async function WebhookManager(target, opts = {}) {
  const el = resolveEl(target);
  const list = document.createElement('div'); list.className = 'space-y-2 mt-4';
  const renderList = async () => {
    let rows = []; try { const r = await bm.api.get('/api/_webhooks'); rows = Array.isArray(r) ? r : (r.webhooks || []); } catch (_) {}
    list.innerHTML = rows.length ? rows.map((w) => `<div class="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 px-4 py-2.5 text-sm"><div><div class="font-medium truncate" style="max-width:320px">${esc(w.url)}</div><div class="text-zinc-500">${esc((w.events || w.event || '').toString())}</div></div><div class="flex gap-3"><button data-test="${esc(w.id)}" class="bm-accent-text">Test</button><button data-del="${esc(w.id)}" class="text-red-600">Delete</button></div></div>`).join('') : skin.emptyState('No webhooks.');
    list.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.delete('/api/_webhooks/' + b.getAttribute('data-del')); renderList(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
    list.querySelectorAll('[data-test]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.post('/api/_webhooks/' + b.getAttribute('data-test') + '/test'); Toast('Test delivery sent', { type: 'success' }); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  el.innerHTML = formShell(skinField('url', 'Endpoint URL', { type: 'url', required: true }) + skinField('secret', 'Signing secret', { required: true }) + skinField('events', 'Events (e.g. contacts.create)', {}), 'Add webhook');
  el.appendChild(list);
  const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
  form.addEventListener('submit', async (e) => { e.preventDefault(); errEl.hidden = true; const fd = new FormData(form); try { await bm.api.post('/api/_webhooks', { url: fd.get('url'), secret: fd.get('secret'), events: fd.get('events') }); form.reset(); renderList(); } catch (ex) { errEl.textContent = ex?.message || 'Failed'; errEl.hidden = false; } });
  await renderList();
  return { refresh: renderList, destroy: () => { el.innerHTML = ''; } };
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 3a - cross-table read/query layer (POST /api/_query)
// ═══════════════════════════════════════════════════════════════════

// query(spec) - run a declarative read. spec: { table, select?, where?,
// group_by?, aggregates?, order_by?, limit? }. Returns rows[]. Scoped +
// column-validated server-side, so it can't read more than GET /api/<t>.
export async function query(spec) {
  const r = await bm.api.post('/api/_query', spec);
  return Array.isArray(r) ? r : (r.rows || []);
}

// generic key-driven table (query results aren't schema fields).
function genericTable(rows, { columns, onRowClick } = {}) {
  if (!rows.length) return skin.emptyState('No results.');
  const keys = columns || Object.keys(rows[0]);
  const head = skin.tr({ cells: keys.map((k) => skin.th(humanize(k))).join(''), clickable: false });
  const body = rows.map((row) => {
    const cells = keys.map((k) => skin.cell(typeof row[k] === 'number' ? `<span class="tabular-nums">${esc(row[k])}</span>` : esc(row[k] == null ? '-' : row[k]))).join('');
    return skin.tr({ cells, clickable: !!onRowClick }).replace('<tr ', `<tr data-bm-id="${esc(row.id ?? '')}" `);
  }).join('');
  return skin.table({ head, body });
}

// QueryView(target, { table, select?, where?, order_by?, limit?, columns?, onRowClick? })
export async function QueryView(target, opts) {
  const el = resolveEl(target);
  const render = async () => {
    try {
      const rows = await query({ table: opts.table, select: opts.select, where: opts.where, order_by: opts.order_by, limit: opts.limit });
      el.innerHTML = genericTable(rows, { columns: opts.columns, onRowClick: opts.onRowClick });
      if (opts.onRowClick) el.querySelectorAll('[data-bm-row][data-bm-id]').forEach((tr) => tr.addEventListener('click', () => opts.onRowClick(tr.getAttribute('data-bm-id'))));
    } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'Query failed'); }
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// Report(target, { table, group_by, aggregates, where?, order_by?, chart? })
// Grouped aggregate table; pass chart:{type} to also render a Chart of
// the first aggregate by the first group dimension.
export async function Report(target, opts) {
  const el = resolveEl(target);
  const groupBy = Array.isArray(opts.group_by) ? opts.group_by : [opts.group_by].filter(Boolean);
  const aggs = opts.aggregates || [{ fn: 'count', as: 'count' }];
  let chartSub = null;
  const render = async () => {
    if (chartSub) { chartSub.destroy(); chartSub = null; }
    try {
      const rows = await query({ table: opts.table, group_by: groupBy, aggregates: aggs, where: opts.where, order_by: opts.order_by, limit: opts.limit || 500 });
      el.innerHTML = `<div data-bm-report class="space-y-4">${opts.chart ? '<div data-bm-report-chart style="height:260px"></div>' : ''}<div data-bm-report-table></div></div>`;
      el.querySelector('[data-bm-report-table]').innerHTML = genericTable(rows);
      if (opts.chart && rows.length && groupBy.length) {
        const aggKey = aggs[0].as || (aggs[0].fn + (aggs[0].col ? '_' + aggs[0].col : '')) || 'count';
        chartSub = await Chart(el.querySelector('[data-bm-report-chart]'), { type: opts.chart.type || 'bar', live: false, data: { labels: rows.map((r) => String(r[groupBy[0]] ?? '-')), values: rows.map((r) => Number(r[aggKey]) || 0) }, label: humanize(aggKey) });
      }
    } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'Report failed'); }
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} if (chartSub) chartSub.destroy(); el.innerHTML = ''; } };
}

// PivotTable(target, { table, rows, cols, value?, where? }) - two-dim pivot.
// rows/cols are group-by columns; value is an aggregate (default count).
export async function PivotTable(target, opts) {
  const el = resolveEl(target);
  const value = opts.value || { fn: 'count', as: 'v' };
  value.as = value.as || 'v';
  const render = async () => {
    try {
      const data = await query({ table: opts.table, group_by: [opts.rows, opts.cols], aggregates: [value], where: opts.where, limit: 2000 });
      const rowKeys = [...new Set(data.map((d) => String(d[opts.rows] ?? '-')))];
      const colKeys = [...new Set(data.map((d) => String(d[opts.cols] ?? '-')))];
      const cell = {};
      data.forEach((d) => { cell[`${d[opts.rows]}|${d[opts.cols]}`] = d[value.as]; });
      const head = skin.tr({ cells: [skin.th(humanize(opts.rows) + ' \\ ' + humanize(opts.cols))].concat(colKeys.map((c) => skin.th(c))).join(''), clickable: false });
      const body = rowKeys.map((rk) => skin.tr({ cells: [skin.cell(`<b>${esc(rk)}</b>`)].concat(colKeys.map((ck) => skin.cell(`<span class="tabular-nums">${esc(cell[`${rk}|${ck}`] ?? 0)}</span>`))).join(''), clickable: false })).join('');
      el.innerHTML = skin.table({ head, body });
    } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'Pivot failed'); }
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// SavedViews(target, { spec?, onSelect? }) - list/save/delete query specs.
export async function SavedViews(target, opts = {}) {
  const el = resolveEl(target);
  const render = async () => {
    let views = [];
    try { const r = await bm.api.get('/api/_query/views'); views = Array.isArray(r) ? r : (r.views || []); } catch (_) {}
    el.innerHTML = `<div data-bm-savedviews class="space-y-3">
      ${opts.spec ? `<form data-save class="flex gap-2"><input name="name" placeholder="Save current view as…" class="${inputCls}" style="flex:1"><button class="px-3 py-2 rounded-md bm-accent-bg text-sm">Save</button></form>` : ''}
      <div data-list class="space-y-1">${views.length ? views.map((v) => `<div class="flex items-center justify-between text-sm px-1 py-1.5 rounded hover:bg-zinc-100 dark:hover:bg-zinc-800"><button data-load="${esc(v.id)}" class="text-left flex-1 bm-accent-text">${esc(v.name)}</button><button data-del="${esc(v.id)}" class="text-red-600 ml-3">✕</button></div>`).join('') : '<p class="text-sm text-zinc-500">No saved views.</p>'}</div></div>`;
    el.querySelector('[data-save]')?.addEventListener('submit', async (e) => { e.preventDefault(); const name = new FormData(e.target).get('name'); if (!name) return; try { await bm.api.post('/api/_query/views', { name, spec: opts.spec }); render(); } catch (ex) { Toast(ex?.message || 'Save failed', { type: 'error' }); } });
    el.querySelectorAll('[data-load]').forEach((b) => b.addEventListener('click', () => { const v = views.find((x) => String(x.id) === b.getAttribute('data-load')); if (v && opts.onSelect) { let spec = v.spec; try { spec = typeof spec === 'string' ? JSON.parse(spec) : spec; } catch (_) {} opts.onSelect(spec, v); } }));
    el.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.delete('/api/_query/views/' + b.getAttribute('data-del')); render(); } catch (ex) { Toast(ex?.message || 'Delete failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 3b - M2M + hierarchical relations (over auto-CRUD)
// ═══════════════════════════════════════════════════════════════════

// MultiRelation(target, { table, parentField, parentId, childTable, childField, labelField?, onChange? })
// Renders the children linked to a parent through a join table; add via a
// picker (creates a join row), remove via × (deletes the join row).
export async function MultiRelation(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const lf = opts.labelField || labelField(s[opts.childTable]);
  const render = async () => {
    const [links, children] = await Promise.all([
      listRows(opts.table, { limit: 500, where: { [opts.parentField]: opts.parentId } }),
      bm.table(opts.childTable).list({ limit: 500 }),
    ]);
    const childById = Object.fromEntries(children.map((c) => [String(c.id), c]));
    const linkedIds = new Set(links.map((l) => String(l[opts.childField])));
    const avail = children.filter((c) => !linkedIds.has(String(c.id)));
    el.innerHTML = `<div data-bm-multirel class="space-y-2">
      <div class="flex flex-wrap gap-2">${links.length ? links.map((l) => { const c = childById[String(l[opts.childField])]; return `<span data-link="${esc(l.id)}" style="display:inline-flex;align-items:center;gap:6px;padding:3px 6px 3px 10px;border-radius:9999px;background:rgba(37,99,235,.12);color:#1d4ed8;font-size:13px">${esc(c ? c[lf] : l[opts.childField])}<button data-unlink="${esc(l.id)}" style="background:none;border:none;cursor:pointer;color:inherit;font-weight:700">×</button></span>`; }).join('') : '<span class="text-sm text-zinc-500">None linked.</span>'}</div>
      ${avail.length ? `<div class="flex gap-2"><select data-add class="${inputCls}" style="flex:1"><option value="">+ Add…</option>${avail.map((c) => `<option value="${esc(c.id)}">${esc(c[lf] ?? c.id)}</option>`).join('')}</select></div>` : ''}</div>`;
    el.querySelectorAll('[data-unlink]').forEach((b) => b.addEventListener('click', async () => { try { await bm.table(opts.table).delete(b.getAttribute('data-unlink')); if (opts.onChange) opts.onChange(); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
    el.querySelector('[data-add]')?.addEventListener('change', async (e) => { const v = e.target.value; if (!v) return; try { await bm.table(opts.table).create({ [opts.parentField]: opts.parentId, [opts.childField]: v }); if (opts.onChange) opts.onChange(); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } });
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// TreeView(target, { table, parentField?, labelField?, onSelect? }) - self-referential hierarchy.
export async function TreeView(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const pf = opts.parentField || 'parent_id';
  const lf = opts.labelField || labelField(s[opts.table]);
  const render = async () => {
    const rows = await listRows(opts.table, { limit: 1000 });
    const byParent = new Map();
    rows.forEach((r) => { const p = r[pf] == null ? 'root' : String(r[pf]); if (!byParent.has(p)) byParent.set(p, []); byParent.get(p).push(r); });
    const node = (r) => {
      const kids = byParent.get(String(r.id)) || [];
      return `<li data-bm-node data-id="${esc(r.id)}"><div style="display:flex;align-items:center;gap:6px;padding:3px 0">${kids.length ? `<button data-toggle style="background:none;border:none;cursor:pointer;opacity:.5;width:14px">▾</button>` : '<span style="width:14px;display:inline-block"></span>'}<span data-label style="cursor:${opts.onSelect ? 'pointer' : 'default'}">${esc(r[lf] ?? r.id)}</span></div>${kids.length ? `<ul data-children style="list-style:none;margin:0;padding-left:18px">${kids.map(node).join('')}</ul>` : ''}</li>`;
    };
    const roots = byParent.get('root') || [];
    el.innerHTML = `<ul data-bm-tree style="list-style:none;margin:0;padding:0;font-size:14px">${roots.map(node).join('')}</ul>`;
    el.querySelectorAll('[data-toggle]').forEach((b) => b.addEventListener('click', () => { const kids = b.closest('[data-bm-node]').querySelector('[data-children]'); if (kids) { const hidden = kids.style.display === 'none'; kids.style.display = hidden ? '' : 'none'; b.textContent = hidden ? '▾' : '▸'; } }));
    if (opts.onSelect) el.querySelectorAll('[data-label]').forEach((s2) => s2.addEventListener('click', () => opts.onSelect(s2.closest('[data-bm-node]').getAttribute('data-id'))));
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 3c - per-record scheduling + approvals (/api/_scheduled, /api/_approvals)
// ═══════════════════════════════════════════════════════════════════

function schedList(tasks) {
  if (!tasks.length) return '<p class="text-sm text-zinc-500">Nothing scheduled.</p>';
  return tasks.map((t) => `<div class="flex items-center justify-between text-sm px-1 py-1.5"><div><span class="font-medium">${esc(t.title || t.message || t.flow || 'Task')}</span> <span class="text-zinc-500">${relTime(t.run_at)} · ${esc(t.status)}</span></div>${t.status === 'pending' ? `<button data-cancel="${esc(t.id)}" class="text-red-600">Cancel</button>` : ''}</div>`).join('');
}
// Reminder(target, { table?, rowId? }) - schedule an in-app reminder.
export async function Reminder(target, opts = {}) {
  const el = resolveEl(target);
  const render = async () => {
    let tasks = [];
    try { const qs = new URLSearchParams(); if (opts.table) qs.set('table', opts.table); if (opts.rowId != null) qs.set('row_id', String(opts.rowId)); const r = await bm.api.get('/api/_scheduled' + (qs.toString() ? '?' + qs : '')); tasks = (Array.isArray(r) ? r : (r.tasks || [])).filter((t) => t.kind !== 'flow'); } catch (_) {}
    el.innerHTML = `<div data-bm-reminder class="space-y-3"><form data-bm-form class="space-y-2">${skin.error('')}
      ${skinField('message', 'Reminder', { required: true })}
      <label class="block space-y-1"><span class="text-sm font-medium">When</span><input name="run_at" type="datetime-local" required class="${inputCls}"></label>
      ${skin.button({ label: 'Set reminder' })}</form><div data-list class="space-y-1">${schedList(tasks)}</div></div>`;
    const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
    form.addEventListener('submit', async (e) => { e.preventDefault(); errEl.hidden = true; const fd = new FormData(form); const when = fd.get('run_at'); try { await bm.api.post('/api/_scheduled', { kind: 'reminder', title: 'Reminder', message: fd.get('message'), run_at: new Date(when).toISOString(), table: opts.table, row_id: opts.rowId != null ? String(opts.rowId) : '' }); render(); } catch (ex) { errEl.textContent = ex?.message || 'Failed'; errEl.hidden = false; } });
    el.querySelectorAll('[data-cancel]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.delete('/api/_scheduled/' + b.getAttribute('data-cancel')); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// ScheduleAction(target, { flow, body?, table?, rowId?, label? }) - run a flow at a future time.
export async function ScheduleAction(target, opts) {
  const el = resolveEl(target);
  const render = async () => {
    let tasks = [];
    try { const r = await bm.api.get('/api/_scheduled' + (opts.table ? '?table=' + encodeURIComponent(opts.table) : '')); tasks = (Array.isArray(r) ? r : (r.tasks || [])).filter((t) => t.kind === 'flow'); } catch (_) {}
    el.innerHTML = `<div data-bm-scheduleaction class="space-y-3"><form data-bm-form class="space-y-2">${skin.error('')}
      <div class="text-sm text-zinc-500">Schedule <b>${esc(opts.label || opts.flow)}</b> to run at:</div>
      <input name="run_at" type="datetime-local" required class="${inputCls}">
      ${skin.button({ label: 'Schedule' })}</form><div data-list class="space-y-1">${schedList(tasks)}</div></div>`;
    const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
    form.addEventListener('submit', async (e) => { e.preventDefault(); errEl.hidden = true; const when = new FormData(form).get('run_at'); try { await bm.api.post('/api/_scheduled', { kind: 'flow', title: opts.label || opts.flow, flow: opts.flow, body: opts.body || {}, run_at: new Date(when).toISOString(), table: opts.table, row_id: opts.rowId != null ? String(opts.rowId) : '' }); render(); } catch (ex) { errEl.textContent = ex?.message || 'Failed'; errEl.hidden = false; } });
    el.querySelectorAll('[data-cancel]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.delete('/api/_scheduled/' + b.getAttribute('data-cancel')); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}
// Approval(target, { table, id, approverEmail?, title? }) - request + decide.
export async function Approval(target, opts) {
  const el = resolveEl(target);
  const me = await currentUser();
  const render = async () => {
    let rows = [];
    try { const r = await bm.api.get(`/api/_approvals?table=${encodeURIComponent(opts.table)}&row_id=${encodeURIComponent(opts.id)}`); rows = Array.isArray(r) ? r : (r.approvals || []); } catch (_) {}
    const open = rows.find((a) => a.status === 'pending');
    let inner;
    if (open) {
      const amApprover = me && (open.approver_email === me.email);
      inner = `<div class="flex items-center gap-3 text-sm">${Badge('Pending approval', { variant: 'warning' })}<span class="text-zinc-500">${esc(open.title || '')} · ${esc(open.approver_email || 'unassigned')}</span></div>` +
        (amApprover || (me && me.role === 'admin') ? `<div class="flex gap-2 mt-2"><button data-decide="approved" class="px-3 py-1.5 rounded-md bg-green-600 text-white text-sm">Approve</button><button data-decide="rejected" class="px-3 py-1.5 rounded-md border border-red-300 text-red-600 text-sm">Reject</button></div>` : '');
    } else {
      const last = rows[0];
      inner = (last ? `<div class="text-sm mb-3">Last decision: ${Badge(last.status, { variant: last.status === 'approved' ? 'success' : 'error' })} ${esc(last.note || '')}</div>` : '') +
        `<form data-bm-form class="space-y-2">${skin.error('')}${skinField('approver_email', 'Approver email', { type: 'email', required: true })}${skinField('title', 'What needs approval?', {})}${skin.button({ label: 'Request approval' })}</form>`;
    }
    el.innerHTML = `<div data-bm-approval>${inner}</div>`;
    el.querySelectorAll('[data-decide]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.post(`/api/_approvals/${open.id}/decide`, { decision: b.getAttribute('data-decide') }); Toast('Decision recorded', { type: 'success' }); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
    const form = el.querySelector('form');
    if (form) { const errEl = el.querySelector('[data-bm-error]'); form.addEventListener('submit', async (e) => { e.preventDefault(); errEl.hidden = true; const fd = new FormData(form); try { await bm.api.post('/api/_approvals', { table: opts.table, row_id: String(opts.id), approver_email: fd.get('approver_email'), title: fd.get('title') }); render(); } catch (ex) { errEl.textContent = ex?.message || 'Failed'; errEl.hidden = false; } }); }
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 4 - remaining tail (all over existing primitives)
// ═══════════════════════════════════════════════════════════════════

// Calendar(target, { table, dateField, titleField?, onSelect? }) - month grid.
export async function Calendar(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const titleField = opts.titleField || labelField(s[opts.table]);
  let cursor = new Date(); cursor.setDate(1);
  const render = async () => {
    const rows = await listRows(opts.table, { limit: 500, where: opts.where });
    const byDay = {};
    rows.forEach((r) => { const d = String(r[opts.dateField] || '').slice(0, 10); if (d) (byDay[d] = byDay[d] || []).push(r); });
    const y = cursor.getFullYear(), mo = cursor.getMonth();
    const first = new Date(y, mo, 1), startDow = first.getDay(), days = new Date(y, mo + 1, 0).getDate();
    const monthName = cursor.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
    const CELL = 'height:92px;box-sizing:border-box;border:1px solid rgba(128,128,128,.15);border-radius:6px;padding:4px;font-size:11px;overflow:hidden';
    let cells = '';
    for (let i = 0; i < startDow; i++) cells += `<div style="height:92px"></div>`;
    for (let d = 1; d <= days; d++) {
      const iso = `${y}-${String(mo + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
      const items = byDay[iso] || [];
      cells += `<div style="${CELL}"><div style="opacity:.5;font-weight:600">${d}</div>${items.slice(0, 2).map((r) => `<div data-id="${esc(r.id)}" style="cursor:${opts.onSelect ? 'pointer' : 'default'};background:rgba(37,99,235,.12);color:#1d4ed8;border-radius:4px;padding:1px 4px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r[titleField] ?? r.id)}</div>`).join('')}${items.length > 2 ? `<div style="opacity:.5;margin-top:2px">+${items.length - 2} more</div>` : ''}</div>`;
    }
    el.innerHTML = `<div data-bm-calendar><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><button data-prev style="background:none;border:none;cursor:pointer;font-size:18px">‹</button><b>${esc(monthName)}</b><button data-next style="background:none;border:none;cursor:pointer;font-size:18px">›</button></div><div style="display:grid;grid-template-columns:repeat(7,1fr);gap:4px;font-size:10px;opacity:.5;text-align:center;margin-bottom:4px">${['S','M','T','W','T','F','S'].map((d) => `<div>${d}</div>`).join('')}</div><div style="display:grid;grid-template-columns:repeat(7,1fr);gap:4px">${cells}</div></div>`;
    el.querySelector('[data-prev]').addEventListener('click', () => { cursor.setMonth(cursor.getMonth() - 1); render(); });
    el.querySelector('[data-next]').addEventListener('click', () => { cursor.setMonth(cursor.getMonth() + 1); render(); });
    if (opts.onSelect) el.querySelectorAll('[data-id]').forEach((x) => x.addEventListener('click', () => opts.onSelect(x.getAttribute('data-id'))));
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// Timeline(target, { table, dateField?, titleField? }) - vertical chronology.
export async function Timeline(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const df = opts.dateField || 'created_at';
  const tf = opts.titleField || (visible(s[opts.table] ? tableDesc(s, opts.table) : { fields: [] }).find((f) => ['summary', 'title', 'name', 'message'].includes(f.name)) || {}).name || 'id';
  const render = async () => {
    const rows = await listRows(opts.table, { limit: opts.limit || 50, sort: df, order: 'desc', where: opts.where });
    if (!rows.length) { el.innerHTML = skin.emptyState('Nothing yet.'); return; }
    el.innerHTML = `<ol data-bm-timeline style="list-style:none;margin:0;padding:0;position:relative;border-left:2px solid rgba(128,128,128,.2);margin-left:8px">` + rows.map((r) => `<li style="position:relative;padding:0 0 18px 20px"><span style="position:absolute;left:-7px;top:2px;width:12px;height:12px;border-radius:9999px;background:var(--bm-accent,#2563eb);box-shadow:0 0 0 3px var(--card,#fff)"></span><div style="font-size:14px">${esc(r[tf] ?? r.id)}</div><div style="font-size:11px;opacity:.5">${relTime(r[df])}</div></li>`).join('') + `</ol>`;
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// InlineEdit(target, { table, id, field, value?, onSaved? }) - click-to-edit one field.
export async function InlineEdit(target, opts) {
  const el = resolveEl(target);
  let value = opts.value;
  if (value === undefined) { try { const row = await bm.table(opts.table).get(opts.id); value = row[opts.field]; } catch (_) { value = ''; } }
  const view = () => { el.innerHTML = `<span data-bm-inline style="border-bottom:1px dashed rgba(128,128,128,.5);cursor:text">${esc(value == null || value === '' ? '-' : value)}</span>`; el.querySelector('span').addEventListener('click', edit); };
  const edit = () => {
    el.innerHTML = `<input value="${esc(value ?? '')}" class="${inputCls}" style="display:inline-block;width:auto">`;
    const inp = el.querySelector('input'); inp.focus(); inp.select();
    const save = async () => { const nv = inp.value; if (nv === String(value ?? '')) { view(); return; } try { await bm.table(opts.table).update(opts.id, { [opts.field]: nv }); value = nv; if (opts.onSaved) opts.onSaved(nv); } catch (ex) { Toast(ex?.message || 'Save failed', { type: 'error' }); } view(); };
    inp.addEventListener('blur', save);
    inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') inp.blur(); if (e.key === 'Escape') view(); });
  };
  view();
  return { destroy: () => { el.innerHTML = ''; } };
}

// Funnel(target, { table, stageField, stages, where? }) - counts per stage.
export async function Funnel(target, opts) {
  const el = resolveEl(target);
  const render = async () => {
    const counts = await Promise.all(opts.stages.map((st) => bm.table(opts.table).count({ where: { ...(opts.where || {}), [opts.stageField]: st } }).catch(() => 0)));
    const max = Math.max(1, ...counts);
    el.innerHTML = `<div data-bm-funnel class="space-y-1.5">` + opts.stages.map((st, i) => {
      const pct = (counts[i] / max) * 100;
      const conv = i > 0 && counts[i - 1] ? Math.round((counts[i] / counts[i - 1]) * 100) : null;
      return `<div style="display:flex;align-items:center;gap:10px"><div style="width:110px;font-size:13px;text-align:right;opacity:.7">${esc(humanize(st))}</div><div style="flex:1;background:rgba(128,128,128,.1);border-radius:6px;overflow:hidden"><div style="width:${Math.max(pct, 4)}%;background:var(--bm-accent,#2563eb);color:#fff;padding:4px 8px;font-size:12px;font-weight:600;border-radius:6px">${counts[i]}</div></div><div style="width:48px;font-size:11px;opacity:.5">${conv != null ? conv + '%' : ''}</div></div>`;
    }).join('') + `</div>`;
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// Import(target, { table, onDone? }) - CSV → POST /api/{table}/batch.
export function Import(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-import class="space-y-2"><input type="file" accept=".csv,text/csv" data-file class="block text-sm"><div data-status class="text-sm text-zinc-500"></div></div>`;
  const status = el.querySelector('[data-status]');
  el.querySelector('[data-file]').addEventListener('change', async (e) => {
    const file = e.target.files[0]; if (!file) return;
    status.textContent = 'Parsing…';
    const text = await file.text();
    const lines = text.split(/\r?\n/).filter((l) => l.trim());
    if (lines.length < 2) { status.textContent = 'Empty or header-only file.'; return; }
    const headers = lines[0].split(',').map((h) => h.trim());
    const rows = lines.slice(1).map((l) => { const cells = l.split(','); const o = {}; headers.forEach((h, i) => { o[h] = (cells[i] || '').trim(); }); return o; });
    status.textContent = `Importing ${rows.length} rows…`;
    try { const r = await bm.api.post(`/api/${opts.table}/batch`, rows); status.textContent = `Imported ${rows.length} rows ✓`; if (opts.onDone) opts.onDone(r); }
    catch (ex) { status.textContent = 'Import failed: ' + (ex?.message || ''); }
  });
  return { destroy: () => { el.innerHTML = ''; } };
}

// CustomFields(target, { table }) - manage runtime custom fields.
export async function CustomFields(target, opts) {
  const el = resolveEl(target);
  const base = `/api/_schema/${opts.table}/fields`;
  const render = async () => {
    let fields = [];
    try { const r = await bm.api.get(base); fields = Array.isArray(r) ? r : (r.fields || []); } catch (_) {}
    el.innerHTML = `<div data-bm-customfields class="space-y-3"><form data-bm-form class="flex gap-2 items-end">${skin.error('')}
      <label class="flex-1 space-y-1"><span class="text-sm font-medium">Field name</span><input name="name" required class="${inputCls}"></label>
      <label class="space-y-1"><span class="text-sm font-medium">Type</span><select name="type" class="${inputCls}"><option value="text">Text</option><option value="number">Number</option><option value="boolean">Boolean</option><option value="date">Date</option></select></label>
      ${skin.button({ label: 'Add field' })}</form>
      <div data-list class="space-y-1">${fields.length ? fields.map((f) => `<div class="flex items-center justify-between text-sm px-1"><span><b>${esc(f.name)}</b> <span class="text-zinc-500">${esc(f.type || '')}</span></span><button data-del="${esc(f.name)}" class="text-red-600">Remove</button></div>`).join('') : '<p class="text-sm text-zinc-500">No custom fields.</p>'}</div></div>`;
    const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
    form.addEventListener('submit', async (e) => { e.preventDefault(); errEl.hidden = true; const fd = new FormData(form); try { await bm.api.post(base, { name: fd.get('name'), type: fd.get('type') }); render(); } catch (ex) { errEl.textContent = ex?.message || 'Failed'; errEl.hidden = false; } });
    el.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => { try { await bm.api.delete(base + '/' + encodeURIComponent(b.getAttribute('data-del'))); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}

// ─── layout / chrome ─────────────────────────────────────────────────
// AppShell(target, { title, brand?, nav:[{label,href?,onClick?,icon?}], active? }) → { content, destroy }
export function AppShell(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-appshell style="display:flex;min-height:100vh">
    <aside style="width:220px;flex-shrink:0;border-right:1px solid rgba(128,128,128,.15);padding:16px;background:rgba(128,128,128,.03)">
      <div style="font-weight:700;font-size:15px;margin-bottom:16px">${esc(opts.brand || opts.title || 'App')}</div>
      <nav data-nav style="display:flex;flex-direction:column;gap:2px">${(opts.nav || []).map((n, i) => `<a data-i="${i}" href="${esc(n.href || '#')}" style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:8px;font-size:14px;text-decoration:none;color:inherit;${i === (opts.active || 0) ? 'background:rgba(37,99,235,.12);color:#1d4ed8;font-weight:600' : ''}">${n.icon ? esc(n.icon) + ' ' : ''}${esc(n.label)}</a>`).join('')}</nav>
    </aside>
    <main data-content style="flex:1;padding:28px;min-width:0"></main></div>`;
  (opts.nav || []).forEach((n, i) => { if (n.onClick) el.querySelector(`[data-i="${i}"]`).addEventListener('click', (e) => { e.preventDefault(); n.onClick(); }); });
  return { content: el.querySelector('[data-content]'), destroy: () => { el.innerHTML = ''; } };
}
// Nav(target, { items:[{label,href?,onClick?}], active? }) → { destroy }
export function Nav(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<nav data-bm-nav style="display:flex;gap:4px">${(opts.items || []).map((n, i) => `<a data-i="${i}" href="${esc(n.href || '#')}" style="padding:8px 12px;border-radius:8px;font-size:14px;text-decoration:none;color:inherit;${i === (opts.active || 0) ? 'background:rgba(37,99,235,.12);color:#1d4ed8;font-weight:600' : ''}">${esc(n.label)}</a>`).join('')}</nav>`;
  (opts.items || []).forEach((n, i) => { if (n.onClick) el.querySelector(`[data-i="${i}"]`).addEventListener('click', (e) => { e.preventDefault(); n.onClick(); }); });
  return { destroy: () => { el.innerHTML = ''; } };
}
// Breadcrumbs(target, { items:[{label,href?}] }) → { destroy }
export function Breadcrumbs(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<nav data-bm-breadcrumbs style="display:flex;align-items:center;gap:6px;font-size:13px;opacity:.8">${(opts.items || []).map((it, i) => `${i ? '<span style="opacity:.4">/</span>' : ''}${it.href ? `<a href="${esc(it.href)}" style="color:var(--bm-accent,#2563eb);text-decoration:none">${esc(it.label)}</a>` : `<span>${esc(it.label)}</span>`}`).join('')}</nav>`;
  return { destroy: () => { el.innerHTML = ''; } };
}
// CommandPalette({ commands:[{label,run,hint?}], hotkey? }) → { open, close, destroy }
export function CommandPalette(opts = {}) {
  ensureStyles();
  const cmds = opts.commands || [];
  let back = null;
  const close = () => { if (back) { back.remove(); back = null; } };
  const open = () => {
    if (back) return;
    back = document.createElement('div');
    back.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.4);display:flex;align-items:flex-start;justify-content:center;padding:12vh 16px';
    back.innerHTML = `<div style="background:var(--card,#fff);border-radius:12px;width:100%;max-width:520px;box-shadow:0 24px 64px rgba(0,0,0,.35);overflow:hidden"><input data-cmd placeholder="Type a command…" style="width:100%;padding:14px 16px;border:none;border-bottom:1px solid rgba(128,128,128,.15);font-size:15px;background:none;outline:none"><div data-results style="max-height:340px;overflow:auto"></div></div>`;
    document.body.appendChild(back);
    const input = back.querySelector('[data-cmd]'), results = back.querySelector('[data-results]');
    let active = 0, filtered = cmds;
    const draw = () => { results.innerHTML = filtered.length ? filtered.map((c, i) => `<div data-r="${i}" style="padding:10px 16px;cursor:pointer;display:flex;justify-content:space-between;${i === active ? 'background:rgba(37,99,235,.1)' : ''}"><span>${esc(c.label)}</span><span style="opacity:.4;font-size:12px">${esc(c.hint || '')}</span></div>`).join('') : '<div style="padding:16px;opacity:.5;font-size:14px">No matches.</div>'; results.querySelectorAll('[data-r]').forEach((r) => r.addEventListener('click', () => run(filtered[+r.getAttribute('data-r')]))); };
    const run = (c) => { if (!c) return; close(); try { c.run(); } catch (_) {} };
    input.addEventListener('input', () => { const q = input.value.toLowerCase(); filtered = cmds.filter((c) => c.label.toLowerCase().includes(q)); active = 0; draw(); });
    input.addEventListener('keydown', (e) => { if (e.key === 'ArrowDown') { active = Math.min(active + 1, filtered.length - 1); draw(); } else if (e.key === 'ArrowUp') { active = Math.max(active - 1, 0); draw(); } else if (e.key === 'Enter') run(filtered[active]); else if (e.key === 'Escape') close(); });
    back.addEventListener('mousedown', (e) => { if (e.target === back) close(); });
    draw(); input.focus();
  };
  const onKey = (e) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === (opts.hotkey || 'k')) { e.preventDefault(); back ? close() : open(); } };
  window.addEventListener('keydown', onKey);
  return { open, close, destroy: () => { close(); window.removeEventListener('keydown', onKey); } };
}

// ─── content editors ─────────────────────────────────────────────────
// DatePicker(target, { value?, onChange? }) → { value, destroy }
export function DatePicker(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<input type="date" value="${esc((opts.value || '').slice(0, 10))}" class="${inputCls}" style="width:auto">`;
  const inp = el.querySelector('input');
  inp.addEventListener('change', () => opts.onChange && opts.onChange(inp.value));
  return { get value() { return inp.value; }, destroy: () => { el.innerHTML = ''; } };
}
// Markdown(target, { text }) → { destroy } - renders via bm.markdown (safe).
export async function Markdown(target, opts) {
  const el = resolveEl(target);
  try { el.innerHTML = `<div data-bm-markdown>${await bm.markdown(opts.text || '')}</div>`; } catch (_) { el.textContent = opts.text || ''; }
  return { destroy: () => { el.innerHTML = ''; } };
}
// RichText(target, { value?, onChange? }) → { html, destroy } - minimal toolbar.
export function RichText(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-richtext style="border:1px solid rgba(128,128,128,.3);border-radius:8px;overflow:hidden"><div style="display:flex;gap:2px;padding:6px;border-bottom:1px solid rgba(128,128,128,.15)">${[['bold', 'B'], ['italic', 'I'], ['insertUnorderedList', '• List']].map(([c, l]) => `<button type="button" data-cmd="${c}" style="padding:4px 8px;background:none;border:none;cursor:pointer;font-weight:600;border-radius:4px">${l}</button>`).join('')}</div><div data-edit contenteditable="true" style="padding:10px;min-height:120px;outline:none;font-size:14px">${opts.value || ''}</div></div>`;
  const edit = el.querySelector('[data-edit]');
  el.querySelectorAll('[data-cmd]').forEach((b) => b.addEventListener('mousedown', (e) => { e.preventDefault(); document.execCommand(b.getAttribute('data-cmd')); edit.focus(); }));
  edit.addEventListener('input', () => opts.onChange && opts.onChange(edit.innerHTML));
  return { get html() { return edit.innerHTML; }, destroy: () => { el.innerHTML = ''; } };
}
// Code(target, { code, lang?, copy? }) → { destroy }
export function Code(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-code style="position:relative"><pre style="background:#0d1117;color:#e6edf3;border-radius:8px;padding:14px;overflow:auto;font-size:13px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace"><code>${esc(opts.code || '')}</code></pre>${opts.copy === false ? '' : `<button data-copy style="position:absolute;top:8px;right:8px;background:rgba(255,255,255,.1);color:#fff;border:none;border-radius:6px;padding:4px 8px;font-size:11px;cursor:pointer">Copy</button>`}</div>`;
  el.querySelector('[data-copy]')?.addEventListener('click', () => { navigator.clipboard?.writeText(opts.code || ''); Toast('Copied', { type: 'success', duration: 1500 }); });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── livestream (bm.broadcast / WebRTC SFU) ──────────────────────────
// Broadcast(target, { slug }) - publish this device's camera/mic. Returns { stop, destroy }.
export async function Broadcast(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-broadcast class="space-y-2"><video data-v autoplay muted playsinline style="width:100%;border-radius:8px;background:#000"></video><div data-status class="text-sm text-zinc-500">Click to go live.</div><button data-go class="px-4 py-2 rounded-md bg-red-600 text-white font-medium">Go live</button></div>`;
  const video = el.querySelector('[data-v]'), status = el.querySelector('[data-status]'), btn = el.querySelector('[data-go]');
  let stream = null, handle = null;
  const stop = () => { try { handle && bm.broadcast.stop && bm.broadcast.stop(opts.slug); } catch (_) {} if (stream) stream.getTracks().forEach((t) => t.stop()); stream = null; status.textContent = 'Stopped.'; btn.textContent = 'Go live'; };
  btn.addEventListener('click', async () => {
    if (stream) { stop(); return; }
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      video.srcObject = stream; status.textContent = 'Connecting…';
      handle = await bm.broadcast.publish(opts.slug, stream);
      status.textContent = 'Live ✓'; btn.textContent = 'Stop';
    } catch (ex) { status.textContent = 'Failed: ' + (ex?.message || ''); }
  });
  return { stop, destroy: () => { stop(); el.innerHTML = ''; } };
}
// Viewer(target, { slug }) - subscribe to a broadcast. Returns { destroy }.
export async function Viewer(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-viewer><video data-v autoplay muted playsinline controls style="width:100%;border-radius:8px;background:#000"></video><div data-status class="text-sm text-zinc-500 mt-1">Connecting…</div><button data-unmute class="text-sm bm-accent-text mt-1" hidden>Tap to unmute</button></div>`;
  const video = el.querySelector('[data-v]'), status = el.querySelector('[data-status]'), unmute = el.querySelector('[data-unmute]');
  let handle = null;
  unmute.addEventListener('click', () => { video.muted = false; unmute.hidden = true; });
  try {
    const stream = await bm.broadcast.subscribe(opts.slug);
    video.srcObject = stream; status.textContent = 'Watching ✓'; unmute.hidden = false;
  } catch (ex) { status.textContent = 'No live stream: ' + (ex?.message || ''); }
  return { destroy: () => { try { handle && handle.close && handle.close(); } catch (_) {} el.innerHTML = ''; } };
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 5 - gaps surfaced by real apps + general additions
// ═══════════════════════════════════════════════════════════════════

// Stepper(target, { steps, current, onClick? }) - ordered stage tracker.
// steps: string[] | {label}[]. current: index or matching label.
export function Stepper(target, opts) {
  const el = resolveEl(target);
  const steps = (opts.steps || []).map((s) => (typeof s === 'string' ? { label: s } : s));
  let cur = typeof opts.current === 'number' ? opts.current : steps.findIndex((s) => s.label === opts.current);
  if (cur < 0) cur = 0;
  const draw = () => {
    el.innerHTML = `<div data-bm-stepper style="display:flex;align-items:center;width:100%">` + steps.map((s, i) => {
      const done = i < cur, active = i === cur;
      const bg = done ? '#16a34a' : active ? 'var(--bm-accent,#2563eb)' : 'rgba(128,128,128,.25)';
      const fg = (done || active) ? '#fff' : 'inherit';
      const circle = `<div data-step="${i}" style="display:flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:50%;background:${bg};color:${fg};font-size:13px;font-weight:600;flex-shrink:0;cursor:${opts.onClick ? 'pointer' : 'default'}">${done ? '✓' : (i + 1)}</div>`;
      const lbl = `<div style="font-size:12px;margin:0 8px;white-space:nowrap;opacity:${active ? 1 : .65};font-weight:${active ? 600 : 400}">${esc(s.label)}</div>`;
      const line = i < steps.length - 1 ? `<div style="flex:1;height:2px;background:${i < cur ? '#16a34a' : 'rgba(128,128,128,.25)'};min-width:14px"></div>` : '';
      return `<div style="display:flex;align-items:center;${i < steps.length - 1 ? 'flex:1' : ''}">${circle}${lbl}${line}</div>`;
    }).join('') + `</div>`;
    if (opts.onClick) el.querySelectorAll('[data-step]').forEach((c) => c.addEventListener('click', () => opts.onClick(Number(c.getAttribute('data-step')))));
  };
  draw();
  return { set: (i) => { cur = i; draw(); }, destroy: () => { el.innerHTML = ''; } };
}

// FilterBar(target, { filters, target?, onChange? }) - controls that build a
// `where` and push it to a DataTable handle (target) and/or onChange(where).
// filters: [{ name, label?, type:'select'|'date'|'search', options? }].
export function FilterBar(target, opts) {
  const el = resolveEl(target);
  const filters = opts.filters || [];
  const ctrl = (f) => {
    if (f.type === 'select') return `<select data-f="${esc(f.name)}" class="${inputCls}" style="width:auto"><option value="">${esc(f.label || humanize(f.name))}: all</option>${(f.options || []).map((o) => { const v = typeof o === 'string' ? o : o.value; const l = typeof o === 'string' ? o : o.label; return `<option value="${esc(v)}">${esc(l)}</option>`; }).join('')}</select>`;
    if (f.type === 'date') return `<input data-f="${esc(f.name)}" type="date" class="${inputCls}" style="width:auto" title="${esc(f.label || f.name)}">`;
    return `<input data-f="${esc(f.name)}" type="search" placeholder="${esc(f.label || humanize(f.name))}" class="${inputCls}" style="width:auto">`;
  };
  el.innerHTML = `<div data-bm-filterbar style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">${filters.map(ctrl).join('')}<button data-clear style="font-size:13px;color:var(--bm-accent,#2563eb);background:none;border:none;cursor:pointer">Clear</button></div>`;
  const collect = () => { const w = {}; el.querySelectorAll('[data-f]').forEach((i) => { const v = i.value.trim(); if (v) w[i.getAttribute('data-f')] = v; }); return w; };
  const apply = () => { const w = collect(); if (opts.target && opts.target.setWhere) opts.target.setWhere(w); if (opts.onChange) opts.onChange(w); };
  el.querySelectorAll('[data-f]').forEach((i) => { i.addEventListener('change', apply); if (i.type === 'search') { let t; i.addEventListener('input', () => { clearTimeout(t); t = setTimeout(apply, 300); }); } });
  el.querySelector('[data-clear]').addEventListener('click', () => { el.querySelectorAll('[data-f]').forEach((i) => { i.value = ''; }); apply(); });
  return { value: collect, apply, destroy: () => { el.innerHTML = ''; } };
}

// KpiTile(target, { label, value, delta?, deltaUnit?, deltaLabel?, spark?, format? })
export function KpiTile(target, opts) {
  const el = resolveEl(target);
  const spark = opts.spark || [];
  const max = Math.max(1, ...spark);
  const sparkHtml = spark.length ? `<div style="display:flex;align-items:flex-end;gap:2px;height:28px;margin-top:10px">${spark.map((v) => `<div style="flex:1;background:rgba(37,99,235,.4);border-radius:1px;height:${Math.max(2, (v / max) * 28)}px"></div>`).join('')}</div>` : '';
  const d = opts.delta;
  const deltaHtml = (d != null) ? `<span style="font-size:12px;font-weight:600;color:${d >= 0 ? '#16a34a' : '#dc2626'}">${d >= 0 ? '▲' : '▼'} ${Math.abs(d)}${opts.deltaUnit || '%'}</span>` : '';
  el.innerHTML = `<div data-bm-kpi class="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4">
    <div style="display:flex;justify-content:space-between;align-items:baseline;gap:8px"><span style="font-size:12px;text-transform:uppercase;letter-spacing:.04em;opacity:.55">${esc(opts.label || '')}</span>${deltaHtml}</div>
    <div style="font-size:26px;font-weight:600;margin-top:4px" class="tabular-nums">${esc(opts.format ? opts.format(opts.value) : opts.value)}</div>
    ${opts.deltaLabel ? `<div style="font-size:11px;opacity:.5;margin-top:2px">${esc(opts.deltaLabel)}</div>` : ''}${sparkHtml}</div>`;
  return { destroy: () => { el.innerHTML = ''; } };
}

// Alert(target, { type, title?, message, dismissible?, onDismiss? }) - inline callout.
export function Alert(target, opts = {}) {
  const el = resolveEl(target);
  const types = { info: ['var(--bm-accent,#2563eb)', 'rgba(37,99,235,.1)', 'info'], success: ['#16a34a', 'rgba(22,163,74,.1)', 'check-circle'], warning: ['#d97706', 'rgba(217,119,6,.1)', 'alert-triangle'], error: ['#dc2626', 'rgba(220,38,38,.1)', 'x-circle'] };
  const [c, bg, icon] = types[opts.type] || types.info;
  el.innerHTML = `<div data-bm-alert role="alert" style="display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:8px;background:${bg};border-left:3px solid ${c}">
    <span style="color:${c};display:inline-flex;align-items:center;padding-top:1px">${lucide(icon, 16)}</span>
    <div style="flex:1;font-size:13px;line-height:1.45">${opts.title ? `<div style="font-weight:600;margin-bottom:2px">${esc(opts.title)}</div>` : ''}<div style="opacity:.85">${esc(opts.message || '')}</div></div>
    ${opts.dismissible ? `<button data-x style="background:none;border:none;cursor:pointer;opacity:.5;font-size:16px;line-height:1">×</button>` : ''}</div>`;
  el.querySelector('[data-x]')?.addEventListener('click', () => { el.innerHTML = ''; if (opts.onDismiss) opts.onDismiss(); });
  return { destroy: () => { el.innerHTML = ''; } };
}

// EmptyState(target, { icon?, title, body?, actionLabel?, onAction? })
export function EmptyState(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-emptystate style="text-align:center;padding:40px 20px">
    ${opts.icon ? `<div style="font-size:30px;opacity:.4;margin-bottom:8px">${esc(opts.icon)}</div>` : ''}
    <div style="font-weight:600;font-size:15px">${esc(opts.title || 'Nothing here')}</div>
    ${opts.body ? `<div style="font-size:13px;opacity:.6;margin-top:4px;max-width:340px;margin:4px auto 0">${esc(opts.body)}</div>` : ''}
    ${opts.actionLabel ? `<button data-act style="margin-top:14px;padding:8px 16px;border-radius:8px;background:var(--bm-accent,#2563eb);color:#fff;border:none;cursor:pointer;font-size:14px">${esc(opts.actionLabel)}</button>` : ''}</div>`;
  el.querySelector('[data-act]')?.addEventListener('click', () => opts.onAction && opts.onAction());
  return { destroy: () => { el.innerHTML = ''; } };
}

// ConfirmDialog({ title?, message?, confirmLabel?, cancelLabel?, danger? }) → Promise<boolean>
export function ConfirmDialog(opts = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; resolve(v); m.close(); };
    const m = Modal({ title: opts.title || 'Are you sure?', size: 'sm', dismissable: true, onClose: () => finish(false) });
    m.el.innerHTML = `<div style="font-size:14px;opacity:.8;margin-bottom:18px">${esc(opts.message || '')}</div>
      <div style="display:flex;justify-content:flex-end;gap:8px">
        <button data-cancel style="padding:8px 14px;border-radius:8px;border:1px solid rgba(128,128,128,.3);background:none;cursor:pointer;font-size:14px">${esc(opts.cancelLabel || 'Cancel')}</button>
        <button data-ok style="padding:8px 14px;border-radius:8px;border:none;cursor:pointer;font-size:14px;color:#fff;background:${opts.danger ? '#dc2626' : 'var(--bm-accent,#2563eb)'}">${esc(opts.confirmLabel || 'Confirm')}</button></div>`;
    m.el.querySelector('[data-cancel]').addEventListener('click', () => finish(false));
    m.el.querySelector('[data-ok]').addEventListener('click', () => finish(true));
  });
}

// DiffViewer(target, { before, after, fields? }) - highlight changed keys.
export function DiffViewer(target, opts) {
  const el = resolveEl(target);
  const before = opts.before || {}, after = opts.after || {};
  const keys = opts.fields || [...new Set([...Object.keys(before), ...Object.keys(after)])];
  const fmt = (v) => v === undefined ? '∅' : esc(typeof v === 'object' ? JSON.stringify(v) : String(v));
  const rows = keys.map((k) => {
    if (JSON.stringify(before[k]) === JSON.stringify(after[k])) return '';
    return `<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid rgba(128,128,128,.1)"><span style="width:130px;opacity:.6;flex-shrink:0">${esc(k)}</span><span style="background:rgba(220,38,38,.12);color:#b91c1c;padding:0 5px;border-radius:3px;text-decoration:line-through">${fmt(before[k])}</span><span style="opacity:.4">→</span><span style="background:rgba(22,163,74,.12);color:#15803d;padding:0 5px;border-radius:3px">${fmt(after[k])}</span></div>`;
  }).join('');
  el.innerHTML = `<div data-bm-diff style="font-family:ui-monospace,Menlo,monospace;font-size:12.5px">${rows || '<div style="opacity:.5">No changes.</div>'}</div>`;
  return { destroy: () => { el.innerHTML = ''; } };
}

// SegmentedControl(target, { options, value?, onChange }) - pill toggle.
export function SegmentedControl(target, opts) {
  const el = resolveEl(target);
  const options = (opts.options || []).map((o) => (typeof o === 'string' ? { value: o, label: o } : o));
  let val = opts.value ?? (options[0] && options[0].value);
  const draw = () => {
    el.innerHTML = `<div data-bm-segmented style="display:inline-flex;background:rgba(128,128,128,.12);border-radius:8px;padding:2px">` + options.map((o) => `<button data-v="${esc(o.value)}" style="padding:6px 14px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500;color:inherit;background:${o.value === val ? 'var(--card,#fff)' : 'transparent'};box-shadow:${o.value === val ? '0 1px 2px rgba(0,0,0,.12)' : 'none'}">${esc(o.label)}</button>`).join('') + `</div>`;
    el.querySelectorAll('[data-v]').forEach((b) => b.addEventListener('click', () => { val = b.getAttribute('data-v'); draw(); if (opts.onChange) opts.onChange(val); }));
  };
  draw();
  return { get value() { return val; }, set: (v) => { val = v; draw(); }, destroy: () => { el.innerHTML = ''; } };
}

// DateRangePicker(target, { from?, to?, onChange }) → { value, destroy }
export function DateRangePicker(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-daterange style="display:inline-flex;align-items:center;gap:8px"><input data-from type="date" value="${esc(opts.from || '')}" class="${inputCls}" style="width:auto"><span style="opacity:.5">→</span><input data-to type="date" value="${esc(opts.to || '')}" class="${inputCls}" style="width:auto"></div>`;
  const from = el.querySelector('[data-from]'), to = el.querySelector('[data-to]');
  const emit = () => opts.onChange && opts.onChange({ from: from.value, to: to.value });
  from.addEventListener('change', emit); to.addEventListener('change', emit);
  return { get value() { return { from: from.value, to: to.value }; }, destroy: () => { el.innerHTML = ''; } };
}

// Gauge(target, { value, min?, max?, threshold?, label?, unit?, color?, format? }) - radial.
export function Gauge(target, opts) {
  const el = resolveEl(target);
  const min = opts.min || 0, max = opts.max || 100;
  const arc = Math.PI * 56; // semicircle of r=56
  const draw = (value) => {
    const pct = Math.max(0, Math.min(1, (value - min) / (max - min)));
    const off = arc * (1 - pct);
    const col = opts.color || (opts.threshold != null ? (value >= opts.threshold ? '#16a34a' : '#dc2626') : 'var(--bm-accent,#2563eb)');
    el.innerHTML = `<div data-bm-gauge style="text-align:center"><svg width="150" height="86" viewBox="0 0 150 86"><path d="M19 78 A56 56 0 0 1 131 78" fill="none" stroke="rgba(128,128,128,.2)" stroke-width="12" stroke-linecap="round"/><path d="M19 78 A56 56 0 0 1 131 78" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${arc}" stroke-dashoffset="${off}" style="transition:stroke-dashoffset .4s"/></svg><div style="font-size:22px;font-weight:600;margin-top:-28px" class="tabular-nums">${esc(opts.format ? opts.format(value) : value)}${opts.unit || ''}</div>${opts.label ? `<div style="font-size:12px;opacity:.6;margin-top:6px">${esc(opts.label)}</div>` : ''}</div>`;
  };
  draw(opts.value || 0);
  return { set: draw, destroy: () => { el.innerHTML = ''; } };
}

// DetailHeader(target, { title, subtitle?, meta?, badge?, actions? })
export function DetailHeader(target, opts) {
  const el = resolveEl(target);
  const actions = (opts.actions || []).map((a, i) => `<button data-a="${i}" style="padding:8px 14px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500;border:${a.variant === 'primary' ? 'none' : '1px solid rgba(128,128,128,.3)'};background:${a.variant === 'primary' ? 'var(--bm-accent,#2563eb)' : 'transparent'};color:${a.variant === 'primary' ? '#fff' : (a.danger ? '#dc2626' : 'inherit')}">${esc(a.label)}</button>`).join('');
  const meta = (opts.meta || []).map((mm) => `<span style="font-size:13px;opacity:.6">${esc(mm)}</span>`).join('<span style="opacity:.3">·</span>');
  const badge = opts.badge ? Badge(opts.badge.label || opts.badge, { variant: opts.badge.variant }) : '';
  el.innerHTML = `<div data-bm-detailheader style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap">
    <div><div style="display:flex;align-items:center;gap:10px"><h1 style="font-size:20px;font-weight:600;margin:0">${esc(opts.title || '')}</h1>${badge}</div>
    ${opts.subtitle ? `<div style="font-size:14px;opacity:.6;margin-top:2px">${esc(opts.subtitle)}</div>` : ''}
    ${meta ? `<div style="display:flex;gap:8px;align-items:center;margin-top:8px">${meta}</div>` : ''}</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">${actions}</div></div>`;
  (opts.actions || []).forEach((a, i) => el.querySelector(`[data-a="${i}"]`)?.addEventListener('click', () => a.onClick && a.onClick()));
  return { destroy: () => { el.innerHTML = ''; } };
}

// SplitLayout(target, { leftWidth?, gap? }) → { left, right, destroy } - master/detail panes.
export function SplitLayout(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-split style="display:flex;gap:${opts.gap || '20px'};align-items:flex-start"><div data-left style="width:${opts.leftWidth || '320px'};flex-shrink:0"></div><div data-right style="flex:1;min-width:0"></div></div>`;
  return { left: el.querySelector('[data-left]'), right: el.querySelector('[data-right]'), destroy: () => { el.innerHTML = ''; } };
}

// Map(target, { lat, lng, zoom?, markers?, height?, label? }) - Leaflet + OSM tiles.
// Needs the app CSP to allow unpkg.com (script/style) + *.tile.openstreetmap.org (img).
let _leafletLoading = null;
function loadLeaflet() {
  if (typeof window !== 'undefined' && window.L) return Promise.resolve(window.L);
  if (!_leafletLoading) _leafletLoading = new Promise((res, rej) => {
    const css = document.createElement('link'); css.rel = 'stylesheet'; css.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'; document.head.appendChild(css);
    const sc = document.createElement('script'); sc.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'; sc.onload = () => res(window.L); sc.onerror = () => rej(new Error('failed to load Leaflet (CSP must allow unpkg.com)')); document.head.appendChild(sc);
  });
  return _leafletLoading;
}
// NB: named MapView, NOT Map - a top-level `function Map` would shadow the
// global Map constructor across this whole module and break every `new Map()`
// ("Map is not a constructor"). Re-exported as `Map` below for the public API.
export async function MapView(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-map style="height:${opts.height || '300px'};border-radius:10px;overflow:hidden"></div>`;
  const host = el.querySelector('[data-bm-map]');
  let map = null;
  try {
    const L = await loadLeaflet();
    map = L.map(host).setView([opts.lat ?? 0, opts.lng ?? 0], opts.zoom || 11);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '© OpenStreetMap', maxZoom: 19 }).addTo(map);
    const markers = opts.markers || (opts.lat != null ? [{ lat: opts.lat, lng: opts.lng, label: opts.label }] : []);
    markers.forEach((mk) => { const m = L.marker([mk.lat, mk.lng]).addTo(map); if (mk.label) m.bindPopup(String(mk.label)); });
    setTimeout(() => map.invalidateSize(), 120);
  } catch (ex) { host.innerHTML = skin.emptyState('Map unavailable: ' + (ex?.message || '')); }
  return { map, destroy: () => { try { map && map.remove(); } catch (_) {} el.innerHTML = ''; } };
}
// Public name is `Map`; the impl is MapView so it doesn't shadow global Map.
export { MapView as Map };

// MoneyInput / PercentInput - affixed number fields (currency / percent inputs).
export function MoneyInput(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-money style="position:relative;display:inline-block"><span style="position:absolute;left:10px;top:50%;transform:translateY(-50%);opacity:.6;pointer-events:none">${esc(opts.currency || '$')}</span><input type="number" step="0.01" value="${esc(opts.value ?? '')}" class="${inputCls}" style="padding-left:24px;width:${opts.width || '170px'}"></div>`;
  const inp = el.querySelector('input');
  inp.addEventListener('input', () => opts.onChange && opts.onChange(inp.value === '' ? null : Number(inp.value)));
  return { get value() { return inp.value === '' ? null : Number(inp.value); }, destroy: () => { el.innerHTML = ''; } };
}
export function PercentInput(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-pct style="position:relative;display:inline-block"><input type="number" step="0.1" value="${esc(opts.value ?? '')}" class="${inputCls}" style="padding-right:24px;width:${opts.width || '120px'}"><span style="position:absolute;right:10px;top:50%;transform:translateY(-50%);opacity:.6;pointer-events:none">%</span></div>`;
  const inp = el.querySelector('input');
  inp.addEventListener('input', () => opts.onChange && opts.onChange(inp.value === '' ? null : Number(inp.value)));
  return { get value() { return inp.value === '' ? null : Number(inp.value); }, destroy: () => { el.innerHTML = ''; } };
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 6 - schedule + checklist primitives (gantt / data-room)
// ═══════════════════════════════════════════════════════════════════

// GanttChart(target, { items?|table, labelField?, startField?, endField?,
//   colorField?, where?, onClick?, labelWidth? }) - bars on a date axis.
// items: [{ id?, label, start, end, color? }]. Live-refreshes when table-driven.
export async function GanttChart(target, opts) {
  const el = resolveEl(target);
  const LABELW = opts.labelWidth || 150;
  const toItems = async () => {
    if (opts.items) return opts.items;
    if (!opts.table) return [];
    const rows = await listRows(opts.table, { limit: opts.limit || 200, where: opts.where });
    const lf = opts.labelField || 'name', sf = opts.startField || 'start', ef = opts.endField || 'end';
    return rows.map((r) => ({ id: r.id, label: r[lf], start: r[sf], end: r[ef], color: opts.colorField ? r[opts.colorField] : undefined }));
  };
  // Persisted collapse state for parents with children (keyed by storageKey/table).
  const COLLAPSE_KEY = `bm:gantt:${opts.storageKey || opts.table || 'g'}`;
  let collapsed = new Set();
  try { collapsed = new Set(JSON.parse(localStorage.getItem(COLLAPSE_KEY) || '[]')); } catch (_) {}
  const saveCollapsed = () => { try { localStorage.setItem(COLLAPSE_KEY, JSON.stringify([...collapsed])); } catch (_) {} };

  const render = async () => {
    // null/''/undefined → NaN (NOT the 1970 epoch new Date(null) yields).
    const parseDate = (v) => { if (v == null || v === '') return NaN; const t = new Date(v).getTime(); return isNaN(t) ? NaN : t; };
    const parseKids = (it) => (it.children || []).map((c) => { const s = parseDate(c.start); let e = parseDate(c.end); if (isNaN(e)) e = s; return { ...c, s, e }; }).filter((c) => !isNaN(c.s));
    const items = (await toItems()).map((it) => { const s = parseDate(it.start); let e = parseDate(it.end); if (isNaN(e)) e = s; return { ...it, s, e, kids: parseKids(it) }; }).filter((it) => !isNaN(it.s));
    if (!items.length) { el.innerHTML = skin.emptyState('No scheduled dates to plot - set start/end dates on these rows.'); return; }
    // Domain over parents AND children so nothing overflows the track.
    const ts = []; items.forEach((it) => { ts.push(it.s, it.e); it.kids.forEach((c) => ts.push(c.s, c.e)); });
    let min = Math.min(...ts), max = Math.max(...ts);
    if (max <= min) max = min + 86400000 * 30;
    // Snap the axis to month boundaries so ticks align with the data range
    // (was off-by-one: a mid-month min put the first tick at a negative %).
    const lo = new Date(min); lo.setHours(0, 0, 0, 0); lo.setDate(1); min = lo.getTime();
    const hi = new Date(max); hi.setHours(0, 0, 0, 0); hi.setDate(1); hi.setMonth(hi.getMonth() + 1); max = hi.getTime();
    const span = max - min || 1, pct = (t) => ((t - min) / span) * 100;
    const ticks = []; const d = new Date(min);
    while (d.getTime() <= max && ticks.length < 48) { ticks.push(new Date(d)); d.setMonth(d.getMonth() + 1); }
    const gridLines = ticks.map((t) => `<div style="position:absolute;left:${pct(t.getTime())}%;top:0;bottom:0;width:1px;background:rgba(128,128,128,.12)"></div>`).join('');
    // "Today" marker - a vertical line in every track (pointer-events:none so it
    // never blocks bar hovers) plus a distinct red pill in the header you can
    // hover for today's full date (opts.today !== false, default on).
    const now = Date.now();
    const showToday = opts.today !== false && now >= min && now <= max;
    const todayPct = pct(now);
    const todayStr = new Date(now).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
    const todayLine = showToday ? `<div style="position:absolute;left:${todayPct}%;top:0;bottom:0;width:2px;background:#ef4444;opacity:.6;pointer-events:none;z-index:1"></div>` : '';
    const grid = gridLines + todayLine;
    const head = ticks.map((t) => pct(t.getTime()) <= 100 ? `<div style="position:absolute;top:0;left:${pct(t.getTime())}%;font-size:10px;opacity:.5">${t.toLocaleDateString(undefined, { month: 'short' })}</div>` : '').join('')
      + (showToday ? `<div data-bar data-tip="${esc('Today · ' + todayStr)}" style="position:absolute;left:${todayPct}%;bottom:0;transform:translateX(-50%);background:#ef4444;color:#fff;font-size:9px;font-weight:600;line-height:1;padding:2px 6px;border-radius:8px;white-space:nowrap;cursor:help;z-index:2">Today</div>` : '');
    const fmtD = (t) => new Date(t).toLocaleDateString();
    const tip = (it) => opts.tooltip ? opts.tooltip(it) : `${it.label} · ${fmtD(it.s)} → ${fmtD(it.e)}`;
    const barRow = (it, i, sub, meta) => {
      const left = pct(it.s), width = Math.max(1.5, pct(it.e) - pct(it.s));
      const color = (typeof it.color === 'string' && it.color.startsWith('#')) ? it.color : _chartPalette[i % _chartPalette.length];
      const h = sub ? 22 : 30, bh = sub ? 11 : 18;
      const chevron = (meta && meta.hasKids) ? `<button data-toggle="${esc(meta.key)}" style="background:none;border:none;cursor:pointer;padding:0 5px 0 0;color:inherit;opacity:.55;font-size:11px;flex-shrink:0">${meta.collapsed ? '▸' : '▾'}</button>` : '';
      // Optional in-bar title: opts.barLabel === true → item.label; a function → custom string.
      const inBar = opts.barLabel ? (typeof opts.barLabel === 'function' ? esc(String(opts.barLabel(it) ?? '')) : esc(it.label)) : '';
      const barInner = inBar ? `<span style="position:absolute;inset:0;padding:0 6px;color:#fff;font-size:${sub ? 9 : 11}px;font-weight:500;line-height:${bh}px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;pointer-events:none;text-shadow:0 1px 1px rgba(0,0,0,.4)">${inBar}</span>` : '';
      return `<div style="display:flex;align-items:center;height:${h}px"><div style="width:${LABELW}px;flex-shrink:0;display:flex;align-items:center;font-size:${sub ? 11 : 12}px;${sub ? 'padding-left:16px;opacity:.7;' : ''}padding-right:10px">${chevron}<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${sub ? '└ ' : ''}${esc(it.label)}</span></div><div style="position:relative;flex:1;height:100%;overflow:hidden">${grid}<div data-bar ${sub ? '' : `data-i="${i}"`} data-tip="${esc(tip(it))}" style="position:absolute;top:6px;left:${left}%;width:${width}%;height:${bh}px;background:${color};border-radius:4px;min-width:6px;cursor:${(opts.onClick && !sub) ? 'pointer' : 'default'};opacity:${sub ? '.8' : '1'}">${barInner}</div></div></div>`;
    };
    const rows = items.map((it, i) => {
      const key = String(it.id ?? i), hasKids = it.kids.length > 0, isCol = collapsed.has(key);
      let html = barRow(it, i, false, { hasKids, collapsed: isCol, key });
      if (hasKids) html += `<div data-kids="${esc(key)}" ${isCol ? 'hidden' : ''}>${it.kids.map((c, j) => barRow(c, `${i}.${j}`, true)).join('')}</div>`;
      return html;
    }).join('');
    el.innerHTML = `<div data-bm-gantt style="font-size:12px"><div style="display:flex;height:24px;margin-bottom:2px"><div style="width:${LABELW}px;flex-shrink:0"></div><div style="position:relative;flex:1;overflow:hidden">${head}</div></div>${rows}</div>`;
    if (opts.onClick) el.querySelectorAll('[data-i]').forEach((b) => b.addEventListener('click', () => opts.onClick(items[Number(b.getAttribute('data-i'))])));
    // Collapse toggles (persisted).
    el.querySelectorAll('[data-toggle]').forEach((btn) => btn.addEventListener('click', (e) => {
      e.stopPropagation(); const k = btn.getAttribute('data-toggle');
      if (collapsed.has(k)) collapsed.delete(k); else collapsed.add(k);
      saveCollapsed();
      const kidsEl = el.querySelector(`[data-kids="${CSS.escape(k)}"]`); if (kidsEl) kidsEl.hidden = collapsed.has(k);
      btn.textContent = collapsed.has(k) ? '▸' : '▾';
    }));
    // Real hover tooltip (native title is slow/flaky); multi-line supported.
    const tipEl = document.createElement('div');
    tipEl.style.cssText = 'position:fixed;z-index:9999;background:#18181b;color:#fff;font-size:12px;padding:5px 9px;border-radius:6px;pointer-events:none;white-space:pre;display:none;box-shadow:0 4px 14px rgba(0,0,0,.3)';
    el.appendChild(tipEl);
    el.querySelectorAll('[data-bar]').forEach((b) => {
      b.addEventListener('mouseenter', () => { tipEl.textContent = b.getAttribute('data-tip'); tipEl.style.display = 'block'; });
      b.addEventListener('mousemove', (ev) => { tipEl.style.left = (ev.clientX + 12) + 'px'; tipEl.style.top = (ev.clientY + 14) + 'px'; });
      b.addEventListener('mouseleave', () => { tipEl.style.display = 'none'; });
    });
  };
  await render();
  let stop = null;
  if (opts.table) stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// Checklist(target, { items, onToggle?, onUpload?, title? }) - items:
// [{ label, done, required?, fileUrl?, hint?, group? }]. group → folder
// sections (the data-room pattern). Shows completion %. onUpload(item,file)
// should return a URL.
export function Checklist(target, opts) {
  const el = resolveEl(target);
  const items = opts.items || [];
  const render = () => {
    const total = items.length, done = items.filter((i) => i.done).length;
    const groups = {};
    items.forEach((it, idx) => { const g = it.group || ''; (groups[g] = groups[g] || []).push({ ...it, _i: idx }); });
    const row = (it) => `<div style="display:flex;align-items:center;gap:10px;padding:8px 4px;border-bottom:1px solid rgba(128,128,128,.1)">
      <input type="checkbox" ${it.done ? 'checked' : ''} data-toggle="${it._i}" style="width:16px;height:16px;accent-color:#16a34a;cursor:pointer">
      <div style="flex:1"><div style="font-size:13px;${it.done ? 'opacity:.55;text-decoration:line-through' : ''}">${esc(it.label)}${it.required ? ' <span style="color:#dc2626;font-size:11px">required</span>' : ''}</div>${it.hint ? `<div style="font-size:11px;opacity:.5">${esc(it.hint)}</div>` : ''}</div>
      ${it.fileUrl ? `<a href="${esc(it.fileUrl)}" target="_blank" rel="noopener" style="font-size:12px;color:var(--bm-accent,#2563eb)">view</a>` : (opts.onUpload ? `<button data-up="${it._i}" style="font-size:12px;color:var(--bm-accent,#2563eb);background:none;border:none;cursor:pointer">upload</button>` : '')}</div>`;
    el.innerHTML = `<div data-bm-checklist>${opts.title ? `<div style="font-weight:600;font-size:14px;margin-bottom:8px">${esc(opts.title)}</div>` : ''}<div style="margin-bottom:12px">${ProgressBar(total ? (done / total) * 100 : 0, { label: `${done}/${total} complete` })}</div>${Object.keys(groups).map((g) => `${g ? `<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;opacity:.5;margin:14px 0 2px">${esc(g)}</div>` : ''}${groups[g].map(row).join('')}`).join('')}</div>`;
    el.querySelectorAll('[data-toggle]').forEach((c) => c.addEventListener('change', () => { const i = Number(c.getAttribute('data-toggle')); items[i].done = c.checked; if (opts.onToggle) opts.onToggle(items[i], c.checked); render(); }));
    if (opts.onUpload) el.querySelectorAll('[data-up]').forEach((b) => b.addEventListener('click', () => {
      const i = Number(b.getAttribute('data-up')); const inp = document.createElement('input'); inp.type = 'file';
      inp.onchange = async () => { if (!inp.files || !inp.files[0]) return; try { const url = await opts.onUpload(items[i], inp.files[0]); if (url) { items[i].fileUrl = url; items[i].done = true; } render(); } catch (ex) { Toast(ex?.message || 'Upload failed', { type: 'error' }); } };
      inp.click();
    }));
  };
  render();
  return { destroy: () => { el.innerHTML = ''; } };
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 7 - forms, inputs & primitives (pure-UI / existing endpoints)
// ═══════════════════════════════════════════════════════════════════

// Combobox(target, { table?|options?, labelField?, value?, placeholder?, onChange })
// Typeahead select. table → server `?q=` search (scales past <select>'s ~200);
// options:[{value,label}] → client filter. onChange(value, row).
export async function Combobox(target, opts) {
  const el = resolveEl(target);
  let lf = opts.labelField;
  if (opts.table && !lf) { try { lf = labelField((await schema())[opts.table]); } catch (_) { lf = 'name'; } }
  let value = opts.value ?? '', label = '';
  el.innerHTML = `<div data-bm-combobox style="position:relative"><input data-cb type="text" placeholder="${esc(opts.placeholder || 'Search…')}" autocomplete="off" class="${inputCls}"><div data-cb-menu hidden style="position:absolute;left:0;right:0;z-index:50;margin-top:2px;max-height:240px;overflow:auto;background:var(--card,#fff);border:1px solid rgba(128,128,128,.2);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.15)"></div></div>`;
  const input = el.querySelector('[data-cb]'), menu = el.querySelector('[data-cb-menu]');
  const fetchRows = async (q) => {
    if (opts.options) { const ql = q.toLowerCase(); return opts.options.filter((o) => (o.label ?? o.value ?? o).toString().toLowerCase().includes(ql)).slice(0, 30).map((o) => ({ value: o.value ?? o, label: o.label ?? o.value ?? o })); }
    if (opts.table) { const rows = await listRows(opts.table, { q: q || undefined, limit: 20, where: opts.where }); return rows.map((r) => ({ value: r.id, label: r[lf] ?? r.id, row: r })); }
    return [];
  };
  const close = () => { menu.hidden = true; };
  const draw = (rows) => {
    menu.innerHTML = rows.length ? rows.map((r, i) => `<div data-i="${i}" style="padding:8px 12px;cursor:pointer;font-size:14px">${esc(r.label)}</div>`).join('') : `<div style="padding:8px 12px;font-size:13px;opacity:.5">No matches</div>`;
    menu.hidden = false;
    menu.querySelectorAll('[data-i]').forEach((d) => d.addEventListener('mousedown', (e) => { e.preventDefault(); const r = rows[+d.getAttribute('data-i')]; value = r.value; label = r.label; input.value = label; close(); if (opts.onChange) opts.onChange(value, r.row); }));
  };
  let t;
  input.addEventListener('input', () => { clearTimeout(t); t = setTimeout(async () => draw(await fetchRows(input.value.trim())), 200); });
  input.addEventListener('focus', async () => draw(await fetchRows(input.value.trim())));
  input.addEventListener('blur', () => setTimeout(close, 150));
  return { get value() { return value; }, destroy: () => { el.innerHTML = ''; } };
}

// MultiSelect(target, { table?|options?, value?:[], labelField?, onChange }) - tag-style multi-pick.
export async function MultiSelect(target, opts) {
  const el = resolveEl(target);
  let lf = opts.labelField;
  if (opts.table && !lf) { try { lf = labelField((await schema())[opts.table]); } catch (_) { lf = 'name'; } }
  const picked = new Map(); // value → label
  (opts.value || []).forEach((v) => picked.set(String(v), String(v)));
  el.innerHTML = `<div data-bm-multiselect><div data-chips style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px"></div><div data-cb-host></div></div>`;
  const chips = el.querySelector('[data-chips]');
  const drawChips = () => { chips.innerHTML = [...picked].map(([v, l]) => `<span style="display:inline-flex;align-items:center;gap:6px;padding:3px 6px 3px 10px;border-radius:9999px;background:rgba(37,99,235,.12);color:#1d4ed8;font-size:13px">${esc(l)}<button data-rm="${esc(v)}" style="background:none;border:none;cursor:pointer;color:inherit;font-weight:700">×</button></span>`).join('') || '<span style="font-size:13px;opacity:.5">None selected</span>'; chips.querySelectorAll('[data-rm]').forEach((b) => b.addEventListener('click', () => { picked.delete(b.getAttribute('data-rm')); drawChips(); emit(); })); };
  const emit = () => opts.onChange && opts.onChange([...picked.keys()]);
  await Combobox(el.querySelector('[data-cb-host]'), { table: opts.table, options: opts.options, labelField: lf, where: opts.where, placeholder: opts.placeholder || 'Add…', onChange: (v, row) => { picked.set(String(v), row ? String(row[lf] ?? v) : String(v)); drawChips(); emit(); el.querySelector('[data-cb] ')?.blur?.(); } });
  drawChips();
  return { get value() { return [...picked.keys()]; }, destroy: () => { el.innerHTML = ''; } };
}

// Switch(target, { checked?, label?, onChange }) → { checked, destroy }
export function Switch(target, opts = {}) {
  const el = resolveEl(target);
  let on = !!opts.checked;
  const draw = () => { el.innerHTML = `<label style="display:inline-flex;align-items:center;gap:10px;cursor:pointer"><span data-sw style="width:38px;height:22px;border-radius:9999px;background:${on ? 'var(--bm-accent,#2563eb)' : 'rgba(128,128,128,.35)'};position:relative;transition:background .15s"><span style="position:absolute;top:2px;left:${on ? 18 : 2}px;width:18px;height:18px;border-radius:50%;background:#fff;transition:left .15s;box-shadow:0 1px 2px rgba(0,0,0,.3)"></span></span>${opts.label ? `<span style="font-size:14px">${esc(opts.label)}</span>` : ''}</label>`; el.querySelector('[data-sw]').parentElement.addEventListener('click', () => { on = !on; draw(); if (opts.onChange) opts.onChange(on); }); };
  draw();
  return { get checked() { return on; }, destroy: () => { el.innerHTML = ''; } };
}

// Slider(target, { min?, max?, step?, value?, label?, onChange }) → { value, destroy }
export function Slider(target, opts = {}) {
  const el = resolveEl(target);
  const min = opts.min ?? 0, max = opts.max ?? 100;
  el.innerHTML = `<div data-bm-slider><div style="display:flex;justify-content:space-between;font-size:12px;opacity:.6;margin-bottom:4px"><span>${esc(opts.label || '')}</span><span data-val>${esc(opts.value ?? min)}</span></div><input type="range" min="${min}" max="${max}" step="${opts.step ?? 1}" value="${opts.value ?? min}" style="width:100%;accent-color:var(--bm-accent,#2563eb)"></div>`;
  const input = el.querySelector('input'), val = el.querySelector('[data-val]');
  input.addEventListener('input', () => { val.textContent = input.value; if (opts.onChange) opts.onChange(Number(input.value)); });
  return { get value() { return Number(input.value); }, destroy: () => { el.innerHTML = ''; } };
}

// Rating(target, { value?, max?, onChange }) → { value, destroy }
export function Rating(target, opts = {}) {
  const el = resolveEl(target);
  const max = opts.max || 5; let value = opts.value || 0;
  const draw = () => { el.innerHTML = `<div data-bm-rating style="display:inline-flex;gap:2px;font-size:22px;cursor:pointer">${Array.from({ length: max }, (_, i) => `<span data-s="${i + 1}" style="color:${i < value ? '#f59e0b' : 'rgba(128,128,128,.35)'}">★</span>`).join('')}</div>`; el.querySelectorAll('[data-s]').forEach((s) => s.addEventListener('click', () => { value = Number(s.getAttribute('data-s')); draw(); if (opts.onChange) opts.onChange(value); })); };
  draw();
  return { get value() { return value; }, destroy: () => { el.innerHTML = ''; } };
}

// ColorPicker(target, { value?, onChange }) → { value, destroy }
export function ColorPicker(target, opts = {}) {
  const el = resolveEl(target);
  const v = opts.value || 'var(--bm-accent,#2563eb)';
  el.innerHTML = `<div data-bm-colorpicker style="display:inline-flex;align-items:center;gap:8px"><input type="color" value="${esc(v)}" style="width:38px;height:34px;border:1px solid rgba(128,128,128,.3);border-radius:6px;background:none;cursor:pointer"><code data-hex style="font-size:13px">${esc(v)}</code></div>`;
  const input = el.querySelector('input'), hex = el.querySelector('[data-hex]');
  input.addEventListener('input', () => { hex.textContent = input.value; if (opts.onChange) opts.onChange(input.value); });
  return { get value() { return input.value; }, destroy: () => { el.innerHTML = ''; } };
}

// NumberStepper(target, { value?, min?, max?, step?, onChange }) → { value, destroy }
export function NumberStepper(target, opts = {}) {
  const el = resolveEl(target);
  let value = opts.value ?? 0; const step = opts.step ?? 1;
  const clamp = (n) => { if (opts.min != null) n = Math.max(opts.min, n); if (opts.max != null) n = Math.min(opts.max, n); return n; };
  const draw = () => { el.innerHTML = `<div data-bm-numberstepper style="display:inline-flex;align-items:center;border:1px solid rgba(128,128,128,.3);border-radius:8px;overflow:hidden"><button data-d="-1" style="padding:6px 12px;background:none;border:none;cursor:pointer;font-size:16px">−</button><input data-n type="number" value="${value}" style="width:60px;text-align:center;border:none;border-left:1px solid rgba(128,128,128,.2);border-right:1px solid rgba(128,128,128,.2);padding:6px 0;background:none;color:inherit"><button data-d="1" style="padding:6px 12px;background:none;border:none;cursor:pointer;font-size:16px">+</button></div>`; el.querySelectorAll('[data-d]').forEach((b) => b.addEventListener('click', () => { value = clamp(value + step * Number(b.getAttribute('data-d'))); draw(); if (opts.onChange) opts.onChange(value); })); el.querySelector('[data-n]').addEventListener('change', (e) => { value = clamp(Number(e.target.value) || 0); draw(); if (opts.onChange) opts.onChange(value); }); };
  draw();
  return { get value() { return value; }, destroy: () => { el.innerHTML = ''; } };
}

// Popover(target, { content, trigger? }) - floating panel anchored to target. → { open, close, destroy }
export function Popover(target, opts) {
  const el = resolveEl(target);
  if (getComputedStyle(el).position === 'static') el.style.position = 'relative';
  const pop = document.createElement('div');
  pop.hidden = true;
  pop.style.cssText = 'position:absolute;top:100%;left:0;z-index:60;margin-top:6px;min-width:180px;background:var(--card,#fff);border:1px solid rgba(128,128,128,.2);border-radius:10px;box-shadow:0 10px 28px rgba(0,0,0,.18);padding:12px';
  setContent(pop, opts.content); el.appendChild(pop);
  const onDoc = (e) => { if (!el.contains(e.target)) close(); };
  const open = () => { pop.hidden = false; setTimeout(() => document.addEventListener('click', onDoc), 0); };
  const close = () => { pop.hidden = true; document.removeEventListener('click', onDoc); };
  const trig = (e) => { e.stopPropagation(); pop.hidden ? open() : close(); };
  if ((opts.trigger || 'click') === 'hover') { el.addEventListener('mouseenter', open); el.addEventListener('mouseleave', close); }
  else el.addEventListener('click', trig);
  return { open, close, destroy: () => { pop.remove(); } };
}

// ContextMenu(target, { items }) - right-click menu. items:[{label,onClick,danger?,divider?}]
export function ContextMenu(target, opts) {
  const el = resolveEl(target);
  let menu = null;
  const close = () => { if (menu) { menu.remove(); menu = null; document.removeEventListener('click', close); } };
  const onCtx = (e) => {
    e.preventDefault(); close();
    menu = document.createElement('div');
    menu.style.cssText = `position:fixed;z-index:9999;left:${e.clientX}px;top:${e.clientY}px;min-width:170px;background:var(--card,#fff);border:1px solid rgba(128,128,128,.2);border-radius:8px;box-shadow:0 10px 28px rgba(0,0,0,.2);overflow:hidden;padding:4px 0`;
    menu.innerHTML = (opts.items || []).map((it, i) => it.divider ? '<div style="height:1px;background:rgba(128,128,128,.15);margin:4px 0"></div>' : `<button data-i="${i}" style="display:block;width:100%;text-align:left;padding:7px 14px;background:none;border:none;cursor:pointer;font-size:14px;color:${it.danger ? '#dc2626' : 'inherit'}">${esc(it.label)}</button>`).join('');
    document.body.appendChild(menu);
    menu.querySelectorAll('[data-i]').forEach((b) => b.addEventListener('click', () => { const it = opts.items[+b.getAttribute('data-i')]; close(); it.onClick && it.onClick(); }));
    setTimeout(() => document.addEventListener('click', close), 0);
  };
  el.addEventListener('contextmenu', onCtx);
  return { destroy: () => { el.removeEventListener('contextmenu', onCtx); close(); } };
}

// Carousel(target, { images:[{src,caption?}], auto?, lightbox? }) → { destroy }
export function Carousel(target, opts) {
  const el = resolveEl(target);
  const imgs = opts.images || []; let i = 0; let timer = null;
  const draw = () => {
    const im = imgs[i] || {};
    el.innerHTML = `<div data-bm-carousel style="position:relative;border-radius:10px;overflow:hidden;background:#000"><img src="${esc(im.src || '')}" alt="${esc(im.caption || '')}" style="width:100%;height:${opts.height || '320px'};object-fit:contain;display:block;cursor:${opts.lightbox ? 'zoom-in' : 'default'}">${im.caption ? `<div style="position:absolute;bottom:0;left:0;right:0;padding:10px 14px;background:linear-gradient(transparent,rgba(0,0,0,.6));color:#fff;font-size:13px">${esc(im.caption)}</div>` : ''}<button data-prev style="position:absolute;left:8px;top:50%;transform:translateY(-50%);background:rgba(0,0,0,.4);color:#fff;border:none;border-radius:9999px;width:34px;height:34px;cursor:pointer;font-size:18px">‹</button><button data-next style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:rgba(0,0,0,.4);color:#fff;border:none;border-radius:9999px;width:34px;height:34px;cursor:pointer;font-size:18px">›</button><div style="position:absolute;bottom:8px;left:50%;transform:translateX(-50%);display:flex;gap:6px">${imgs.map((_, j) => `<span style="width:7px;height:7px;border-radius:50%;background:${j === i ? '#fff' : 'rgba(255,255,255,.4)'}"></span>`).join('')}</div></div>`;
    el.querySelector('[data-prev]').addEventListener('click', () => { i = (i - 1 + imgs.length) % imgs.length; draw(); });
    el.querySelector('[data-next]').addEventListener('click', () => { i = (i + 1) % imgs.length; draw(); });
    if (opts.lightbox) el.querySelector('img').addEventListener('click', () => Lightbox(imgs, i));
  };
  if (imgs.length) draw(); else el.innerHTML = skin.emptyState('No images.');
  if (opts.auto && imgs.length > 1) timer = setInterval(() => { i = (i + 1) % imgs.length; draw(); }, opts.auto);
  return { destroy: () => { if (timer) clearInterval(timer); el.innerHTML = ''; } };
}
// Lightbox(images, start) - fullscreen image viewer overlay.
export function Lightbox(images, start = 0) {
  let i = start;
  const back = document.createElement('div');
  back.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.9);display:flex;align-items:center;justify-content:center';
  const draw = () => { const im = images[i] || {}; back.innerHTML = `<button data-x style="position:absolute;top:16px;right:20px;background:none;border:none;color:#fff;font-size:28px;cursor:pointer">×</button><button data-p style="position:absolute;left:20px;color:#fff;background:none;border:none;font-size:34px;cursor:pointer">‹</button><img src="${esc(im.src || '')}" style="max-width:90vw;max-height:88vh;object-fit:contain"><button data-n style="position:absolute;right:20px;color:#fff;background:none;border:none;font-size:34px;cursor:pointer">›</button>${im.caption ? `<div style="position:absolute;bottom:20px;color:#fff;font-size:14px">${esc(im.caption)}</div>` : ''}`; back.querySelector('[data-x]').onclick = close; back.querySelector('[data-p]').onclick = () => { i = (i - 1 + images.length) % images.length; draw(); }; back.querySelector('[data-n]').onclick = () => { i = (i + 1) % images.length; draw(); }; };
  const close = () => { back.remove(); window.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); if (e.key === 'ArrowLeft') { i = (i - 1 + images.length) % images.length; draw(); } if (e.key === 'ArrowRight') { i = (i + 1) % images.length; draw(); } };
  draw(); back.addEventListener('mousedown', (e) => { if (e.target === back) close(); }); window.addEventListener('keydown', onKey); document.body.appendChild(back);
  return { close };
}

// Sortable(target, { items, onReorder }) - drag-to-reorder. items:[{id,label}] | string[]
export function Sortable(target, opts) {
  const el = resolveEl(target);
  let order = (opts.items || []).map((it, i) => (typeof it === 'string' ? { id: String(i), label: it } : it));
  const draw = () => {
    el.innerHTML = `<ul data-bm-sortable style="list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px">` + order.map((it) => `<li draggable="true" data-id="${esc(it.id)}" style="display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid rgba(128,128,128,.2);border-radius:8px;background:var(--card,#fff);cursor:grab;font-size:14px"><span style="opacity:.4">⋮⋮</span>${esc(it.label)}</li>`).join('') + `</ul>`;
    let dragId = null;
    el.querySelectorAll('[data-id]').forEach((li) => {
      li.addEventListener('dragstart', () => { dragId = li.getAttribute('data-id'); li.style.opacity = '.4'; });
      li.addEventListener('dragend', () => { li.style.opacity = '1'; });
      li.addEventListener('dragover', (e) => e.preventDefault());
      li.addEventListener('drop', (e) => { e.preventDefault(); const toId = li.getAttribute('data-id'); if (dragId === toId) return; const from = order.findIndex((x) => x.id === dragId), to = order.findIndex((x) => x.id === toId); const [m] = order.splice(from, 1); order.splice(to, 0, m); draw(); if (opts.onReorder) opts.onReorder(order.map((x) => x.id)); });
    });
  };
  draw();
  return { order: () => order.map((x) => x.id), destroy: () => { el.innerHTML = ''; } };
}

// Pagination(target, { page, perPage, total, onChange }) → { destroy }
export function Pagination(target, opts) {
  const el = resolveEl(target);
  const pages = Math.max(1, Math.ceil((opts.total || 0) / (opts.perPage || 10)));
  const cur = opts.page || 1;
  const btn = (p, label, disabled, active) => `<button data-p="${p}" ${disabled ? 'disabled' : ''} style="min-width:34px;padding:6px 10px;border-radius:7px;border:1px solid rgba(128,128,128,.25);background:${active ? 'var(--bm-accent,#2563eb)' : 'transparent'};color:${active ? '#fff' : 'inherit'};cursor:pointer;font-size:13px;${disabled ? 'opacity:.4' : ''}">${label}</button>`;
  const nums = []; const span = 2;
  for (let p = 1; p <= pages; p++) { if (p === 1 || p === pages || (p >= cur - span && p <= cur + span)) nums.push(p); else if (nums[nums.length - 1] !== '…') nums.push('…'); }
  el.innerHTML = `<div data-bm-pagination style="display:flex;gap:6px;align-items:center">${btn(cur - 1, '‹', cur <= 1)}${nums.map((p) => p === '…' ? '<span style="padding:0 4px;opacity:.5">…</span>' : btn(p, String(p), false, p === cur)).join('')}${btn(cur + 1, '›', cur >= pages)}</div>`;
  el.querySelectorAll('[data-p]').forEach((b) => b.addEventListener('click', () => { const p = Number(b.getAttribute('data-p')); if (p >= 1 && p <= pages && p !== cur && opts.onChange) opts.onChange(p); }));
  return { destroy: () => { el.innerHTML = ''; } };
}

// FileDropzone(target, { onUpload?, multiple?, accept? }) - drag-drop + click multi-upload via bm.upload.
export function FileDropzone(target, opts = {}) {
  const el = resolveEl(target);
  el.innerHTML = `<div data-bm-dropzone style="border:2px dashed rgba(128,128,128,.35);border-radius:10px;padding:28px;text-align:center;cursor:pointer;transition:border-color .15s"><div style="opacity:.4">${lucide('upload', 28)}</div><div style="font-size:14px;margin-top:6px">Drop files here or click to upload</div><div data-list style="margin-top:10px;display:flex;flex-direction:column;gap:4px;font-size:13px"></div><input type="file" ${opts.multiple !== false ? 'multiple' : ''} ${opts.accept ? `accept="${esc(opts.accept)}"` : ''} hidden></div>`;
  const zone = el.querySelector('[data-bm-dropzone]'), input = el.querySelector('input'), list = el.querySelector('[data-list]');
  const upload = async (files) => { for (const f of files) { const row = document.createElement('div'); row.textContent = `${f.name} - uploading…`; list.appendChild(row); try { const r = await bm.upload(f); row.textContent = `${f.name} ✓`; if (opts.onUpload) opts.onUpload(r, f); } catch (ex) { row.textContent = `${f.name} - failed`; } } };
  zone.addEventListener('click', () => input.click());
  input.addEventListener('change', () => input.files && upload([...input.files]));
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.style.borderColor = 'var(--bm-accent,#2563eb)'; });
  zone.addEventListener('dragleave', () => { zone.style.borderColor = ''; });
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.style.borderColor = ''; if (e.dataTransfer.files) upload([...e.dataTransfer.files]); });
  return { destroy: () => { el.innerHTML = ''; } };
}

// Kbd(keys) / Sparkline(values) - atoms (HTML strings).
export function Kbd(keys) {
  const parts = Array.isArray(keys) ? keys : String(keys).split('+');
  return parts.map((k) => `<kbd style="display:inline-block;padding:2px 6px;border-radius:5px;border:1px solid rgba(128,128,128,.3);border-bottom-width:2px;background:rgba(128,128,128,.08);font-family:ui-monospace,Menlo,monospace;font-size:11px;line-height:1.4">${esc(k.trim())}</kbd>`).join(' ');
}
export function Sparkline(values, opts = {}) {
  const vals = (values || []).map(Number).filter((n) => isFinite(n));
  if (!vals.length) return '';
  const w = opts.width || 100, h = opts.height || 24, max = Math.max(...vals), min = Math.min(...vals), span = max - min || 1;
  const pts = vals.map((v, i) => `${(i / (vals.length - 1 || 1)) * w},${h - ((v - min) / span) * (h - 2) - 1}`).join(' ');
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" style="vertical-align:middle"><polyline fill="none" stroke="${esc(opts.color || 'var(--bm-accent,#2563eb)')}" stroke-width="1.5" points="${pts}"/></svg>`;
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 8 - RBAC · security · data ops (over real RBAC/auth endpoints)
// ═══════════════════════════════════════════════════════════════════

// PermissionMatrix(target) - read-only roles × scopes grid (GET /api/_auth/roles).
export async function PermissionMatrix(target, opts = {}) {
  const el = resolveEl(target);
  let roles = [];
  try { const r = await bm.api.get('/api/_auth/roles'); roles = r.roles || r || []; } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'No roles access.'); return { destroy: () => { el.innerHTML = ''; } }; }
  // scopes come back as a space-separated STRING ("contacts:read contacts:write"),
  // not an array - split before treating as a list.
  const scopeList = (r) => { const v = r.effective_scopes ?? r.scopes ?? ''; return (Array.isArray(v) ? v : String(v).split(/\s+/)).filter(Boolean); };
  const scopeSet = new Set();
  roles.forEach((r) => scopeList(r).forEach((s) => scopeSet.add(s)));
  const allWild = (r) => scopeList(r).includes('*');
  const cols = [...scopeSet].filter((s) => s !== '*').sort();
  const head = `<tr><th style="text-align:left;padding:8px 10px;font-size:11px;text-transform:uppercase;opacity:.6">Role</th>${cols.map((c) => `<th style="padding:8px 6px;font-size:10px;writing-mode:vertical-rl;transform:rotate(180deg);white-space:nowrap;opacity:.6">${esc(c)}</th>`).join('')}</tr>`;
  const body = roles.map((r) => { const has = new Set(scopeList(r)); const wild = allWild(r); return `<tr><td style="padding:8px 10px;font-weight:600;font-size:13px;border-top:1px solid rgba(128,128,128,.12)">${esc(r.name)}${wild ? ' <span style="font-size:10px;opacity:.5">(all)</span>' : ''}</td>${cols.map((c) => `<td style="text-align:center;padding:8px 6px;border-top:1px solid rgba(128,128,128,.12)">${wild || has.has(c) ? '<span style="color:#16a34a">●</span>' : '<span style="opacity:.2">·</span>'}</td>`).join('')}</tr>`; }).join('');
  el.innerHTML = `<div data-bm-permmatrix style="overflow-x:auto"><table style="border-collapse:collapse;font-size:13px"><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
  return { destroy: () => { el.innerHTML = ''; } };
}

// TeamManager(target) - users + grant/revoke roles (RBAC join-table endpoints).
export async function TeamManager(target, opts = {}) {
  const el = resolveEl(target);
  const render = async () => {
    let users = [], roleDefs = [];
    try { users = await bm.users.list({ limit: 100 }); } catch (_) {}
    try { const r = await bm.api.get('/api/_auth/roles'); roleDefs = (r.roles || r || []).map((x) => x.name); } catch (_) {}
    const rolesFor = async (id) => { try { const r = await bm.api.get(`/api/_auth/users/${id}/roles`); return (r.roles || r || []).map((x) => x.role || x.name || x); } catch (_) { return []; } };
    const rows = await Promise.all(users.map(async (u) => ({ u, roles: await rolesFor(u.id) })));
    el.innerHTML = `<div data-bm-teammanager class="space-y-2">` + rows.map(({ u, roles }) => `<div style="display:flex;align-items:center;gap:10px;justify-content:space-between;border:1px solid rgba(128,128,128,.2);border-radius:8px;padding:10px 12px">
      <div style="display:flex;align-items:center;gap:10px;min-width:0"><span>${Avatar({ name: u.email || u.username, src: u.avatar_url || undefined, size: 28 })}</span><span style="font-size:13px;overflow:hidden;text-overflow:ellipsis">${esc(u.email || u.username)}</span></div>
      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">${roles.map((rl) => `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 6px 2px 9px;border-radius:9999px;background:rgba(37,99,235,.12);color:#1d4ed8;font-size:12px">${esc(rl)}<button data-revoke="${esc(u.id)}|${esc(rl)}" style="background:none;border:none;cursor:pointer;color:inherit;font-weight:700">×</button></span>`).join('')}<select data-grant="${esc(u.id)}" class="${inputCls}" style="width:auto;font-size:12px;padding:4px 8px"><option value="">+ role</option>${roleDefs.filter((rd) => !roles.includes(rd)).map((rd) => `<option value="${esc(rd)}">${esc(rd)}</option>`).join('')}</select></div></div>`).join('') + `</div>`;
    el.querySelectorAll('[data-revoke]').forEach((b) => b.addEventListener('click', async () => { const [id, role] = b.getAttribute('data-revoke').split('|'); try { await bm.api.delete(`/api/_auth/users/${id}/roles/${encodeURIComponent(role)}`); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
    el.querySelectorAll('[data-grant]').forEach((s) => s.addEventListener('change', async () => { if (!s.value) return; try { await bm.api.post(`/api/_auth/users/${s.getAttribute('data-grant')}/roles`, { role: s.value }); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } }));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}

// StepUp({ title?, message? }) → Promise<boolean> - re-auth confirm (verify the
// signed-in user's password via the token endpoint) before a sensitive action.
export async function StepUp(opts = {}) {
  const me = await currentUser();
  const email = me?.email;
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; resolve(v); m.close(); };
    const m = Modal({ title: opts.title || 'Confirm it\'s you', size: 'sm', dismissable: true, onClose: () => finish(false) });
    m.el.innerHTML = `<div style="font-size:14px;opacity:.8;margin-bottom:12px">${esc(opts.message || 'Re-enter your password to continue.')}</div><form data-su class="space-y-3">${skin.error('')}${skinField('password', 'Password', { type: 'password', required: true })}<div style="display:flex;justify-content:flex-end;gap:8px"><button type="button" data-cancel style="padding:8px 14px;border-radius:8px;border:1px solid rgba(128,128,128,.3);background:none;cursor:pointer;font-size:14px">Cancel</button>${skin.button({ label: 'Confirm' })}</div></form>`;
    const form = m.el.querySelector('form'), errEl = m.el.querySelector('[data-bm-error]');
    m.el.querySelector('[data-cancel]').addEventListener('click', () => finish(false));
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); errEl.hidden = true;
      const res = await bm.api.raw.post('/api/_auth/token', { email, password: new FormData(form).get('password') });
      if (res.ok) finish(true);
      else { errEl.textContent = 'Incorrect password'; errEl.hidden = false; }
    });
  });
}

// SensitiveReveal(target, { label?, value?, reveal?, stepUp?, log? }) - masked field
// that reveals on click (optionally behind StepUp). `reveal` supplies the real value.
export async function SensitiveReveal(target, opts) {
  const el = resolveEl(target);
  let shown = false, val = opts.value;
  const draw = () => {
    el.innerHTML = `<span data-bm-sensitive style="display:inline-flex;align-items:center;gap:8px;font-family:ui-monospace,Menlo,monospace;font-size:14px"><span>${shown ? esc(val ?? '-') : '••••••'}</span><button data-t style="font-size:12px;color:var(--bm-accent,#2563eb);background:none;border:none;cursor:pointer">${shown ? 'hide' : 'reveal'}</button></span>`;
    el.querySelector('[data-t]').addEventListener('click', async () => {
      if (shown) { shown = false; draw(); return; }
      if (opts.stepUp && !(await StepUp({ title: 'Reveal sensitive data', message: opts.stepUpMessage }))) return;
      if (val === undefined && opts.reveal) { try { val = await opts.reveal(); } catch (ex) { Toast(ex?.message || 'Reveal failed', { type: 'error' }); return; } }
      if (opts.log) { try { opts.log(); } catch (_) {} }
      shown = true; draw();
    });
  };
  draw();
  return { destroy: () => { el.innerHTML = ''; } };
}

// ImpersonationBanner(target?) - fixed banner shown while acting as another group/user.
export async function ImpersonationBanner(target, opts = {}) {
  let state = {};
  try { state = await bm.api.get('/api/_auth/act_as'); } catch (_) {}
  const acting = state && (state.acting_as_group || state.is_impersonation);
  if (!acting) return { destroy: () => {} };
  const bar = document.createElement('div');
  bar.setAttribute('data-bm-impersonation', '');
  bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9997;background:#b45309;color:#fff;font-size:13px;padding:8px 16px;display:flex;align-items:center;justify-content:center;gap:12px';
  bar.innerHTML = `<span style="display:inline-flex;align-items:center;gap:6px">${lucide('alert-triangle', 15)} Acting as ${esc(state.acting_as_group ? 'group ' + state.acting_as_group : 'another user')}</span><button data-exit style="background:rgba(255,255,255,.25);color:#fff;border:none;border-radius:6px;padding:3px 10px;cursor:pointer;font-weight:600">Exit</button>`;
  document.body.appendChild(bar);
  document.body.style.paddingTop = (bar.offsetHeight || 34) + 'px';
  bar.querySelector('[data-exit]').addEventListener('click', async () => { try { await bm.api.delete('/api/_auth/act_as'); } catch (_) {} try { await bm.api.post('/api/_auth/end-impersonation'); } catch (_) {} location.reload(); });
  return { destroy: () => { bar.remove(); document.body.style.paddingTop = ''; } };
}

// ModuleGate(target, { module, enabled }) - hide target unless module is enabled.
// enabled: string[] of enabled modules, or () => Promise<string[]>.
export async function ModuleGate(target, opts) {
  const el = resolveEl(target);
  let enabled = opts.enabled;
  if (typeof enabled === 'function') { try { enabled = await enabled(); } catch (_) { enabled = []; } }
  const ok = Array.isArray(enabled) ? enabled.includes(opts.module) : true;
  if (ok) el.removeAttribute('hidden'); else el.setAttribute('hidden', '');
  return ok;
}

// ExportButton(target, { table, columns?, where?, filename?, label? }) - rows → CSV download.
export function ExportButton(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<button data-bm-export class="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 text-sm font-medium">${lucide('download', 16)} ${esc(opts.label || 'Export CSV')}</button>`;
  el.querySelector('button').addEventListener('click', async () => {
    const btn = el.querySelector('button'); const txt = btn.textContent; btn.textContent = 'Exporting…'; btn.disabled = true;
    try {
      const rows = await listRows(opts.table, { limit: opts.limit || 5000, where: opts.where });
      const cols = opts.columns ? opts.columns.split(',').map((c) => c.trim()) : (rows.length ? Object.keys(rows[0]) : []);
      const escCsv = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
      const csv = [cols.join(','), ...rows.map((r) => cols.map((c) => escCsv(r[c])).join(','))].join('\n');
      const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = opts.filename || (opts.table + '.csv'); a.click(); URL.revokeObjectURL(a.href);
    } catch (ex) { Toast(ex?.message || 'Export failed', { type: 'error' }); }
    btn.textContent = txt; btn.disabled = false;
  });
  return { destroy: () => { el.innerHTML = ''; } };
}

// ColumnChooser(target, { columns, value?, onChange }) - toggle visible columns.
export function ColumnChooser(target, opts) {
  const el = resolveEl(target);
  const cols = (opts.columns || []).map((c) => (typeof c === 'string' ? { name: c, label: humanize(c) } : c));
  const sel = new Set(opts.value || cols.map((c) => c.name));
  el.innerHTML = `<div data-bm-columnchooser style="display:flex;flex-wrap:wrap;gap:10px">` + cols.map((c) => `<label style="display:inline-flex;align-items:center;gap:6px;font-size:13px"><input type="checkbox" data-c="${esc(c.name)}" ${sel.has(c.name) ? 'checked' : ''} style="accent-color:var(--bm-accent,#2563eb)">${esc(c.label)}</label>`).join('') + `</div>`;
  el.querySelectorAll('[data-c]').forEach((cb) => cb.addEventListener('change', () => { const n = cb.getAttribute('data-c'); cb.checked ? sel.add(n) : sel.delete(n); if (opts.onChange) opts.onChange([...sel]); }));
  return { value: () => [...sel], destroy: () => { el.innerHTML = ''; } };
}

// ConsentManager({ message?, policyUrl?, onAccept?, onDecline? }) - cookie consent (localStorage).
export function ConsentManager(opts = {}) {
  const KEY = 'bm:consent';
  let prior = null; try { prior = localStorage.getItem(KEY); } catch (_) {}
  if (prior) { if (prior === 'accept' && opts.onAccept) opts.onAccept(); return { destroy: () => {} }; }
  const bar = document.createElement('div');
  bar.style.cssText = 'position:fixed;bottom:16px;left:16px;right:16px;max-width:560px;margin:0 auto;z-index:9996;background:#18181b;color:#fff;border-radius:12px;padding:14px 18px;display:flex;align-items:center;gap:14px;box-shadow:0 10px 30px rgba(0,0,0,.3);font-size:13px';
  bar.innerHTML = `<span style="flex:1">${esc(opts.message || 'We use cookies to improve your experience.')}${opts.policyUrl ? ` <a href="${esc(opts.policyUrl)}" style="color:#93c5fd">Learn more</a>` : ''}</span><button data-decline style="background:none;border:1px solid rgba(255,255,255,.3);color:#fff;border-radius:7px;padding:6px 12px;cursor:pointer">Decline</button><button data-accept style="background:var(--bm-accent,#2563eb);border:none;color:#fff;border-radius:7px;padding:6px 14px;cursor:pointer;font-weight:600">Accept</button>`;
  const close = (choice) => { try { localStorage.setItem(KEY, choice); } catch (_) {} bar.remove(); };
  bar.querySelector('[data-accept]').addEventListener('click', () => { close('accept'); opts.onAccept && opts.onAccept(); });
  bar.querySelector('[data-decline]').addEventListener('click', () => { close('decline'); opts.onDecline && opts.onDecline(); });
  document.body.appendChild(bar);
  return { destroy: () => { bar.remove(); } };
}

// ═══════════════════════════════════════════════════════════════════
//  WAVE 9 - workflow & domain (over existing primitives/endpoints)
// ═══════════════════════════════════════════════════════════════════

// ApprovalInbox(target, { onDecide? }) - everything awaiting my decision (/api/_approvals?mine=1).
export async function ApprovalInbox(target, opts = {}) {
  const el = resolveEl(target);
  const render = async () => {
    let rows = [];
    try { const r = await bm.api.get('/api/_approvals?mine=1'); rows = (Array.isArray(r) ? r : r.approvals || []).filter((a) => a.status === 'pending'); } catch (ex) { el.innerHTML = skin.emptyState(ex?.message || 'No approvals access.'); return; }
    if (!rows.length) { el.innerHTML = skin.emptyState('Nothing awaiting your decision.'); return; }
    el.innerHTML = `<div data-bm-approvalinbox class="space-y-2">` + rows.map((a) => `<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid rgba(128,128,128,.2);border-radius:8px;padding:10px 12px"><div style="font-size:13px"><div style="font-weight:600">${esc(a.title || (a.table_name + ' #' + a.row_id))}</div><div style="opacity:.55">from ${esc(a.requested_email || a.requested_by)} · ${relTime(a.created_at)}</div></div><div style="display:flex;gap:6px"><button data-ok="${esc(a.id)}" style="padding:6px 12px;border-radius:7px;border:none;background:#16a34a;color:#fff;cursor:pointer;font-size:13px">Approve</button><button data-no="${esc(a.id)}" style="padding:6px 12px;border-radius:7px;border:1px solid #dc2626;color:#dc2626;background:none;cursor:pointer;font-size:13px">Reject</button></div></div>`).join('') + `</div>`;
    const decide = async (id, decision) => { try { await bm.api.post(`/api/_approvals/${id}/decide`, { decision }); if (opts.onDecide) opts.onDecide(id, decision); render(); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } };
    el.querySelectorAll('[data-ok]').forEach((b) => b.addEventListener('click', () => decide(b.getAttribute('data-ok'), 'approved')));
    el.querySelectorAll('[data-no]').forEach((b) => b.addEventListener('click', () => decide(b.getAttribute('data-no'), 'rejected')));
  };
  await render();
  return { refresh: render, destroy: () => { el.innerHTML = ''; } };
}

// BulkChangeWizard(target, { table, filters?, fields, onDone? }) - filter → preview → apply.
// fields: which columns can be set. Applies via PATCH /api/{table}/batch {ids, fields}.
export async function BulkChangeWizard(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const desc = tableDesc(s, opts.table);
  const setable = editable(desc).filter((f) => !opts.fields || opts.fields.includes(f.name));
  let where = {}, affected = [];
  const filterCols = opts.filters || visible(desc).filter((f) => ['select', 'text', 'checkbox', 'number'].includes(f.control)).slice(0, 4).map((f) => f.name);
  const render = (step) => {
    if (step === 1) {
      el.innerHTML = `<div data-bm-bulk class="space-y-3"><div style="font-size:13px;opacity:.6">1 · Filter the records to change</div><div data-fb></div><div style="display:flex;justify-content:flex-end"><button data-next style="padding:8px 16px;border-radius:8px;background:var(--bm-accent,#2563eb);color:#fff;border:none;cursor:pointer">Preview →</button></div></div>`;
      FilterBar(el.querySelector('[data-fb]'), { filters: filterCols.map((n) => ({ name: n, type: 'search' })), onChange: (w) => { where = w; } });
      el.querySelector('[data-next]').addEventListener('click', () => render(2));
    } else if (step === 2) {
      el.innerHTML = `<div data-bm-bulk class="space-y-3"><div style="font-size:13px;opacity:.6">2 · Review affected records</div><div data-tbl></div><div style="display:flex;justify-content:space-between"><button data-back style="padding:8px 16px;border-radius:8px;border:1px solid rgba(128,128,128,.3);background:none;cursor:pointer">← Back</button><button data-next style="padding:8px 16px;border-radius:8px;background:var(--bm-accent,#2563eb);color:#fff;border:none;cursor:pointer">Set changes →</button></div></div>`;
      listRows(opts.table, { where, limit: 500 }).then((rows) => { affected = rows; el.querySelector('[data-tbl]').innerHTML = `<div style="font-size:13px;margin-bottom:6px"><b>${rows.length}</b> record(s) match.</div>` + genericTable(rows.slice(0, 20), { columns: visible(desc).slice(0, 5).map((f) => f.name) }); });
      el.querySelector('[data-back]').addEventListener('click', () => render(1));
      el.querySelector('[data-next]').addEventListener('click', () => render(3));
    } else {
      el.innerHTML = `<div data-bm-bulk class="space-y-3"><div style="font-size:13px;opacity:.6">3 · Set the new values for ${affected.length} record(s)</div><form data-set class="space-y-3">${skin.error('')}${setable.map((f) => skin.field({ label: f.label, inner: controlHTML(f, '', null), required: false })).join('')}<div style="display:flex;justify-content:space-between"><button type="button" data-back style="padding:8px 16px;border-radius:8px;border:1px solid rgba(128,128,128,.3);background:none;cursor:pointer">← Back</button><button type="submit" style="padding:8px 16px;border-radius:8px;background:#dc2626;color:#fff;border:none;cursor:pointer">Apply to ${affected.length}</button></div></form></div>`;
      const form = el.querySelector('form'), errEl = el.querySelector('[data-bm-error]');
      el.querySelector('[data-back]').addEventListener('click', () => render(2));
      form.addEventListener('submit', async (e) => { e.preventDefault(); errEl.hidden = true; const fd = new FormData(form); const fields = {}; setable.forEach((f) => { const v = fd.get(f.name); if (v != null && v !== '') fields[f.name] = f.control === 'number' ? Number(v) : v; }); if (!Object.keys(fields).length) { errEl.textContent = 'Set at least one field.'; errEl.hidden = false; return; } try { await bm.api.patch(`/api/${opts.table}/batch`, { ids: affected.map((r) => r.id), fields }); Toast(`Updated ${affected.length} record(s) ✓`, { type: 'success' }); if (opts.onDone) opts.onDone(affected.length); render(1); } catch (ex) { errEl.textContent = ex?.message || 'Apply failed'; errEl.hidden = false; } });
    }
  };
  render(1);
  return { destroy: () => { el.innerHTML = ''; } };
}

// RunReview(target, { table, where?, columns?, title?, onApprove? }) - review a batch's line items + approve.
export async function RunReview(target, opts) {
  const el = resolveEl(target);
  const rows = await listRows(opts.table, { where: opts.where, limit: opts.limit || 500 });
  el.innerHTML = `<div data-bm-runreview class="space-y-3"><div style="display:flex;justify-content:space-between;align-items:center"><div style="font-weight:600">${esc(opts.title || 'Review')} · ${rows.length} item(s)</div>${opts.onApprove ? `<button data-approve style="padding:8px 16px;border-radius:8px;background:#16a34a;color:#fff;border:none;cursor:pointer;font-size:14px">Approve & commit</button>` : ''}</div><div data-tbl></div></div>`;
  const cols = opts.columns ? opts.columns.split(',').map((c) => c.trim()) : (rows.length ? Object.keys(rows[0]).slice(0, 6) : []);
  el.querySelector('[data-tbl]').innerHTML = genericTable(rows, { columns: cols });
  el.querySelector('[data-approve]')?.addEventListener('click', async () => { try { await opts.onApprove(rows); Toast('Committed ✓', { type: 'success' }); } catch (ex) { Toast(ex?.message || 'Failed', { type: 'error' }); } });
  return { destroy: () => { el.innerHTML = ''; } };
}

// Wizard(target, { steps:[{title, content}], onFinish? }) - generic content multi-step.
export function Wizard(target, opts) {
  const el = resolveEl(target);
  const steps = opts.steps || []; let cur = 0;
  const draw = () => {
    el.innerHTML = `<div data-bm-wizard><div data-bm-stepper style="margin-bottom:16px"></div><div data-body style="min-height:60px"></div><div style="display:flex;justify-content:space-between;margin-top:16px">${cur > 0 ? '<button data-back style="padding:8px 16px;border-radius:8px;border:1px solid rgba(128,128,128,.3);background:none;cursor:pointer">← Back</button>' : '<span></span>'}<button data-next style="padding:8px 16px;border-radius:8px;background:var(--bm-accent,#2563eb);color:#fff;border:none;cursor:pointer">${cur < steps.length - 1 ? 'Next →' : 'Finish'}</button></div></div>`;
    Stepper(el.querySelector('[data-bm-stepper]'), { steps: steps.map((s) => s.title || ''), current: cur });
    setContent(el.querySelector('[data-body]'), steps[cur] && steps[cur].content);
    el.querySelector('[data-back]')?.addEventListener('click', () => { cur--; draw(); });
    el.querySelector('[data-next]').addEventListener('click', () => { if (cur < steps.length - 1) { cur++; draw(); } else if (opts.onFinish) opts.onFinish(); });
  };
  draw();
  return { destroy: () => { el.innerHTML = ''; } };
}

// VerticalStepper(target, { steps, current }) - vertical stage tracker.
export function VerticalStepper(target, opts) {
  const el = resolveEl(target);
  const steps = (opts.steps || []).map((s) => (typeof s === 'string' ? { label: s } : s));
  const cur = typeof opts.current === 'number' ? opts.current : 0;
  el.innerHTML = `<ol data-bm-vstepper style="list-style:none;margin:0;padding:0">` + steps.map((s, i) => { const done = i < cur, active = i === cur; const bg = done ? '#16a34a' : active ? 'var(--bm-accent,#2563eb)' : 'rgba(128,128,128,.25)'; return `<li style="display:flex;gap:12px;${i < steps.length - 1 ? 'padding-bottom:18px' : ''};position:relative">${i < steps.length - 1 ? `<span style="position:absolute;left:13px;top:28px;bottom:0;width:2px;background:${done ? '#16a34a' : 'rgba(128,128,128,.25)'}"></span>` : ''}<span style="flex-shrink:0;width:28px;height:28px;border-radius:50%;background:${bg};color:${(done || active) ? '#fff' : 'inherit'};display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;z-index:1">${done ? '✓' : i + 1}</span><div style="padding-top:3px"><div style="font-weight:${active ? 600 : 400};font-size:14px">${esc(s.label)}</div>${s.detail ? `<div style="font-size:12px;opacity:.55;margin-top:2px">${esc(s.detail)}</div>` : ''}</div></li>`; }).join('') + `</ol>`;
  return { destroy: () => { el.innerHTML = ''; } };
}

// ExpirationTracker(target, { table, dateField, labelField?, warnDays?, where? }) - date-driven status.
export async function ExpirationTracker(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const lf = opts.labelField || labelField(s[opts.table]);
  const warn = (opts.warnDays || 30) * 86400000;
  const render = async () => {
    const rows = await listRows(opts.table, { where: opts.where, sort: opts.dateField, order: 'asc', limit: 200 });
    const now = Date.now();
    const withT = rows.map((r) => ({ r, t: new Date(r[opts.dateField]).getTime() })).filter((x) => !isNaN(x.t));
    if (!withT.length) { el.innerHTML = skin.emptyState('Nothing tracked.'); return; }
    el.innerHTML = `<div data-bm-expiration class="space-y-1">` + withT.map(({ r, t }) => { const overdue = t < now, soon = !overdue && t - now < warn; const v = overdue ? 'error' : soon ? 'warning' : 'success'; const lbl = overdue ? 'overdue' : soon ? 'due soon' : 'ok'; return `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 4px;border-bottom:1px solid rgba(128,128,128,.1);font-size:13px"><span>${esc(r[lf] ?? r.id)}</span><span style="display:flex;align-items:center;gap:10px"><span style="opacity:.6">${new Date(t).toLocaleDateString()}</span>${Badge(lbl, { variant: v })}</span></div>`; }).join('') + `</div>`;
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// KnowledgeBase(target, { table, titleField?, bodyField? }) - searchable article browser.
export async function KnowledgeBase(target, opts) {
  const el = resolveEl(target);
  const tf = opts.titleField || 'title', bf = opts.bodyField || 'body';
  const rows = await listRows(opts.table, { limit: 500 });
  el.innerHTML = `<div data-bm-kb><input type="search" data-q placeholder="Search articles…" class="${inputCls}" style="margin-bottom:12px"><div data-list class="space-y-1"></div></div>`;
  const list = el.querySelector('[data-list]'), q = el.querySelector('[data-q]');
  const open = async (r) => { const m = Modal({ title: r[tf], size: 'lg' }); try { m.el.innerHTML = await bm.markdown(r[bf] || ''); } catch (_) { m.el.textContent = r[bf] || ''; } };
  const draw = () => { const needle = q.value.toLowerCase(); const hits = rows.filter((r) => (String(r[tf] ?? '') + ' ' + String(r[bf] ?? '')).toLowerCase().includes(needle)); list.innerHTML = hits.length ? hits.map((r, i) => `<button data-i="${rows.indexOf(r)}" style="display:block;width:100%;text-align:left;padding:12px 14px;border:1px solid rgba(128,128,128,.2);border-radius:8px;background:var(--card,#fff);cursor:pointer"><div style="font-weight:600;font-size:14px">${esc(r[tf] ?? '')}</div><div style="font-size:12px;opacity:.55;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(String(r[bf] ?? '').replace(/[#*`]/g, '').slice(0, 120))}</div></button>`).join('') : skin.emptyState('No articles found.'); list.querySelectorAll('[data-i]').forEach((b) => b.addEventListener('click', () => open(rows[+b.getAttribute('data-i')]))); };
  q.addEventListener('input', draw); draw();
  return { destroy: () => { el.innerHTML = ''; } };
}

// PlanComparison(target, { plans, features, nameField? }) - plans as columns, features as rows.
// plans: array of objects (or {table}). features: [{key,label}] or [key].
export async function PlanComparison(target, opts) {
  const el = resolveEl(target);
  let plans = opts.plans;
  if (!plans && opts.table) plans = await listRows(opts.table, { limit: 20, where: opts.where });
  plans = plans || [];
  const nameField = opts.nameField || 'name';
  const feats = (opts.features || (plans.length ? Object.keys(plans[0]).filter((k) => k !== 'id' && k !== nameField && !k.endsWith('_at') && k !== 'user_id') : [])).map((f) => (typeof f === 'string' ? { key: f, label: humanize(f) } : f));
  const cell = (v) => v === true || v === 1 ? '<span style="color:#16a34a">✓</span>' : v === false || v === 0 || v == null || v === '' ? '<span style="opacity:.3">-</span>' : esc(v);
  el.innerHTML = `<div data-bm-plancompare style="overflow-x:auto"><table style="border-collapse:collapse;width:100%;font-size:13px"><thead><tr><th style="text-align:left;padding:10px 12px"></th>${plans.map((p) => `<th style="padding:10px 12px;text-align:center;font-weight:700">${esc(p[nameField] ?? '')}</th>`).join('')}</tr></thead><tbody>${feats.map((f) => `<tr style="border-top:1px solid rgba(128,128,128,.12)"><td style="padding:10px 12px;opacity:.7">${esc(f.label)}</td>${plans.map((p) => `<td style="padding:10px 12px;text-align:center">${cell(p[f.key])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  return { destroy: () => { el.innerHTML = ''; } };
}

// TreeTable(target, { table, parentField?, columns?, labelField? }) - hierarchical table.
export async function TreeTable(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const pf = opts.parentField || 'parent_id', lf = opts.labelField || labelField(s[opts.table]);
  const cols = opts.columns ? opts.columns.split(',').map((c) => c.trim()) : null;
  const render = async () => {
    const rows = await listRows(opts.table, { limit: 1000 });
    const byParent = new Map();
    rows.forEach((r) => { const p = r[pf] == null ? 'root' : String(r[pf]); if (!byParent.has(p)) byParent.set(p, []); byParent.get(p).push(r); });
    const showCols = cols || visible(tableDesc(s, opts.table)).filter((f) => f.name !== lf).slice(0, 3).map((f) => f.name);
    const out = [];
    const walk = (r, depth) => { out.push(`<tr style="border-top:1px solid rgba(128,128,128,.1)"><td style="padding:8px 12px;padding-left:${12 + depth * 22}px;font-size:13px">${depth ? '<span style="opacity:.4">└ </span>' : ''}${esc(r[lf] ?? r.id)}</td>${showCols.map((c) => `<td style="padding:8px 12px;font-size:13px">${esc(r[c] ?? '')}</td>`).join('')}</tr>`); (byParent.get(String(r.id)) || []).forEach((c) => walk(c, depth + 1)); };
    (byParent.get('root') || []).forEach((r) => walk(r, 0));
    el.innerHTML = `<div data-bm-treetable style="overflow-x:auto"><table style="border-collapse:collapse;width:100%"><thead><tr><th style="text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;opacity:.6">${esc(humanize(lf))}</th>${showCols.map((c) => `<th style="text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;opacity:.6">${esc(humanize(c))}</th>`).join('')}</tr></thead><tbody>${out.join('')}</tbody></table></div>`;
  };
  await render();
  const stop = bm.live.scoped ? bm.live.scoped(opts.table, () => render()) : bm.live(opts.table, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// Heatmap(target, { data:[{x,y,value}], color? }) - grid colored by value intensity.
export function Heatmap(target, opts) {
  const el = resolveEl(target);
  const data = opts.data || [];
  if (!data.length) { el.innerHTML = skin.emptyState('No data.'); return { destroy: () => { el.innerHTML = ''; } }; }
  const xs = [...new Set(data.map((d) => String(d.x)))], ys = [...new Set(data.map((d) => String(d.y)))];
  const map = {}; let max = 0; data.forEach((d) => { map[`${d.x}|${d.y}`] = d.value; max = Math.max(max, d.value); });
  const base = opts.color || '37,99,235';
  el.innerHTML = `<div data-bm-heatmap style="overflow-x:auto"><table style="border-collapse:separate;border-spacing:3px"><thead><tr><th></th>${xs.map((x) => `<th style="font-size:10px;opacity:.6;font-weight:500;padding:2px 4px">${esc(x)}</th>`).join('')}</tr></thead><tbody>${ys.map((y) => `<tr><td style="font-size:10px;opacity:.6;padding-right:6px;white-space:nowrap">${esc(y)}</td>${xs.map((x) => { const v = map[`${x}|${y}`] ?? 0; const a = max ? v / max : 0; return `<td title="${esc(x)} · ${esc(y)}: ${esc(v)}" style="width:26px;height:26px;border-radius:4px;background:rgba(${base},${(a * 0.9 + 0.05).toFixed(2)});text-align:center;font-size:10px;color:${a > 0.5 ? '#fff' : 'inherit'}">${v || ''}</td>`; }).join('')}</tr>`).join('')}</tbody></table></div>`;
  return { destroy: () => { el.innerHTML = ''; } };
}

// DocViewer(target, { url, height? }) - embed a PDF/doc.
export function DocViewer(target, opts) {
  const el = resolveEl(target);
  el.innerHTML = `<iframe data-bm-docviewer src="${esc(opts.url)}" style="width:100%;height:${opts.height || '480px'};border:1px solid rgba(128,128,128,.2);border-radius:8px" title="document"></iframe>`;
  return { destroy: () => { el.innerHTML = ''; } };
}

// ─── Wave 9b - heavier domain primitives ────────────────────────────

// EditableMatrix(target, { rows, cols, value?, onChange?, cornerLabel?, totals? })
// Spreadsheet grid: rows×cols editable cells + optional live totals.
export function EditableMatrix(target, opts) {
  const el = resolveEl(target);
  const rows = (opts.rows || []).map((r) => (typeof r === 'string' ? { key: r, label: r } : r));
  const cols = (opts.cols || []).map((c) => (typeof c === 'string' ? { key: c, label: c } : c));
  const data = {}; rows.forEach((r) => cols.forEach((c) => { data[`${r.key}|${c.key}`] = opts.value ? (opts.value(r.key, c.key) ?? '') : ''; }));
  const num = (v) => { const n = Number(v); return isFinite(n) ? n : 0; };
  const refreshTotals = () => { if (!opts.totals) return; rows.forEach((r) => { const cell = el.querySelector(`[data-rt="${CSS.escape(r.key)}"]`); if (cell) cell.textContent = cols.reduce((s, c) => s + num(data[`${r.key}|${c.key}`]), 0); }); cols.forEach((c) => { const cell = el.querySelector(`[data-ct="${CSS.escape(c.key)}"]`); if (cell) cell.textContent = rows.reduce((s, r) => s + num(data[`${r.key}|${c.key}`]), 0); }); const g = el.querySelector('[data-gt]'); if (g) g.textContent = rows.reduce((s, r) => s + cols.reduce((s2, c) => s2 + num(data[`${r.key}|${c.key}`]), 0), 0); };
  el.innerHTML = `<div data-bm-matrix style="overflow-x:auto"><table style="border-collapse:collapse;font-size:13px"><thead><tr><th style="padding:6px 10px;text-align:left">${esc(opts.cornerLabel || '')}</th>${cols.map((c) => `<th style="padding:6px 10px;text-align:right;font-weight:600">${esc(c.label)}</th>`).join('')}${opts.totals ? '<th style="padding:6px 10px;text-align:right">Total</th>' : ''}</tr></thead><tbody>${rows.map((r) => `<tr style="border-top:1px solid rgba(128,128,128,.12)"><td style="padding:6px 10px;font-weight:500;white-space:nowrap">${esc(r.label)}</td>${cols.map((c) => `<td style="padding:2px"><input data-cell="${esc(r.key)}|${esc(c.key)}" value="${esc(data[`${r.key}|${c.key}`])}" inputmode="decimal" style="width:78px;text-align:right;padding:5px 8px;border:1px solid transparent;border-radius:5px;background:rgba(128,128,128,.07);color:inherit"></td>`).join('')}${opts.totals ? `<td data-rt="${esc(r.key)}" style="padding:6px 10px;text-align:right;font-weight:600;font-variant-numeric:tabular-nums"></td>` : ''}</tr>`).join('')}${opts.totals ? `<tr style="border-top:2px solid rgba(128,128,128,.25);font-weight:700"><td style="padding:6px 10px">Total</td>${cols.map((c) => `<td data-ct="${esc(c.key)}" style="padding:6px 10px;text-align:right;font-variant-numeric:tabular-nums"></td>`).join('')}<td data-gt style="padding:6px 10px;text-align:right"></td></tr>` : ''}</tbody></table></div>`;
  el.querySelectorAll('[data-cell]').forEach((inp) => inp.addEventListener('input', () => { const [rk, ck] = inp.getAttribute('data-cell').split('|'); data[`${rk}|${ck}`] = inp.value; if (opts.onChange) opts.onChange(rk, ck, inp.value); refreshTotals(); }));
  refreshTotals();
  return { value: () => ({ ...data }), destroy: () => { el.innerHTML = ''; } };
}

// Scheduler(target, { resources?|resourceTable, shiftTable?, dateField?, resourceField?, labelField?, weekStart?, onCreate? })
// Week grid: resources × 7 days; shifts placed from shiftTable; click an empty cell → onCreate(resourceId, isoDate).
export async function Scheduler(target, opts) {
  const el = resolveEl(target);
  let resources = opts.resources;
  if (!resources && opts.resourceTable) { const s = await schema(); const lf = labelField(s[opts.resourceTable]); resources = (await listRows(opts.resourceTable, { limit: 50 })).map((r) => ({ id: r.id, label: r[lf] ?? r.id })); }
  resources = resources || [];
  const df = opts.dateField || 'date', rf = opts.resourceField || 'resource_id', lf2 = opts.labelField || 'title';
  const base = opts.weekStart ? new Date(opts.weekStart) : (() => { const d = new Date(); const day = (d.getDay() + 6) % 7; d.setDate(d.getDate() - day); return d; })();
  const days = Array.from({ length: 7 }, (_, i) => { const d = new Date(base); d.setDate(base.getDate() + i); return d; });
  const iso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const render = async () => {
    let shifts = []; if (opts.shiftTable) { try { shifts = await listRows(opts.shiftTable, { limit: 500 }); } catch (_) {} }
    const byCell = {}; shifts.forEach((sh) => { const k = `${sh[rf]}|${String(sh[df]).slice(0, 10)}`; (byCell[k] = byCell[k] || []).push(sh); });
    el.innerHTML = `<div data-bm-scheduler style="overflow-x:auto"><table style="border-collapse:collapse;font-size:12px;width:100%"><thead><tr><th style="padding:8px;text-align:left;position:sticky;left:0;background:var(--card,#fff)"></th>${days.map((d) => `<th style="padding:8px;text-align:center;font-weight:600">${d.toLocaleDateString(undefined, { weekday: 'short' })}<div style="opacity:.5;font-weight:400">${d.getDate()}</div></th>`).join('')}</tr></thead><tbody>${resources.map((r) => `<tr style="border-top:1px solid rgba(128,128,128,.12)"><td style="padding:8px;font-weight:500;white-space:nowrap;position:sticky;left:0;background:var(--card,#fff)">${esc(r.label)}</td>${days.map((d) => { const cell = byCell[`${r.id}|${iso(d)}`] || []; return `<td data-cell="${esc(r.id)}|${iso(d)}" style="padding:3px;vertical-align:top;min-width:88px;cursor:${opts.onCreate ? 'pointer' : 'default'};border-left:1px solid rgba(128,128,128,.08)">${cell.map((sh) => `<div style="background:rgba(37,99,235,.15);color:#1d4ed8;border-radius:4px;padding:2px 5px;margin-bottom:2px">${esc(sh[lf2] ?? 'shift')}</div>`).join('')}</td>`; }).join('')}</tr>`).join('')}</tbody></table></div>`;
    if (opts.onCreate) el.querySelectorAll('[data-cell]').forEach((td) => td.addEventListener('click', (e) => { if (e.target !== td) return; const [rid, date] = td.getAttribute('data-cell').split('|'); opts.onCreate(rid, date); }));
  };
  await render();
  let stop = null; if (opts.shiftTable) stop = bm.live.scoped ? bm.live.scoped(opts.shiftTable, () => render()) : bm.live(opts.shiftTable, () => render());
  return { refresh: render, destroy: () => { try { stop && stop(); } catch (_) {} el.innerHTML = ''; } };
}

// TicketThread(target, { table, messageTable, parentField, subjectField?, statusField?, bodyField?, where? })
// Ticket list (left) + selected ticket's message thread (right).
export async function TicketThread(target, opts) {
  const el = resolveEl(target);
  const s = await schema();
  const subjF = opts.subjectField || labelField(s[opts.table]);
  const sp = SplitLayout(el, { leftWidth: '280px' });
  const openTicket = async (id, t) => { sp.right.innerHTML = `<h3 style="font-size:16px;font-weight:600;margin:0 0 10px">${esc(t ? (t[subjF] ?? ('Ticket #' + id)) : 'Ticket')}</h3><div data-thread></div>`; await CommentThread(sp.right.querySelector('[data-thread]'), { table: opts.messageTable, where: { [opts.parentField]: id }, bodyField: opts.bodyField || 'body' }); };
  const renderList = async () => { const tickets = await listRows(opts.table, { limit: 100, sort: 'created_at', order: 'desc', where: opts.where }); sp.left.innerHTML = tickets.length ? tickets.map((t) => `<button data-id="${esc(t.id)}" style="display:block;width:100%;text-align:left;padding:10px 12px;border:1px solid rgba(128,128,128,.15);border-radius:8px;margin-bottom:6px;background:var(--card,#fff);cursor:pointer"><div style="font-weight:600;font-size:13px">${esc(t[subjF] ?? ('Ticket #' + t.id))}</div><div style="font-size:11px;opacity:.5;margin-top:2px">${opts.statusField && t[opts.statusField] ? esc(t[opts.statusField]) + ' · ' : ''}${relTime(t.created_at)}</div></button>`).join('') : skin.emptyState('No tickets.'); sp.left.querySelectorAll('[data-id]').forEach((b) => b.addEventListener('click', () => openTicket(b.getAttribute('data-id'), tickets.find((x) => String(x.id) === b.getAttribute('data-id'))))); };
  await renderList(); sp.right.innerHTML = '<div style="opacity:.5;font-size:13px;padding:20px">Select a ticket →</div>';
  return { refresh: renderList, destroy: () => { el.innerHTML = ''; } };
}

// FieldArray(target, { fields, value?, onChange?, addLabel? }) - repeatable subform rows.
export function FieldArray(target, opts) {
  const el = resolveEl(target);
  const flds = opts.fields || []; let rows = (opts.value || []).map((r) => ({ ...r }));
  const emit = () => opts.onChange && opts.onChange(rows);
  const draw = () => {
    el.innerHTML = `<div data-bm-fieldarray class="space-y-2">${rows.map((row, i) => `<div data-row="${i}" style="display:flex;gap:8px;align-items:flex-end">${flds.map((f) => `<label style="flex:1"><span style="display:block;font-size:11px;opacity:.6;margin-bottom:3px">${esc(f.label || humanize(f.name))}</span><input data-f="${esc(f.name)}" type="${esc(f.type || 'text')}" value="${esc(row[f.name] ?? '')}" class="${inputCls}"></label>`).join('')}<button data-rm="${i}" style="padding:8px 11px;border:1px solid rgba(128,128,128,.3);border-radius:7px;background:none;cursor:pointer">✕</button></div>`).join('')}<button data-add style="font-size:13px;color:var(--bm-accent,#2563eb);background:none;border:none;cursor:pointer">+ ${esc(opts.addLabel || 'Add row')}</button></div>`;
    el.querySelectorAll('[data-row]').forEach((rowEl, i) => rowEl.querySelectorAll('[data-f]').forEach((inp) => inp.addEventListener('input', () => { rows[i][inp.getAttribute('data-f')] = inp.value; emit(); })));
    el.querySelectorAll('[data-rm]').forEach((b) => b.addEventListener('click', () => { rows.splice(+b.getAttribute('data-rm'), 1); draw(); emit(); }));
    el.querySelector('[data-add]').addEventListener('click', () => { rows.push({}); draw(); emit(); });
  };
  draw();
  return { value: () => rows, destroy: () => { el.innerHTML = ''; } };
}

// FileField(target, { value?, onChange? }) - current file + upload/replace (bm.upload → url).
export function FileField(target, opts = {}) {
  const el = resolveEl(target); let url = opts.value || '';
  const draw = () => {
    el.innerHTML = `<div data-bm-filefield style="display:flex;align-items:center;gap:10px">${url ? `<a href="${esc(url)}" target="_blank" rel="noopener" style="font-size:13px;color:var(--bm-accent,#2563eb);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(url.split('/').pop())}</a>` : '<span style="font-size:13px;opacity:.5">No file</span>'}<button data-up style="font-size:13px;padding:6px 12px;border:1px solid rgba(128,128,128,.3);border-radius:7px;background:none;cursor:pointer">${url ? 'Replace' : 'Upload'}</button></div>`;
    el.querySelector('[data-up]').addEventListener('click', () => { const inp = document.createElement('input'); inp.type = 'file'; inp.onchange = async () => { if (!inp.files || !inp.files[0]) return; try { const r = await bm.upload(inp.files[0]); url = r.url || r.path || ''; draw(); if (opts.onChange) opts.onChange(url); } catch (ex) { Toast(ex?.message || 'Upload failed', { type: 'error' }); } }; inp.click(); });
  };
  draw();
  return { get value() { return url; }, destroy: () => { el.innerHTML = ''; } };
}

// PhoneField(target, { value?, onChange? }) - country code + number → combined string.
const _phoneCC = [['+1', '🇺🇸'], ['+44', '🇬🇧'], ['+61', '🇦🇺'], ['+91', '🇮🇳'], ['+49', '🇩🇪'], ['+33', '🇫🇷'], ['+81', '🇯🇵'], ['+55', '🇧🇷']];
export function PhoneField(target, opts = {}) {
  const el = resolveEl(target);
  const m = String(opts.value || '').match(/^(\+\d+)?\s*(.*)$/) || [];
  const cc = m[1] || '+1', num = m[2] || '';
  el.innerHTML = `<div data-bm-phonefield style="display:inline-flex;gap:6px"><select data-cc class="${inputCls}" style="width:auto">${_phoneCC.map(([c, f]) => `<option value="${c}" ${c === cc ? 'selected' : ''}>${f} ${c}</option>`).join('')}</select><input data-num type="tel" value="${esc(num)}" placeholder="555 0100" class="${inputCls}"></div>`;
  const sel = el.querySelector('[data-cc]'), inp = el.querySelector('[data-num]');
  const emit = () => opts.onChange && opts.onChange(`${sel.value} ${inp.value}`.trim());
  sel.addEventListener('change', emit); inp.addEventListener('input', emit);
  return { get value() { return `${sel.value} ${inp.value}`.trim(); }, destroy: () => { el.innerHTML = ''; } };
}

export default {
  schema, clearSchemaCache, registerSkin, resetSkin, setAccent, query,
  PermissionMatrix, TeamManager, StepUp, SensitiveReveal, ImpersonationBanner, ModuleGate, ExportButton, ColumnChooser, ConsentManager,
  ApprovalInbox, BulkChangeWizard, RunReview, Wizard, VerticalStepper, ExpirationTracker, KnowledgeBase, PlanComparison, TreeTable, Heatmap, DocViewer,
  EditableMatrix, Scheduler, TicketThread, FieldArray, FileField, PhoneField,
  QueryView, Report, PivotTable, SavedViews,
  MultiRelation, TreeView, Reminder, ScheduleAction, Approval,
  Calendar, Timeline, InlineEdit, Funnel, Import, CustomFields,
  AppShell, Nav, Breadcrumbs, CommandPalette, DatePicker, Markdown, RichText, Code, Broadcast, Viewer,
  Stepper, FilterBar, KpiTile, Alert, EmptyState, ConfirmDialog, DiffViewer,
  SegmentedControl, DateRangePicker, Gauge, DetailHeader, SplitLayout, Map: MapView, MoneyInput, PercentInput,
  GanttChart, Checklist,
  Combobox, MultiSelect, Switch, Slider, Rating, ColorPicker, NumberStepper,
  Popover, ContextMenu, Carousel, Lightbox, Sortable, Pagination, FileDropzone, Kbd, Sparkline,
  DataTable, RecordForm, WizardForm, Detail, FlowForm, Transitions, Gate, can, hasRole, Uploader,
  Cards, Board, Stat, Chart,
  Modal, Drawer, Tabs, Accordion, Toast, Dropdown, Tooltip,
  Badge, Avatar, Spinner, Skeleton, ProgressBar,
  Login, Signup, Forgot, Reset, ProfileForm, MfaSetup, OAuthConnect, SessionManager, ApiTokenManager, ActAs,
  VersionHistory, AuditLog, RecordLock, ShareDialog, DownloadMyData,
  SignedImage, PdfButton, MediaGallery,
  FlowButton, WorkflowBadge, JobStatus, JobsDashboard,
  NotificationBell, Presence, Chat, CommentThread, ActivityFeed,
  Dashboard, UsageMeter, WebhookManager,
};
