package main

// Bundled TSX and flow templates used by curated feature packs.

const curatedKanbanTSX = `import bm from 'bm';

type Row = Record<string, any>;

const boards = bm.table('boards' as any) as any;
const columns = bm.table('board_columns' as any) as any;
const cards = bm.table('board_cards' as any) as any;
const history = bm.table('board_card_status_histories' as any) as any;

const state: { board: Row | null; columns: Row[]; cards: Row[]; dragging: number | null } = {
  board: null,
  columns: [],
  cards: [],
  dragging: null,
};

function mount(): HTMLElement {
  let el = document.getElementById('kanban-pack');
  if (!el) {
    el = document.createElement('main');
    el.id = 'kanban-pack';
    document.body.appendChild(el);
  }
  el.className = 'mx-auto max-w-7xl p-6 text-slate-950';
  return el;
}

function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'} as Record<string, string>)[c]);
}

function cardHtml(card: Row): string {
  return '<article draggable="true" data-card-id="' + card.id + '" class="rounded border border-slate-200 bg-white p-3 shadow-sm">' +
    '<div class="flex items-start justify-between gap-3">' +
      '<h3 class="text-sm font-semibold">' + esc(card.title) + '</h3>' +
      '<span class="rounded bg-slate-100 px-2 py-0.5 text-xs">' + esc(card.priority || 'normal') + '</span>' +
    '</div>' +
    '<p class="mt-2 text-sm text-slate-600">' + esc(card.description || 'No description') + '</p>' +
    '<div class="mt-3 flex items-center justify-between text-xs text-slate-500">' +
      '<span>Status: ' + esc(card.status || 'open') + '</span>' +
      '<button data-action="advance-card" data-card-id="' + card.id + '" class="rounded border px-2 py-1">Advance</button>' +
    '</div>' +
  '</article>';
}

function render() {
  const root = mount();
  const unreadable = state.columns.length === 0;
  root.innerHTML = '<header class="flex flex-wrap items-end justify-between gap-4">' +
    '<div><h1 class="text-2xl font-semibold">Kanban</h1><p class="mt-1 text-sm text-slate-600">Drag cards across columns; every move writes status history.</p></div>' +
    '<div class="flex gap-2"><button data-action="seed-kanban" class="rounded bg-slate-950 px-3 py-2 text-sm text-white">Seed board</button><button data-action="refresh-kanban" class="rounded border px-3 py-2 text-sm">Refresh</button></div>' +
  '</header>' +
  (unreadable ? '<section class="mt-6 rounded border border-dashed p-6 text-sm text-slate-600">No board columns yet. Seed a board to create Backlog, In Progress, Review, and Done.</section>' : '') +
  '<section class="mt-6 flex gap-4 overflow-x-auto pb-4">' + state.columns.map(col => {
    const colCards = state.cards.filter(card => Number(card.column_id) === Number(col.id)).sort((a, b) => Number(a.position || 0) - Number(b.position || 0));
    return '<div data-column-id="' + col.id + '" data-status="' + esc(col.name) + '" class="min-w-[260px] flex-1 rounded border bg-slate-50 p-3">' +
      '<div class="mb-3 flex items-center justify-between"><h2 class="font-medium">' + esc(col.name) + '</h2><span class="text-xs text-slate-500">' + colCards.length + '</span></div>' +
      '<div class="space-y-3 min-h-[80px]">' + colCards.map(cardHtml).join('') + '</div>' +
      '<button data-action="add-card" data-column-id="' + col.id + '" class="mt-3 w-full rounded border border-dashed py-2 text-sm">Add card</button>' +
    '</div>';
  }).join('') + '</section>';
  wireEvents(root);
}

async function load() {
  const [boardRows, columnRows, cardRows] = await Promise.all([
    boards.list({ limit: 10 }).catch(() => []),
    columns.list({ limit: 100 }).catch(() => []),
    cards.list({ limit: 250 }).catch(() => []),
  ]);
  state.board = boardRows[0] || null;
  state.columns = columnRows.sort((a: Row, b: Row) => Number(a.position || 0) - Number(b.position || 0));
  state.cards = cardRows;
  render();
}

async function seed() {
  const board = await boards.create({ name: 'Product Workflow' });
  const names = ['Backlog', 'In Progress', 'Review', 'Done'];
  const created = [];
  for (let i = 0; i < names.length; i++) {
    created.push(await columns.create({ board_id: board.id, name: names[i], position: i }));
  }
  await cards.create({ board_id: board.id, column_id: created[0].id, title: 'Triage intake', description: 'Capture owner, priority, and next action.', priority: 'high', position: 0, status: 'Backlog' });
  await cards.create({ board_id: board.id, column_id: created[1].id, title: 'Draft implementation plan', description: 'Keep scope small and testable.', priority: 'normal', position: 1, status: 'In Progress' });
  await load();
}

async function addCard(columnId: number) {
  const title = window.prompt('Card title');
  if (!title) return;
  const boardId = state.board?.id || state.columns.find(c => Number(c.id) === columnId)?.board_id;
  await cards.create({ board_id: boardId, column_id: columnId, title, status: state.columns.find(c => Number(c.id) === columnId)?.name || 'open', position: Date.now() });
  await load();
}

async function moveCard(cardId: number, toColumnId: number) {
  const card = state.cards.find(c => Number(c.id) === cardId);
  const toColumn = state.columns.find(c => Number(c.id) === toColumnId);
  if (!card || !toColumn || Number(card.column_id) === toColumnId) return;
  await history.create({ card_id: cardId, from_column_id: card.column_id, to_column_id: toColumnId, from_status: card.status, to_status: toColumn.name, note: 'drag/drop move' });
  await cards.update(cardId, { column_id: toColumnId, status: toColumn.name, position: Date.now() });
  await load();
}

function wireEvents(root: HTMLElement) {
  root.querySelectorAll('[data-card-id]').forEach(el => {
    el.addEventListener('dragstart', ev => {
      state.dragging = Number((ev.currentTarget as HTMLElement).dataset.cardId);
    });
  });
  root.querySelectorAll('[data-column-id]').forEach(el => {
    el.addEventListener('dragover', ev => ev.preventDefault());
    el.addEventListener('drop', async ev => {
      ev.preventDefault();
      const id = state.dragging;
      state.dragging = null;
      if (id) await moveCard(id, Number((ev.currentTarget as HTMLElement).dataset.columnId));
    });
  });
  root.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', async ev => {
      const target = ev.currentTarget as HTMLElement;
      const action = target.dataset.action;
      if (action === 'seed-kanban') await seed();
      if (action === 'refresh-kanban') await load();
      if (action === 'add-card') await addCard(Number(target.dataset.columnId));
      if (action === 'advance-card') {
        const card = state.cards.find(c => Number(c.id) === Number(target.dataset.cardId));
        const current = state.columns.findIndex(c => Number(c.id) === Number(card?.column_id));
        const next = state.columns[Math.min(current + 1, state.columns.length - 1)];
        if (card && next) await moveCard(Number(card.id), Number(next.id));
      }
    });
  });
}

bm.live.scoped('*' as any, load, { debounce: 100 });
void load();
`

const curatedKanbanMoveFlowYAML = `on:
  request:
    method: POST
    path: /api/kanban/cards/:id/move
    auth: required

jobs:
  move:
    steps:
      - id: before
        run: sql
        query: SELECT column_id, status FROM board_cards WHERE id = :id

      - run: sql
        query: INSERT INTO board_card_status_histories (card_id, from_column_id, to_column_id, from_status, to_status, changed_by, note) SELECT id, column_id, :to_column_id, status, :to_status, NULLIF(:changed_by, ''), :note FROM board_cards WHERE id = :id
        with:
          params:
            to_column_id: ${{ params.column_id }}
            to_status: ${{ params.status | default:'open' }}
            changed_by: ${{ user.id | default:'' }}
            note: ${{ params.note | default:'flow move' }}
        expect_rows: ">0"

      - run: sql
        query: UPDATE board_cards SET column_id = :column_id, status = :status, position = :position WHERE id = :id
        with:
          params:
            column_id: ${{ params.column_id }}
            status: ${{ params.status | default:'open' }}
            position: ${{ params.position | default:'0' }}
        expect_rows: ">0"

      - run: respond
        with:
          body:
            ok: true
            card_id: ${{ params.id }}
            to_column_id: ${{ params.column_id }}
`

const curatedNotifyHubTSX = `import bm from 'bm';

type Row = Record<string, any>;

const notifications = bm.table('notifications' as any) as any;
const preferences = bm.table('notification_preferences' as any) as any;

let rows: Row[] = [];
let prefs: Row[] = [];

function mount(): HTMLElement {
  let el = document.getElementById('notify-hub-pack');
  if (!el) {
    el = document.createElement('main');
    el.id = 'notify-hub-pack';
    document.body.appendChild(el);
  }
  el.className = 'mx-auto max-w-6xl p-6 text-slate-950';
  return el;
}

function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'} as Record<string, string>)[c]);
}

function rowHtml(n: Row): string {
  const unread = !n.read_at;
  return '<article class="rounded border bg-white p-4 shadow-sm ' + (unread ? 'border-slate-950' : 'border-slate-200') + '">' +
    '<div class="flex items-start justify-between gap-3"><div><h3 class="font-semibold">' + esc(n.title) + '</h3><p class="mt-1 text-sm text-slate-600">' + esc(n.body) + '</p></div>' +
    '<span class="rounded bg-slate-100 px-2 py-1 text-xs">' + esc(n.topic || 'general') + '</span></div>' +
    '<div class="mt-3 flex items-center justify-between text-xs text-slate-500"><span>' + esc(n.channel || 'in_app') + ' · ' + esc(n.priority || 'normal') + '</span>' +
    (unread ? '<button data-action="mark-read" data-id="' + n.id + '" class="rounded border px-2 py-1">Mark read</button>' : '<span>Read</span>') + '</div>' +
  '</article>';
}

function render() {
  const unread = rows.filter(n => !n.read_at).length;
  const root = mount();
  root.innerHTML = '<header class="flex flex-wrap items-end justify-between gap-4">' +
    '<div><h1 class="text-2xl font-semibold">Notify Hub</h1><p class="mt-1 text-sm text-slate-600">Inbox, preferences, broadcast flow, and unread counts.</p></div>' +
    '<div class="grid grid-cols-2 gap-2 text-center"><div class="rounded border p-3"><div class="text-2xl font-semibold">' + unread + '</div><div class="text-xs text-slate-500">unread</div></div><div class="rounded border p-3"><div class="text-2xl font-semibold">' + rows.length + '</div><div class="text-xs text-slate-500">total</div></div></div>' +
  '</header>' +
  '<section class="mt-6 grid gap-6 lg:grid-cols-[360px_1fr]">' +
    '<form id="notify-send" class="rounded border bg-white p-4 shadow-sm"><h2 class="font-semibold">Send broadcast</h2><label class="mt-3 block text-sm">Title<input name="title" required class="mt-1 w-full rounded border px-3 py-2"></label><label class="mt-3 block text-sm">Body<textarea name="body" required class="mt-1 w-full rounded border px-3 py-2"></textarea></label><label class="mt-3 block text-sm">Topic<input name="topic" value="general" class="mt-1 w-full rounded border px-3 py-2"></label><button class="mt-4 rounded bg-slate-950 px-3 py-2 text-sm text-white">Broadcast</button></form>' +
    '<div><div class="mb-3 flex items-center justify-between"><h2 class="font-semibold">Inbox</h2><button data-action="refresh" class="rounded border px-3 py-2 text-sm">Refresh</button></div><div class="space-y-3">' + (rows.length ? rows.map(rowHtml).join('') : '<div class="rounded border border-dashed p-6 text-sm text-slate-600">No notifications yet.</div>') + '</div></div>' +
  '</section>' +
  '<section class="mt-6 rounded border bg-slate-50 p-4"><h2 class="font-semibold">Preferences</h2><p class="mt-1 text-sm text-slate-600">' + (prefs.length ? prefs.length + ' preference rows configured.' : 'No preference rows yet; create rows in notification_preferences to tailor topics/channels.') + '</p></section>';
  wireEvents(root);
}

async function load() {
  const [notificationRows, preferenceRows] = await Promise.all([
    notifications.list({ limit: 100 }).catch(() => []),
    preferences.list({ limit: 100 }).catch(() => []),
  ]);
  rows = notificationRows.sort((a: Row, b: Row) => Number(new Date(b.created_at || 0)) - Number(new Date(a.created_at || 0)));
  prefs = preferenceRows;
  render();
}

async function broadcast(form: HTMLFormElement) {
  const data = new FormData(form);
  const title = String(data.get('title') || '').trim();
  const body = String(data.get('body') || '').trim();
  const topic = String(data.get('topic') || 'general').trim() || 'general';
  if (!title || !body) return;
  try {
    await bm.api.post('/api/notify-hub/broadcast' as any, { title, body, topic });
  } catch {
    await notifications.create({ title, body, topic, channel: 'in_app', priority: 'normal' });
  }
  form.reset();
  await load();
}

function wireEvents(root: HTMLElement) {
  root.querySelector('#notify-send')?.addEventListener('submit', async ev => {
    ev.preventDefault();
    await broadcast(ev.currentTarget as HTMLFormElement);
  });
  root.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', async ev => {
      const target = ev.currentTarget as HTMLElement;
      if (target.dataset.action === 'refresh') await load();
      if (target.dataset.action === 'mark-read' && target.dataset.id) {
        await notifications.update(target.dataset.id, { read_at: new Date().toISOString() });
        await load();
      }
    });
  });
}

bm.live.scoped('notifications' as any, load, { debounce: 100 });
void load();
`

const curatedNotifyHubBroadcastFlowYAML = `on:
  request:
    method: POST
    path: /api/notify-hub/broadcast
    auth: required

jobs:
  broadcast:
    steps:
      - id: broadcast
        run: sql
        query: INSERT INTO notification_broadcasts (title, body, audience, channel, topic, sent_by, sent_at) VALUES (:title, :body, :audience, 'in_app', :topic, NULLIF(:sent_by, ''), datetime('now')) RETURNING id
        with:
          params:
            title: ${{ params.title }}
            body: ${{ params.body }}
            audience: ${{ params.audience | default:'all' }}
            topic: ${{ params.topic | default:'general' }}
            sent_by: ${{ user.id | default:'' }}

      - id: recipients
        run: sql
        query: SELECT id FROM _benmore_users WHERE verified = 1

      - for_each: ${{ steps.recipients.outputs }}
        as: recipient
        steps:
          - run: sql
            query: INSERT INTO notifications (user_id, broadcast_id, title, body, channel, topic, priority) VALUES (:user_id, :broadcast_id, :title, :body, 'in_app', :topic, :priority)
            with:
              params:
                user_id: ${{ recipient.id }}
                broadcast_id: ${{ steps.broadcast.outputs.id }}
                title: ${{ params.title }}
                body: ${{ params.body }}
                topic: ${{ params.topic | default:'general' }}
                priority: ${{ params.priority | default:'normal' }}

      - run: respond
        with:
          body:
            ok: true
            broadcast_id: ${{ steps.broadcast.outputs.id }}
`

const curatedFoundryTSX = `import bm from 'bm';

type Row = Record<string, any>;

const projects = bm.table('foundry_projects' as any) as any;
const artifacts = bm.table('foundry_artifacts' as any) as any;
const evaluations = bm.table('foundry_evaluations' as any) as any;
const reviews = bm.table('foundry_reviews' as any) as any;

let projectRows: Row[] = [];
let artifactRows: Row[] = [];
let evaluationRows: Row[] = [];
let reviewRows: Row[] = [];
let selectedId: number | null = null;

const stages = ['intake', 'artifact_review', 'evaluation', 'approved'];

function mount(): HTMLElement {
  let el = document.getElementById('foundry-pack');
  if (!el) {
    el = document.createElement('main');
    el.id = 'foundry-pack';
    document.body.appendChild(el);
  }
  el.className = 'mx-auto max-w-7xl p-6 text-slate-950';
  return el;
}

function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'} as Record<string, string>)[c]);
}

function projectCard(p: Row): string {
  const active = Number(p.id) === selectedId;
  return '<button data-action="select-project" data-id="' + p.id + '" class="w-full rounded border p-3 text-left ' + (active ? 'border-slate-950 bg-white' : 'border-slate-200 bg-slate-50') + '">' +
    '<div class="flex items-center justify-between gap-2"><strong>' + esc(p.name) + '</strong><span class="rounded bg-slate-100 px-2 py-1 text-xs">' + esc(p.stage) + '</span></div>' +
    '<div class="mt-2 text-xs text-slate-500">' + esc(p.owner || 'Unassigned') + ' · ' + esc(p.priority || 'normal') + '</div>' +
  '</button>';
}

function render() {
  if (!selectedId && projectRows[0]) selectedId = Number(projectRows[0].id);
  const selected = projectRows.find(p => Number(p.id) === selectedId) || null;
  const selectedArtifacts = artifactRows.filter(a => Number(a.project_id) === selectedId);
  const selectedEvaluations = evaluationRows.filter(e => Number(e.project_id) === selectedId);
  const selectedReviews = reviewRows.filter(r => Number(r.project_id) === selectedId);
  const root = mount();
  root.innerHTML = '<header class="flex flex-wrap items-end justify-between gap-4"><div><h1 class="text-2xl font-semibold">Foundry</h1><p class="mt-1 text-sm text-slate-600">Project intake, artifact review, evaluation, and decision tracking.</p></div><button data-action="seed-foundry" class="rounded bg-slate-950 px-3 py-2 text-sm text-white">Seed foundry</button></header>' +
    '<section class="mt-6 grid gap-6 lg:grid-cols-[320px_1fr]">' +
      '<aside><form id="foundry-intake" class="rounded border bg-white p-4 shadow-sm"><h2 class="font-semibold">New project</h2><input name="name" required placeholder="Project name" class="mt-3 w-full rounded border px-3 py-2"><input name="owner" placeholder="Owner" class="mt-3 w-full rounded border px-3 py-2"><button class="mt-3 rounded border px-3 py-2 text-sm">Create</button></form><div class="mt-4 space-y-2">' + (projectRows.length ? projectRows.map(projectCard).join('') : '<div class="rounded border border-dashed p-4 text-sm text-slate-600">No projects yet.</div>') + '</div></aside>' +
      '<main class="rounded border bg-white p-4 shadow-sm">' + (selected ? detailHtml(selected, selectedArtifacts, selectedEvaluations, selectedReviews) : '<p class="text-sm text-slate-600">Select or create a project.</p>') + '</main>' +
    '</section>';
  wireEvents(root);
}

function detailHtml(project: Row, projectArtifacts: Row[], projectEvaluations: Row[], projectReviews: Row[]): string {
  return '<div class="flex flex-wrap items-start justify-between gap-4"><div><h2 class="text-xl font-semibold">' + esc(project.name) + '</h2><p class="mt-1 text-sm text-slate-600">Stage: ' + esc(project.stage) + '</p></div><div class="flex gap-2">' + stages.map(stage => '<button data-action="advance-project" data-stage="' + stage + '" class="rounded border px-3 py-2 text-sm">' + esc(stage) + '</button>').join('') + '</div></div>' +
    '<div class="mt-6 grid gap-4 md:grid-cols-3"><section><h3 class="font-semibold">Artifacts</h3>' + (projectArtifacts.length ? projectArtifacts.map(a => '<div class="mt-2 rounded border p-3 text-sm"><strong>' + esc(a.title) + '</strong><div class="text-slate-500">' + esc(a.kind) + ' · ' + esc(a.status) + '</div></div>').join('') : '<p class="mt-2 text-sm text-slate-500">No artifacts.</p>') + '<button data-action="add-artifact" class="mt-3 rounded border px-3 py-2 text-sm">Add artifact</button></section>' +
    '<section><h3 class="font-semibold">Reviews</h3>' + (projectReviews.length ? projectReviews.map(r => '<div class="mt-2 rounded border p-3 text-sm"><strong>' + esc(r.status) + '</strong><div class="text-slate-500">' + esc(r.decision || 'pending') + '</div></div>').join('') : '<p class="mt-2 text-sm text-slate-500">No reviews.</p>') + '<button data-action="add-review" class="mt-3 rounded border px-3 py-2 text-sm">Queue review</button></section>' +
    '<section><h3 class="font-semibold">Evaluation</h3>' + (projectEvaluations.length ? projectEvaluations.map(e => '<div class="mt-2 rounded border p-3 text-sm"><strong>' + esc(e.verdict) + '</strong><div class="text-slate-500">Score ' + esc(e.score ?? 'n/a') + '</div></div>').join('') : '<p class="mt-2 text-sm text-slate-500">No evaluation.</p>') + '<button data-action="add-evaluation" class="mt-3 rounded border px-3 py-2 text-sm">Add evaluation</button></section></div>';
}

async function load() {
  const [p, a, e, r] = await Promise.all([
    projects.list({ limit: 100 }).catch(() => []),
    artifacts.list({ limit: 250 }).catch(() => []),
    evaluations.list({ limit: 250 }).catch(() => []),
    reviews.list({ limit: 250 }).catch(() => []),
  ]);
  projectRows = p;
  artifactRows = a;
  evaluationRows = e;
  reviewRows = r;
  render();
}

async function seed() {
  const project = await projects.create({ name: 'Vendor Diligence', owner: 'Operations', stage: 'intake', priority: 'high' });
  await artifacts.create({ project_id: project.id, title: 'Security packet', kind: 'document', status: 'review' });
  await reviews.create({ project_id: project.id, reviewer: 'Compliance', status: 'queued', decision: 'pending' });
  await evaluations.create({ project_id: project.id, score: 72, verdict: 'pending', notes: 'Needs final artifact review.' });
  selectedId = Number(project.id);
  await load();
}

function wireEvents(root: HTMLElement) {
  root.querySelector('#foundry-intake')?.addEventListener('submit', async ev => {
    ev.preventDefault();
    const form = ev.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const name = String(data.get('name') || '').trim();
    if (!name) return;
    const row = await projects.create({ name, owner: String(data.get('owner') || ''), stage: 'intake', priority: 'normal' });
    selectedId = Number(row.id);
    form.reset();
    await load();
  });
  root.querySelectorAll('[data-action]').forEach(el => el.addEventListener('click', async ev => {
    const target = ev.currentTarget as HTMLElement;
    const action = target.dataset.action;
    if (action === 'seed-foundry') await seed();
    if (action === 'select-project') { selectedId = Number(target.dataset.id); render(); }
    if (!selectedId) return;
    if (action === 'advance-project') { await projects.update(selectedId, { stage: target.dataset.stage }); await load(); }
    if (action === 'add-artifact') { const title = window.prompt('Artifact title'); if (title) { await artifacts.create({ project_id: selectedId, title, kind: 'document', status: 'draft' }); await load(); } }
    if (action === 'add-review') { await reviews.create({ project_id: selectedId, status: 'queued', decision: 'pending' }); await load(); }
    if (action === 'add-evaluation') { await evaluations.create({ project_id: selectedId, score: 0, verdict: 'pending', notes: 'Draft evaluation' }); await load(); }
  }));
}

bm.live.scoped('*' as any, load, { debounce: 100 });
void load();
`

const curatedFoundryAdvanceFlowYAML = `on:
  request:
    method: POST
    path: /api/foundry/projects/:id/advance
    auth: required

jobs:
  advance:
    steps:
      - run: sql
        query: UPDATE foundry_projects SET stage = :stage WHERE id = :id
        with:
          params:
            stage: ${{ params.stage }}
        expect_rows: ">0"

      - run: sql
        query: INSERT INTO foundry_reviews (project_id, reviewer, status, decision, notes) VALUES (:project_id, :reviewer, :status, :decision, :notes)
        with:
          params:
            project_id: ${{ params.id }}
            reviewer: ${{ user.email | default:'' }}
            status: ${{ params.review_status | default:'queued' }}
            decision: ${{ params.decision | default:'pending' }}
            notes: ${{ params.notes | default:'stage advanced' }}

      - run: respond
        with:
          body:
            ok: true
            project_id: ${{ params.id }}
            stage: ${{ params.stage }}
`
