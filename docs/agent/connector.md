# Make an app MCP-compatible

The platform MCP at `/mcp` builds and manages apps. Each app's connector at
`/api/_mcp` lets its users connect an MCP client to reviewed app tools. Platform
credentials cannot substitute for an app user's consent and permissions.

You need the installed CLI and your **app project files**. You do not need the
Benmore framework's Go source, Go, Node, or a compiler to author/review a native
connector. This guide ships inside the CLI that prints it: `benmore version`
names that CLI, and a deployed app's `/health` (`version`) names its runtime.
Run `benmore mcp --help` for the installed commands. The hosted reference is
`benmore api <app> connector`.

## Start from the app's actual files

For an existing deployed app, use a fresh project directory so remote source and
local source agree before adding the connector:

```sh
benmore pull <app> <project-dir> --env dev
cd <project-dir>
```

Pull downloads app source, not production databases, uploads or secrets. Inspect
`schema.prisma`/`schema.sql` and `app.yaml`. Use the actual table, column, access
and role declarations; the example below is for the standard Notes scaffold.
Server-created HTML apps and self-hosted framework starters include a reviewed
Notes manifest. Replace its tool bindings when replacing the demo, then review
the changed project again. Removing the `Note` model is a destructive schema
change: deploy it, and let the app migrate, before a new reviewed `mcp.yaml`
(see Common setup errors). Hosted CLI `benmore new` omits that manifest so its
documented first `benmore deploy` works. Deploy first, pull the complete remote
source into a fresh directory, then author and review a connector there. The
unlinked-app review guard still refuses an already reviewed `mcp.yaml` whose
digest cannot cover source the server contributes during creation.

## Complete native manifest

Create `mcp.yaml` at the app root. This complete authoring example omits digests
on purpose: the review command generates them. `kind: table` and `operation:
list` are not supported handler names; use `kind: native` and `table.list`.

```yaml
version: 1
connector:
  id: notes
  name: Notes
  version: '1'
tools:
  - name: list_notes
    description: Read your notes with bounded pagination
    handler: {kind: native, operation: table.list, table: notes}
    input_schema:
      type: object
      additionalProperties: false
      properties:
        page: {type: integer, minimum: 1}
        per_page: {type: integer, minimum: 1, maximum: 500}
    output_schema:
      type: object
      additionalProperties: false
      properties:
        id: {type: integer}
        title: {type: string}
        body: {type: string}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, title, body]}
    component: none
resources: []
connections: []
```

`output_schema` describes each projected row, not the whole MCP result envelope.
The runtime adds data, pagination, freshness, completeness and revision fields.
Page defaults are 1 and 50 rows; a result is not a promise that all notes were
returned. The tool's `notes:read` scope constrains the caller's existing access;
it never grants another user's rows or bypasses app access/role/read masks.

For a point read, declare `operation: table.read` with required input `id` and
its actual primary-key type. A read flow uses `handler: {kind: native,
operation: flow.call, flow: <flow-name>}` and must match a uniquely registered,
synchronous, effect-free flow's inputs/output. Business writes use reviewed
`kind: flow, operation: command` declarations and first-party human approval;
changing a read tool's `effect` to `write` does not create a command. See the
hosted `connector` and `flows` recipes before adding commands, files, UI resources
or external connections. `mcp generate` produces disabled OpenAPI candidates,
not a deployable native manifest or an approved external connector.

## Review, validate, deploy, enable

Review the app source and the exact tools, permissions and output projections
first. Then, from the app directory:

```sh
benmore mcp review . --reviewed
benmore mcp check .
benmore mcp inspect . --json
benmore deploy . --env dev
benmore mcp status <app> --env dev
benmore mcp enable <app> --env dev
```

Review strictly validates the manifest, configuration and canonical source
bindings, computes both digests and atomically writes the reviewed manifest. It
accepts missing/stale digest values only in this explicit review path. It does
not open app data, enable access or approve an operation. Check/inspect remain
read-only and require a sealed manifest. Local success does not prove the
physical database, host authority directory, current grant or a real client.

Review edits only its own top-level keys (`contract_digest`,
`execution_digest`, `execution_sources`) and keeps the rest of `mcp.yaml` as you
wrote it: integers, quoting, comments and indentation. Reviewing a reviewed
file again keeps its bytes and digests. Omitted optional `tools`, `resources`
and `connections` arrays stay omitted; explicit `null` is invalid. See the
hosted `connector` recipe's `review_serialization` entry.

The generated `contract_digest` and `execution_digest` are **top-level keys**,
next to `version`, `connector` and `tools`, never under `connector`, a tool or a
`review` block. Each is a lowercase 64-character SHA-256. Do not invent, copy
from another app, or calculate these hashes by hand. The contract digest binds
reviewed declarations; the execution digest binds the exact bytes of every
file the runtime can load, execute or serve. Review writes a top-level
`execution_sources: runtime` key (part of the contract digest) to say so:
`static/`, `flows/`, `partials/`, `layouts/`, `i18n/`, `migrations/`, `emails/`,
`templates/`, the root config and schema files, `seeds.sql`, `head.html`,
`theme.css`, `tsconfig.json`, `package.json`, the favicon, root `*.html` pages,
and each `connections[].openapi` document with the JSON/YAML files beside it
(for a document at the app root: the JSON/YAML files at the root and below).
`docs/`, root `*.md`, `src/`, `tests/` and hidden directories outside those
trees (`.sdd/`, `docs/x/.verify/`) do not move it, so a hosted instance may hold
files a checkout lacks. A manifest without the key was reviewed over the whole
tree and keeps validating that way until you run review again. Every
runtime-source edit requires another review. Runtime and upload validation
reject missing/incorrect digests.

Deploy sends dependencies before `mcp.yaml` and requests a final reload. Pushes
with multiple named files also send `mcp.yaml` last. Both put root
`schema.prisma`, `schema.sql` or `schema.yaml` first, then `app.yaml`, then the
remaining dependencies in their existing order. This lets command flows refer
to tables added in the same batch; every upload still passes source validation. If only the manifest changed
and local source exactly matches the server, `benmore push mcp.yaml --env dev`
is sufficient; otherwise deploy the full reviewed project. Extra server files
also change the digest: reconcile source with pull/sync-status instead of forcing
an unrelated snapshot. That includes, for a manifest still in the whole-tree form, server files pull
never writes (hidden directories outside `static/` such as `.sdd/`), and in
either form such files under `flows/` or `emails/`: deploy of `mcp.yaml` is
blocked naming them, and the `mcp_connector_withheld` warning lists them; delete
them on the server or keep identical copies locally, then review again. Deploy
does not upload a hidden directory outside `static/`: when the digest covers a
workspace file in one that the server lacks or holds with other content, deploy
of `mcp.yaml` is blocked naming it; send it with `benmore push <file>`, or move
it to a plain directory and review again. Editor/agent
auto-run config outside `static/` (`.vscode/`, `.mcp.json`, ...) is not part of
the digest: hosted apps refuse it and deploy keeps it local. An interrupted multi-file deploy is not atomic; inspect
its reported failures, correct/review the intended source and rerun it.

Enable requires the app owner and a loaded, valid manifest plus a configured
instance authority directory. If status reports `authority_configured:false`,
an operator must provision it; a CLI flag cannot bypass this. Use an explicit `--env` when dev and prod both exist.
Approved writes stay off until the owner enables `--writes` on an app declaring
approved commands. Export and publication have separate opt-ins.

A restart or runtime upgrade turns approved writes off first (the new process may
carry new code, migrations or environment) and rotates the write epoch, so an
operation prepared or approved before it never runs. Writes then resume on their
own only when the owner state still records the reviewed contract and execution
digests the owner approved, the loaded `mcp.yaml` carries those same digests, read
exposure is on and the revision enrollment is active for the current owner epoch
and verifies against the database. Otherwise `benmore mcp status` shows
`approved_writes_off_reason` and the owner runs `enable --writes` again. An owner
`disable`, `--revoke`, a restore, a hot reload or an environment change forgets the
approval, so a later restart never resumes it. A hot reload is any push or
source write that reloads the app, so the edit that leaves `mcp.yaml`'s review
stale and the push of the new review each turn approved writes and auto-approve
off: a review restores the connector's reads, grants and exposure, not its
write approval. `approved_writes_off_reason` says when a reload did this, until
the owner changes a switch.

Users connect their MCP client to `https://<app-host>/api/_mcp`, sign in as their
own app user and consent to explicit scopes. A successful owner enable is not
proof of a real-client connection. Test allowed and denied identities, revocation
and the actual user workflow before calling the app fully accepted.

### Test a hosted connector from a script

A script can play both the MCP client and the approving person. It needs a
dedicated test app user whose password stays out of the script and its logs
(read it from the environment), and a cookie jar that does not follow
redirects. `ORIGIN` is the instance, for example
`https://<app>-dev.<platform domain>`; the resource is `ORIGIN + "/api/_mcp"`.

1. Sign in: `GET /api/_csrf`, then `POST /login` with JSON
   `{email, password}`, header `X-CSRF-Token: <token>` and
   `Accept: application/json`. Keep the session cookie.
2. Register a client: `POST /oauth/register` with JSON
   `{client_name, redirect_uris: ["http://127.0.0.1:8765/cb"], grant_types:
   ["authorization_code", "refresh_token"], response_types: ["code"],
   token_endpoint_auth_method: "none", scope: "<tool permissions>"}`. A
   loopback `http` redirect is accepted; nothing needs to listen on it. Scopes
   the app does not offer are dropped, and the answer's `grant_types` names
   both grants.
3. Make a PKCE pair: a 43-128 character `verifier` and
   `challenge = base64url(sha256(verifier))` without padding. With the cookie,
   `GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&state=...&scope=...&code_challenge=...&code_challenge_method=S256&resource=<resource>`.
   An account in several workspaces gets a picker first; repeat with
   `&workspace=<id>`.
4. The consent page holds one form that posts to `/oauth/authorize`. Send every
   hidden input back unchanged (`response_type`, `client_id`, `redirect_uri`,
   `state`, `scope`, `code_challenge`, `code_challenge_method`, `resource`,
   `workspace`, `connector_nonce`, `consent`) plus `decision=approve`,
   form-encoded, with `Origin: ORIGIN`. Add `auto_approve=1` only if the page
   offers it and you want it. The `302` `Location` carries `code` and `state`.
5. `POST /oauth/token` form-encoded with `grant_type=authorization_code`,
   `code`, `redirect_uri`, `client_id`, `code_verifier` and `resource`. Refresh
   later with `grant_type=refresh_token`, `refresh_token`, `client_id` and
   `resource`.
6. Call tools: `POST <resource>` with a JSON-RPC body,
   `Authorization: Bearer <access_token>`,
   `Accept: application/json, text/event-stream` and an
   `MCP-Protocol-Version` header. An event-stream answer carries the JSON in its
   last `data:` line. A command tool returns `operation_id` and `review_url`.
7. Approve as the signed-in person: with the cookie, `GET review_url`, read the
   hidden `_csrf` input (bound to that session and that operation) and `POST`
   it form-encoded to the form's action (`<review_url>/approve`) with
   `Origin: ORIGIN`. A `303` back to the review page means approved. The bearer
   token can never approve.
8. Call `_commit` with `{operation_id}`, then `_status`.

```python
import base64, hashlib, html, json, re, secrets, urllib.request

def pkce():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

def hidden_fields(page):
    form = re.search(r'<form[^>]*method="post"[^>]*>(.*?)</form>', page, re.S | re.I).group(1)
    fields = dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', form))
    return {name: html.unescape(value) for name, value in fields.items()}

def rpc(origin, access_token, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(origin + "/api/_mcp", data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + access_token,
        "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"})
    text = urllib.request.urlopen(request).read().decode()
    lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    return json.loads(lines[-1] if lines else text)
```

## Point reads and read flows

For a point read, add a tool to the same manifest. This example matches the
standard Notes scaffold's integer primary key and `notes:read` permission:

```yaml
- name: read_note
  description: Read one note
  handler: {kind: native, operation: table.read, table: notes}
  input_schema:
    type: object
    additionalProperties: false
    required: [id]
    properties:
      id: {type: integer, minimum: 1, maximum: 9007199254740991}
  output_schema:
    type: object
    additionalProperties: false
    properties:
      id: {type: integer}
      title: {type: string}
      body: {type: string}
  permissions: [notes:read]
  effect: read
  approval: none
  idempotency: none
  reconciliation: none
  output: {include: [id, title, body]}
  component: none
```

Text primary keys need a bounded string schema. Native list inputs may include
`page`, `per_page`, `sort`, `order`, `q` and closed `filters`; declare only
inputs that match the app's real readable fields and indexes. `order` requires
`sort`; `q` requires the app's full-text index. Undeclared and ignored inputs
are refused. Read masks and current row access still apply.

Use a flow when a read needs a business-specific projection or row predicate.
This is a minimal Notes pattern; adapt its columns and ownership condition to
the app's actual schema:

```yaml
on:
  request:
    method: GET
    path: /api/mcp-note/:id
    auth: required
    role: editor
    permissions: [notes:read]
jobs:
  read_note:
    steps:
      - id: note
        query: SELECT id, title FROM notes WHERE id = :id AND user_id = :user_id
      - run: respond
        with:
          body: ${{ steps.note.outputs.rows[0] }}
```

Bind it with `handler: {kind: native, operation: flow.call, flow: read_note}`,
an input schema requiring integer `id`, a closed output schema containing
`id` and `title`, `permissions: [notes:read]`, the read-only policy fields,
`output: {include: [id, title]}` and `component: none`. The flow must be uniquely
registered, synchronous and effect-free. Route and tool permissions must agree;
the flow's SQL must scope rows itself (`auth` and permission declarations do not
add SQL predicates). Connector flow reads run read-only.
Mutating SQL, API/email/webhook/enqueue effects, async flows and parallel steps
are rejected. Do not bind a command flow with `flow.call`.

## Approved business commands

Commands are for a specific business action. They use `kind: flow` with
`operation: command`; a read tool cannot become a write by changing its effect.
The following tool declaration is for an app with `tasks(id, project_id, status,
completed_by)` and a `tasks:write` scope:

```yaml
- name: complete_task
  description: Prepare completion of one task for review
  handler: {kind: flow, operation: command, flow: complete_task}
  input_schema:
    type: object
    additionalProperties: false
    required: [arguments]
    properties:
      arguments:
        type: object
        additionalProperties: false
        required: [id, project_id]
        properties:
          id: {type: integer, minimum: 1, maximum: 9007199254740991}
          project_id: {type: integer, minimum: 1, maximum: 9007199254740991}
  output_schema:
    type: object
    additionalProperties: false
    required: [id, status]
    properties:
      id: {type: integer, minimum: 1, maximum: 9007199254740991}
      status: {type: string, minLength: 1, maxLength: 32}
  permissions: [tasks:write]
  effect: write
  approval: first_party
  idempotency: operation
  reconciliation: authoritative_readback
  output: {include: [id, status]}
  component: none
```

The matching `flows/complete_task.yaml` command declaration follows. It is a
minimal example; a real app must add its actual owner/group predicates and
every consequence to the preview:

```yaml
command:
  version: 1
  prepared_schema:
    type: object
    additionalProperties: false
    required: [id, project_id]
    properties:
      id: {type: integer, minimum: 1, maximum: 9007199254740991}
      project_id: {type: integer, minimum: 1, maximum: 9007199254740991}
  preview_schema:
    type: object
    additionalProperties: false
    required: [status]
    properties:
      status: {type: string, minLength: 1, maxLength: 32}
  writes: [tasks]
  dependencies:
    - name: selected_task
      table: tasks
      query: SELECT id FROM tasks WHERE id = :id AND project_id = :project_id AND status <> 'done'
      params: {id: '${{ params.arguments.id }}', project_id: '${{ params.arguments.project_id }}'}
      max_rows: 1
jobs:
  prepare:
    steps:
      - id: selected_task
        run: sql
        with:
          query: SELECT id, status FROM tasks WHERE id = :id AND project_id = :project_id AND status <> 'done'
          params: {id: '${{ params.arguments.id }}', project_id: '${{ params.arguments.project_id }}'}
      - run: respond
        with:
          status: 200
          json:
            arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}'}
            preview: {status: '${{ steps.selected_task.outputs.first.status }}'}
  apply:
    steps:
      - id: complete_task
        run: sql
        expect_rows: '=1'
        with:
          query: UPDATE tasks SET status = 'done', completed_by = :actor WHERE id = :id AND project_id = :project_id AND status <> 'done'
          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', actor: '${{ user.id }}'}
      - run: respond
        with: {status: 200, json: {ok: true}}
  readback:
    steps:
      - id: completed_task
        run: sql
        with:
          query: SELECT t.id, t.status FROM tasks AS t WHERE t.id = :id AND t.project_id = :project_id
          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}'}
      - run: respond
        with:
          status: 200
          json:
            id: '${{ steps.completed_task.outputs.first.id }}'
            status: '${{ steps.completed_task.outputs.first.status }}'
```

As written, a task that does not exist or is already done leaves the prepare
`respond` without a row to read, and the tool answers `unavailable_provider`.
Count the row first and refuse with a message (see "Refuse in prepare with a
message").

A command file is `flows/<name>.yaml`, and `<name>` is the command's name: it
starts with a lowercase letter and holds only lowercase letters, digits and
underscores, 1 to 64 characters (`flows/receive_stock.yaml`; a hyphen, capital
letter or dot is refused). Once the app has an `mcp.yaml`, every command flow
must be bound by exactly one tool in it: one that no tool binds, or that two
bind, is refused with `command "<name>" requires exactly one declaration
binding`. In an app with no
`mcp.yaml` a command flow loads without a connector: it cannot run, and the
columns it lists under `command.owns` are still refused to generic CRUD
(`benmore docs scoping.command_owned_fields`).

Every command flow needs the three jobs `prepare`, `apply` and `readback` and 1
to 64 `dependencies` (an insert-only command still names one, for example the
row it must not duplicate); review refuses `missing "readback"`,
`missing "dependencies"` and `dependencies must contain 1..64 entries`.

Each `dependencies` query must return exactly one column named `id` (`t.id` and
`id AS ID` qualify). Review, `mcp check`, the push write gate and
`benmore check` prepare each query against an empty copy of the schema and refuse
`dependency "<name>" must return exactly one id column`, naming the columns it
returns. A query the schema files alone cannot prepare (a column a migration adds)
is checked at run time instead, where prepare fails with `invalid_declaration`.

Command SQL (dependency queries and the SQL of all three jobs) may call only the
functions listed under "Triggers you wrote on a written table" below, without
the three only triggers may call. Review, `mcp check`, the push write gate and `benmore check` compile
each statement against the same empty copy of the schema and refuse any other
call (`random`, `randomblob`, `iif`, a misspelled name) with
`<statement> calls function "<name>", which approved commands cannot run` and
the allowed list. A statement the schema files alone cannot compile is checked
at run time instead, where it fails with `invalid_declaration` naming the
function. Review does not judge column names, because the schema files do not
list the columns a migration adds: SQL that names a column the database does
not have fails at run time with `invalid_declaration` (the message does not
name the column; the app's log does).

A command permission is `<table>:read|write` for a declared table, or a
capability scope `<capability>:<action>` (for example `billing:write`) when some
role in `app.yaml` `roles:` grants that resource, directly or through `inherits:`;
a name no role grants is refused, and wildcards stay refused. The action of a
capability is any identifier, and one permission must be a declared write table's
`:write` or a capability's `:write`. The actor and the connector grant must both
hold the scope. Command SQL bindings may also use `${{ user.role }}` (the actor's
global framework role string, not a tenant membership role) and
`${{ user.is_admin }}` (1 for a global admin, else 0; no admin bypass) in prepare
and apply SQL only, bound from the live actor of that phase. Both are sealed when the operation is
prepared; if the role or admin flag changes before approve or commit the
operation is refused and must be prepared again.

Optional arguments: declare a property without listing it in `required`, and mark
it nullable with either `type: [string, "null"]` (or `["null", string]`) or
`nullable: true` (the same spelling works in `prepared_schema`). Clients see the
standard JSON Schema `type: [string, "null"]`. A SQL binding may name any declared
string, integer, number or boolean property, optional or nullable included; a
missing or null value binds SQL `NULL`, so write the SQL with
`COALESCE(:note, note)` rather than asking callers to send an empty string. A
boolean binds as `1` or `0`; a number binds as an integer when it is whole and
otherwise as a finite float. `${{ params.note }}` in the prepare `respond` carries an
omitted optional argument forward as an explicit `null` when the target
`prepared_schema` field is `nullable`, and leaves the key out of the sealed
arguments when it is not, so an optional, non-nullable argument can really be
omitted and the approved operation is one deterministic shape either way.
`| default:` is not supported in command bindings; use `COALESCE`.
`for_each` sources (the array and its `items`), dependency params and transfer
paths still need a required, non-nullable path; a nullable one is refused at
review.

**A command's SQL is not checked against the table's `access:` rule.** The
runtime checks the tool's `permissions` against the actor's and the grant's
scopes, then validators, workflow states and transition role guards, record
locks and applicable hooks. Which rows the command may touch is decided by its
SQL alone: a caller who holds the permission can change every row the SQL
matches, including a row their own `PATCH` is refused on. So the prepare SQL and
the apply SQL must each carry the owner, tenant and role predicate, bound from
the actor and never from an argument:

```yaml
- id: cancel_order
  run: sql
  expect_rows: '=1'
  with:
    query: UPDATE orders SET status = 'cancelled' WHERE id = :id AND status = 'placed' AND (user_id = :actor OR :role = 'manager')
    params: {id: '${{ params.id }}', actor: '${{ user.id }}', role: '${{ user.role }}'}
```

On a group-keyed table add `AND org_id = :tenant`, bound to
`${{ user.group_id }}`. In an app whose `app.yaml` has no `roles:` block every
account holds every `<table>:write` scope, so there the permission tells no two
accounts apart and the SQL predicate is the only thing that does.

Use actual domain bounds, bind every value, and make the preview describe
the exact proposed change. Review/check/deploy the command first; then the owner
enables writes separately:

```sh
benmore mcp enable <app> --writes --env dev
```

Commands need a durable `ENCRYPTION_KEY`: prepared operations, approvals and
attempt history are sealed under it, and a load whose `mcp.yaml` binds a
command refuses without one (`operation lifecycle requires configured
ENCRYPTION_KEY`). On the hosted platform the push or deploy that adds commands
to an instance without a key restarts the app instead of hot reloading it, and
the restart pins a key in that instance's environment, as it does for encrypted
fields; `benmore restart <app> --env dev` does the same. An
existing key is never replaced. `benmore check` and `benmore mcp check` warn
while the key is missing. Self-hosted or with `benmore serve --mcp-local`, set
`ENCRYPTION_KEY` (`openssl rand -hex 32`) in `env.yaml` or the environment
before the first start, and keep it: once commands have run, changing it needs
the key-rotation workflow.

The command call only prepares an operation and returns its ID, preview, expiry
and first-party review URL. A person signs in to the app and approves that exact
operation in the browser; `_commit` applies it once, and `_status` reads its
durable state and receipt. There is no MCP approval tool. Connector bearer
credentials, API tokens and impersonated sessions cannot approve.
Prepared approvals expire after 15 minutes. Treat `prepared`, `approved`,
`running`, `succeeded`, `failed`, `conflict`, `unknown`, `expired` and `denied` as
distinct states. Retry only when status says retryable; an unknown result needs
recovery, not a blind second mutation. Business commit and any external delivery
are separate outcomes.

Two failures are final. `constraint_failed` means the apply SQL hit a
FOREIGN KEY, UNIQUE, NOT NULL or CHECK constraint (for example deleting a row other
rows still reference); the change was rolled back, the message names only the
constraint kind, `_status` says `retryable: false`, and `_commit` answers the same
code again. `invalid_declaration` means the reviewed command cannot run against
the database, such as a dependency query that does not return one `id` column,
SQL that calls a function commands cannot run, or SQL that names a column the
database does not have.
Fix the data or the source and prepare a new operation. Genuine outages stay
`unavailable_provider` and remain retryable.

`denied` means the operation has not expired but cannot commit right now, and
`_commit` gives its owner the same answer: `_status` carries `reason` and a failed
`_commit` carries `_meta.reason`, one of `source_changed`, `actor_changed` or
`approval_lapsed`. Prepare the operation again. Another caller gets a bare `denied`.
The review page shows the same state and reason to its owner: an approval whose
browser session has ended (for example, the person signed out) reads "The
approval no longer holds", never "Approved", and an operation blocked by a role
or source change is shown with its reason and cannot be approved. One operation
takes one approval, so the person asks the assistant to prepare it again and
stays signed in until the new one is applied. An `approval: grant` approval is
described as coming from the connection's consent; only `_status` can say
whether that consent still holds.

A command input that does not match `input_schema` fails `invalid_input` naming
the JSON path and the rule (`... at arguments.status: value is not in enum.`),
never the value itself.

A prepared result also carries `batch_review_url`
(`/api/_mcp/operations/batch?grant=<id>`): one page listing every pending,
unexpired change that connection prepared for the signed-in person, approved
together in one POST. Nothing is ticked for the person; each selected change
spends the approval rate limit as it is approved. The person's unexpired changes
that can no longer be applied are listed under "Can't be applied" with the
reason, without a checkbox. It has the single-operation page's gates (cookie session
only, direct login, rate limits, CSP), one CSRF token bound to the session and
that grant, and still records one human approval per operation.

### Sign a removed member out

A command that removes a member can also end that user's sign-ins. The apply
step `run: revoke_user_sessions` deletes the user's sessions, API tokens and
OAuth codes and revokes their connector grants in this app, inside the command
transaction: if anything later in the apply fails nothing is revoked, and on
commit the user is out at the same instant the membership row is gone.

```yaml
command:
  version: 1
  prepared_schema:
    type: object
    additionalProperties: false
    required: [member_id]
    properties:
      member_id: {type: integer, minimum: 1, maximum: 9007199254740991}
  # ...preview_schema, dependencies...
  writes: [members]
jobs:
  apply:
    steps:
      - id: remove_member
        run: sql
        expect_rows: '=1'
        with:
          query: DELETE FROM members WHERE user_id = :member AND org_id = :tenant
          params: {member: '${{ params.member_id }}', tenant: '${{ user.group_id }}'}
      - id: sign_out
        run: revoke_user_sessions
        with:
          user_id: ${{ params.member_id }}
      - run: respond
        with: {status: 200, json: {ok: true}}
```

Rules, all enforced by the runtime:

- `user_id` is a `${{ params.<path> }}` reference to a **required, non-nullable
  integer** in `prepared_schema`. A literal, `${{ user.id }}`, a step output or
  a loop value is refused at review. The step is apply-only and cannot sit in a
  `for_each`.
- The apply is refused (and rolls back whole, error class `denied`) when the
  target is the acting user, a framework admin (the `role` column or a global
  admin grant), or did not hold a live membership in the actor's selected
  tenant when the apply began. A membership the same apply removes counts, so
  the step may come before or after the `DELETE`. Soft-deleted and inactive
  (`groups.active_field`) rows are not memberships; an email-keyed membership
  counts only for a verified account.
- It needs the `groups:` tenant model. An app without `groups:`, or an actor
  with no selected tenant, has every revoke refused.
- Sessions are not tenant-bound, so a target who is also a member of another
  tenant is signed out of it too.
- The review page lists the step ("End every sign-in, API token and connector
  grant of the member this change names"). That is the only consent surface: an
  `approval: grant` command carrying the step applies without a browser trip
  like any other.
- It writes one `mcp_command_revoke_sessions` audit row (user ids only).
- Ordinary flows cannot use it; the write gate refuses the step there.

### Triggers you wrote on a written table (`app_triggers`)

Enabling approved writes refuses a table that carries a trigger the framework
did not generate (`unrecognized or changed trigger ... on enrolled table`): an
unknown trigger could write tables the revision ledger never sees. The triggers
the framework generates from your own declarations (`@updatedAt`, `@@fulltext`,
computed and encrypted fields, `versioned:` history) are accepted when their
stored definition is exactly the generated one, so a command can write a
versioned table: each update or delete it makes records a version in the
command's transaction, with `_changed_by` set to the user who approved it. A
command can declare its own triggers instead. The declaration only points at a trigger;
its SQL comes from the `CREATE TRIGGER` statement in a reviewed `migrations/*.sql`
file (the UP section):

```yaml
command:
  version: 1
  writes: [tasks]
  app_triggers:
    - {table: tasks, name: task_done_log}
```

```sql
-- migrations/0002_task_log_trigger.sql
CREATE TRIGGER task_done_log AFTER UPDATE ON tasks FOR EACH ROW WHEN NEW.status = 'done'
BEGIN
  INSERT INTO task_log(task_id, note) VALUES (NEW.id, 'done');
END;
```

Enrollment compares the live `sqlite_schema` text with that statement (whitespace,
comments and keyword case ignored, quoted text exact); a trigger that differs,
is undeclared, or is declared but not created by a reviewed migration still
fails. Every table the body writes (`task_log` above, which must be a table in
the app's schema) joins the revision universe, recursively through the triggers
and foreign keys of those tables, and so is writable by the command at apply.
A table the WHEN clause or body only selects from (a lookup such as `projects`
in `WHEN EXISTS (SELECT 1 FROM projects WHERE id = NEW.project_id)`) joins the
universe as read-only, because a command may read only universe tables. A body
that writes or reads a `_benmore_*` or other non-app table, uses `OR REPLACE`,
joins with commas, or holds a statement other than SELECT/INSERT/UPDATE/DELETE
is refused. Only
`migrations/` counts: a trigger created by `schema.sql` or by hand stays
refused. To change a trigger, `DROP TRIGGER`
and `CREATE TRIGGER` again in a new migration (a second `CREATE` alone is
skipped as already applied), then review and re-enroll. The WHEN clause and body
may call only these functions: `abs`, `avg`, `char`, `coalesce`, `concat`,
`concat_ws`, `count`, `date`, `datetime`, `benmore_today`, `glob`, `hex`, `ifnull`, `instr`,
`length`, `like`, `lower`, `ltrim`, `max`, `min`, `nullif`, `printf`, `quote`,
`replace`, `round`, `rtrim`, `sign`, `sqlite_version`, `substr`,
`substring`, `sum`, `time`, `total`, `trim`, `typeof`, `unicode`, `upper`,
`zeroblob`, `julianday`, `strftime` and the `json`, `json_array`,
`json_array_length`, `json_group_array`, `json_extract`,
`json_insert`, `json_object`, `json_patch`, `json_remove`, `json_replace`,
`json_set`, `json_type`, `json_valid`, `json_quote` family, plus `raise`, `current_timestamp`
and `benmore_encrypt`, which only triggers may call. Any other call (`random`, `randomblob`, `iif`) and bare
`current_date`/`current_time` make enrollment fail, so the trigger is refused when
you enable writes, not on the first command.

### Review text for the approver

The review page and the batch page show what the person is approving. By
default they have only the model-facing `description` and the preview, so a
command tool can declare human-facing text in `mcp.yaml` (command tools only;
all optional, all part of the contract digest, and a manifest that declares
none keeps the digest it has):

```yaml
- name: set_priority
  title: Change a lead's priority          # at most 80 characters
  review_summary: Changes one field on one lead. Nothing else is touched.   # at most 500
  labels:                                   # at most 60 characters each
    lead_name: Lead
    priority: Priority                      # an enum value of the `field` key below
  review_changes:                           # for a flat preview: {lead_name, field, old_value, new_value}
    - {field: field, before: old_value, after: new_value}
    # or a fixed label: - {label: Role, before: old_role, after: new_role}
```

- A `labels` key must name an intent argument property, a preview key or, for
  a `review_changes` entry with `field:`, an enum value of that key. A key
  without a label shows as the humanised name (`project_status` is
  "Project status"). `review_changes` keys must be string-typed
  `preview_schema` properties.
- No control, invisible or direction-changing character is accepted in any of
  the text, and the title and summary are never taken from `description`.
- Every preview key becomes one labelled row. Strings show as written, numbers
  plain, booleans Yes/No, null a dash and nested values as compact JSON, with
  invisible characters written as `\u` escapes.
- A "before" value is shown only when your own prepare step read it on the
  server (a SELECT in the prepare phase) and returned it in the preview. Two
  forms: the flat pair above, or a preview property that `preview_schema`
  declares as an object with exactly `before` and `after`. The value is sealed
  with the operation and approved as is; it is never re-read at review time,
  and a model-supplied object the schema does not declare that way is never
  shown as a pair. Fill a before key from the prepare step's own SQL read of the
  current row, never from `${{ params.* }}`: the page shows whatever the prepare
  step put there, and a person trusts that column. Native `table.update` tools are private and never reviewed,
  so they have no before/after.
- A prepared connector call also returns `approval_reason`, a fixed phrase
  for why it was not applied automatically: "This kind of change always needs
  your approval" (not `approval: grant`), "Auto-approve is turned off for this
  app", "This connection was not allowed to auto-approve <title>", "The app's
  tools changed since you connected; reconnect the assistant to re-enable
  auto-approve" or "Auto-approve was switched off and on since you connected;
  reconnect to re-enable it". It is stored with the operation and shown on
  the review page. `_commit` still re-checks all three opt-ins.

### Writes without a browser trip per write (opt-in)

A command can apply in the same call that prepares it, with no browser
approval, only when all three opt-ins hold:

1. The reviewed manifest declares `approval: grant` on the command tool
   (command tools only; `table.update` and transfer tools, which push app
   data to an external connection, stay `first_party` and are refused). It
   changes the digests, so review it like any other contract change.
2. The owner turns auto-approval on:
   `benmore mcp enable <app> --writes --auto-approve --env dev`. It refuses
   when no command declares `approval: grant`. `benmore mcp disable <app>
   --auto-approve` turns only it off; turning writes off, a full disable, a
   revoke or a restore also ends it, and each enable mints a new epoch.
3. The user ticks "Let this assistant apply these changes without asking me
   each time" on the consent page. The box is unticked by default and lists
   only live `approval: grant` commands within the connection's scopes, while
   the owner switch is on. The list is stored on that grant; it can only
   shrink, and reconnecting is the only way to change it. The consent is
   bound to the owner's auto-approve epoch at that moment and to the reviewed
   manifest (each tool as `name@<contract digest>`): an owner off/on cycle,
   any write-epoch rotation (every hot reload rotates it) or a change to
   `mcp.yaml` sends the connection
   back to per-write review until the user reconnects and ticks again.
   A grant that does not carry this consent never auto-approves.

The command call then returns the `_commit` result (`outcome`, `receipt` with
`approval_basis: grant_consent:<grant id>`) instead of a review URL. Without
all three it prepares as before. If applying fails, the error carries
`operation_id`; reconcile with `_status` and `_commit`, as after any failed
commit. Each such approval is still a sealed approval row and an
`mcp_command_approve` audit row with its basis, and every `_commit` re-checks
the grant, its consent list, the owner switch and epoch, the declaration and
the role, so revoking the connection, `disable --auto-approve`, re-enabling it,
switching the tool back to `first_party`, a role downgrade or
`disable --writes` stops even a retried commit. Human approvals report
`approval_basis: human`.
### Refuse in prepare with a message

A command's `respond` is normally only the final step of a phase. In
`prepare` alone, an `if` branch (or its `else`) may instead hold exactly one
refusal, so the assistant gets the reason instead of a generic failure:

```yaml
jobs:
  prepare:
    steps:
      - id: ctx
        run: sql
        with:
          query: SELECT count(*) AS found FROM members WHERE user_id = :actor AND org_id = :tenant
          params: {actor: '${{ user.id }}', tenant: '${{ user.group_id }}'}
      - if: ${{ steps.ctx.outputs.first.found }} == 0
        steps:
          - run: respond
            with:
              status: 403
              json: {error: "Only an organization owner, admin or member can create leads."}
      - run: respond
        with: {status: 200, json: {arguments: '${{ params }}', preview: '${{ steps.ctx.outputs }}'}}
```

The accepted shape is exact: the branch holds one step, `run: respond` with
only `status` and `json`; `status` is a literal integer 400-499 except 401 and
407; `json` is exactly `{error: "<text>"}` with a literal string of 1 to 500
characters, no `{{ }}` or `${{ }}` template and no control characters. Anything
else (a template, a 2xx/5xx status, more keys, a respond beside other steps, a
respond anywhere in a `for_each` body, including a refusal `if` nested in one, or a
mid-phase respond in `apply` or `readback`) is refused at review. The refusal ends the prepare before an operation, approval or write
exists, and the tool fails with the code below and your message:

| status | error code |
|---|---|
| 400, 422 | `invalid_input` |
| 409 | `conflict` |
| other 4xx (403, 404, ...) | `denied` |

`apply` and `readback` keep the final-step-only rule: apply runs in the write
transaction, where a refusal must remain an `expect_rows` assertion that rolls
the transaction back. Equality in an `if:` of a command (`== 0`, `== 'x'`) is
evaluated as written; `!=`, `>`, `<`, `>=` and `<=` work the same way.

When an apply step's valid `expect_rows` assertion fails, `_commit` returns
`conflict`; `_status` records a retryable `conflict` attempt after the business
transaction rolls back. Invalid assertions, SQL failures and unavailable row
counts remain `unavailable_provider` operational failures.

### Server-generated tokens (invitations)

A row that needs an unguessable value, such as an invitation token, cannot get
it from SQL: `random()` and `randomblob()` in command SQL would produce a
different value at apply than the one previewed and approved, so they stay
refused. Declare the value instead; the framework draws it:

```yaml
command:
  version: 1
  generated:
    - {name: invite_token, kind: token, bytes: 24}   # encoding: base64url (default) or hex
  prepared_schema:
    type: object
    additionalProperties: false
    required: [email]
    properties:
      email: {type: string, minLength: 3, maxLength: 254}
  preview_schema:
    type: object
    additionalProperties: false
    required: [email]
    properties:
      email: {type: string, maxLength: 254}
  writes: [invites]
  dependencies:                 # at least one, even for an insert
    - name: existing_invite
      table: invites
      query: SELECT id FROM invites WHERE email = :email
      params: {email: '${{ params.email }}'}
      max_rows: 1
jobs:
  prepare:
    steps:
      - run: respond
        with:
          status: 200
          json:
            arguments: {email: '${{ params.email }}'}   # the framework adds `generated` to the arguments
            preview: {email: '${{ params.email }}'}      # the token is not shown unless you write it here
  apply:
    steps:
      - id: invite
        run: sql
        expect_rows: '=1'
        with:
          query: INSERT INTO invites(email, token) VALUES (:email, :token)
          params: {email: '${{ params.email }}', token: '${{ params.generated.invite_token }}'}
      - run: respond
        with: {status: 200, json: {ok: true}}
  readback:
    steps:
      - run: respond
        with: {status: 200, json: {ok: true}}
```

Each entry has a unique lowercase `name`, `kind: token` and `bytes` from 16 to 64
(at most 16 entries). Prepare draws every value from the system's cryptographic
random source once and seals
it into the prepared arguments as `arguments.generated.<name>`, a fixed-length
string (24 bytes is 32 base64url characters or 48 hex). The approval digest covers
it, so approval, commit, a retried attempt and a replay all see the same value, and
a second prepare draws a new one. `prepared_schema` and the tool `input_schema`
may not declare a property named `generated`.

Reference it as `${{ params.generated.<name> }}` in apply and readback (SQL
bindings and responses). The prepare response may reference it too, which is the
only way it reaches the preview the assistant and the reviewer see; prepare SQL
cannot bind it. A `params.generated` reference that does not name one declared
value, and whole `${{ params }}` references, never include it. The audit log
records a digest of each value on the `mcp_command_prepare` row, never the value;
the value is stored only in the sealed operation and in whatever your apply SQL
writes. Do not select the token back in `readback` unless the assistant should
receive it.

## Files, reports, resources and providers

Private file tools refer to a readable table row and its exact private upload
reference. Declare `handler: {kind: file, operation: ingest, table: documents,
file_column: file_url}` (and the same binding for `verify`) to authorize only the
row's current `file_url`. Other string columns, including notes, cannot vouch for
that file. The declared column must exist in the reviewed schema; every read,
cache reuse, verification and publication rechecks its current readable text
value, row authority and upload ownership. Hidden, encrypted and non-text
columns refuse at runtime. The binding is reviewed contract content and requires
resealing; the snapshot remains immutable, but a changed column no longer grants
access to its old processing result. Without `file_column`, legacy tools retain
their broader any-string-column reference check; do not use that mode to claim an
exact document-version binding.

File handlers may also declare `membership_constraints: {kind: human, status: active}`.
Each key must name a canonical, visible scalar column in the configured groups
table; all declared equalities must match the actor's one live membership row
and are checked alongside existing grants, table/row access, exact file-column
binding and ownership. Review, `mcp check` and the push write gate refuse the
manifest when the app has no `groups` table, key and user field configured or
the groups table does not declare a constrained column. Omission preserves
existing behavior. A file handler may
declare a `status` operation with required `processing_id`, `record_id` and
`file_ref` inputs. It returns bounded metadata for a known successful,
snapshot-backed processing result only, after rechecking current row, file,
membership and owner authority. The response contains no parsed blocks or
snapshot payload. `complete` describes historical parser completion and does
not attest to the current file bytes. Failure-only and legacy unbound records
are not eligible.

Apps that allow admins to attach uploads across workspace rows can opt a file
handler into `upload_tenant: current`, alongside its exact `file_column`. The
canonical private-upload owner record must have a nonempty group matching both
the connector grant's selected workspace and the source row's configured group
key. The framework checks that provenance before file access and again during
cache reuse, verification, status reads and snapshot publication. A strict tool
cannot reuse a snapshot recorded under legacy policy. The configured groups
table, key and user field, plus that key on the source table, must be declared in
the reviewed schema; review, `mcp check` and the push write gate refuse the
manifest otherwise. Omitting the field keeps the established admin/uploader/
row-owner vouch rules. The setting is part of the reviewed manifest contract
and appears in lowercase in source inspection.

File tools do not accept arbitrary paths or URLs. `kind: file` supports
`ingest`, `verify` and metadata-only `status`; permissions include both `files:read` and the row's
`<table>:read`. Ingested results are paginated and retain source locations;
verification uses the returned `processing_id` to compare a value against the
same immutable extraction. CSV/XLSX/XLSM and PDF limits and host prerequisites
are in `api(at:"connector")`; OCR output is evidence for human review, not a
guarantee of correctness.

DOCX extraction emits bounded paragraph and table text. PPTX extraction follows
the presentation's declared slide order and emits slide text, tables and notes.
This parser does not reconstruct page geometry, evaluate fields, or interpret
images, charts, SmartArt, inherited layout or animations. Tracked changes,
alternate content and external text stories fail closed rather than selecting a
possibly misleading partial result. `complete` means the declared supported
text scope parsed successfully; it does not mean the rendered document was
understood.

`artifact.export` creates an immutable report from the caller's own successful
reviewed-command receipt. It does not accept arbitrary rows or rerun the command.
It returns `artifact_id`, `kind`, `sha256`, `size` and `download_url`, as
`artifact.create` does.
Retrieval requires the owner's interactive app session and rechecks current
tenant, role and original scopes; a bearer token is insufficient. PDF export has
host prerequisites and a shared per-user rendering budget.

A reviewed read tool can also hand the user a spreadsheet or a report. Declare
the layout on the tool; it is part of the contract digest, and a manifest
without it keeps its digest:

```yaml
tools:
  - name: cashflow_forecast
    handler: {kind: native, operation: flow.call, flow: cashflow_forecast}
    permissions: [forecasts:read]
    # input_schema, output_schema, effect: read ... as for any read tool
    output_schema:
      type: object
      additionalProperties: false
      required: [project, total, months]
      properties:
        project: {type: string}
        total: {type: number}
        months:
          type: array
          items:
            type: object
            additionalProperties: false
            required: [month, revenue, margin]
            properties:
              month: {type: string}     # ISO 8601 date
              revenue: {type: number}
              margin: {type: number}    # a fraction: 0.0525 is 5.25%
    output: {include: [project, total, months]}
    artifact:
      title: Cash-flow forecast
      formats: [xlsx, html, pdf]
      sheets:
        - name: Summary                 # no source: the tool's own scalar fields, one row
          columns:
            - {field: project, label: Project}
            - {field: total, label: Total (USD), format: money}
        - name: Forecast
          source: months                # an array-of-objects property of the output
          columns:
            - {field: month, label: Month, format: date}
            - {field: revenue, label: Revenue (USD), format: money}
            - {field: margin, label: Margin, format: percent}
```

`format` is `text`, `integer`, `number`, `money`, `percent`, `date` or
`datetime` (default from the field type); a value that does not fit it fails
the artifact. A `table.list` tool leaves `source` empty: its rows are the sheet,
one page per call (the result says `read_completeness: partial` when more
remain). The assistant then calls the built-in `artifact.create` with
`{tool: "cashflow_forecast", format: "xlsx", arguments: {...}}`; `arguments` are
only that tool's own inputs. The framework re-runs the read with the caller's
grant, formats the validated result, stores it as an immutable artifact and
returns `artifact_id`, `kind`, `sha256`, `size`, `download_url` and
`read_completeness`. The user opens the
URL signed in to the app in their own browser; retrieval is as for
`artifact.export`. The XLSX has typed cells and a frozen header row; the HTML
is a printable branded report; the PDF prints that report with the same
prerequisites as `artifact.export`. A PDF renderer that is missing, fails or
runs past its deadline returns `unavailable_provider` from both tools; any
other failure after the request is authorized (formatting or storing the file)
returns `incomplete_result` from both, and a refused receipt or tool returns
`denied`. On hosted apps an HTML report is stored as a download-only
`.html.bin` object and served only by the artifact download. Limits: 20 artifacts an hour per user (PDFs
also share the PDF budget), 5000 rows per sheet, 100000 cells, and the newest
25 read artifacts per user within 128 MiB are kept (when a new one is made,
the first one that breaks the count, byte or 7-day limit and every older one are
deleted). A read artifact is a snapshot: it expires after 7 days, and the
download also requires that the reviewed manifest still declares the tool's
artifact and that, for a table tool, the user's current access rule for the
table still admits a read. On S3 or CDN storage the delete of an evicted
artifact's bytes is best effort and can leave an orphan object.

Values are written as declared. A `money` column shows its field as is, in
major units, so a field holding integer cents must be converted by the tool
(or not declared `money`). An integer above 2^53 (a large id) loses precision as
a spreadsheet number: declare it `text`. The full contract is in
`api(at:"connector")` (`connector_grants`).

A reviewed MCP Apps resource needs a real entrypoint under `static/`, a closed
data schema and an explicit tool allowlist. For example:

```yaml
resources:
  - name: notes_card
    uri: ui://notes/card
    mime_type: text/html
    component: card
    entrypoint: static/widgets/card.tsx
    tools: [list_notes, read_note]
    schema_version: 1
    data_schema:
      type: object
      additionalProperties: false
      properties:
        id: {type: integer}
        title: {type: string}
    deep_link: /notes/{id}
```

A tool binds a component by setting its own `component:` to that resource's
`uri` (for example `component: ui://notes/card`). The resource's `name` or its
`component:` label is refused with `tool "<name>" has unresolved component
resource`; `component: none` binds nothing.

The entrypoint and bridge behavior must be tested in the intended MCP client.
Declaring a resource alone does not make a working widget. Calls from the UI
still use tool permissions and first-party write approval; upstream secrets are
not sent to the iframe. A client without MCP Apps support can still use the
structured tool result.

External reads use a named connection pinned to a local OpenAPI 3.0/3.1 file.
`benmore mcp generate` writes disabled candidates to an explicit new file; it
does not make a deployable manifest. Review the real provider response, method,
operation ID, parameter mapping and output schema before authoring a connection.
Only local file references are supported. Private or unresolvable hosts and
generic external write tools are refused. Each user stores their own upstream
credential per connection from a signed-in browser session
(`PUT /api/_mcp/connections/<name>/credential`, body `{"secret": "..."}`),
separate from inbound app-user MCP grants; a call without one answers `denied`
naming that route. `auth.env` must still be declared for `bearer` and `header`
(review refuses the connection without it), but its value is not read.
Selected file pull and approved artifact push use the separate manifest-bound
`transfer` declaration; continuous two-way sync is unsupported.

## Owner controls and client limits

`benmore mcp status|enable|disable <app> --env dev|prod` controls exposure.
`--writes`, `--auto-approve`, `--export`, `--publication` and `--revoke` target
separate controls; `benmore mcp status --help` prints the exact flags. A valid
manifest does not itself enable any switch or create user grants. Nothing
consumes the publication switch yet. Resource subscriptions, arbitrary SQL/shell/HTTP proxies,
automatic exposure of ordinary app routes, and generic external writes are
unsupported. Runtime and local tests do not prove hosted authority setup,
provider qualification or a real client's behavior; measure those on the target
instance before claiming app acceptance.

## Common setup errors

| Error | Correct action |
|---|---|
| Missing/invalid lowercase SHA-256 | Review the app files and run `mcp review . --reviewed`; digests belong at top level. |
| `field ... not found` | Use the complete example; the schema rejects unknown keys and misplaced digests. |
| Unsupported handler kind/operation | Use `native` + `table.list`/`table.read`/`flow.call`; commands use `flow` + `command`. |
| Reviewed digest mismatch, a check warns `mcp_review` on `mcp.yaml`, or a write answers `mcp_connector_withheld` / push warns "this app's MCP connector is off" | Source changed or differs from the server. The app keeps serving the change, but its connector stays off until you reconcile, review again and deploy all reviewed files; if the app serves no connector, delete `mcp.yaml` instead. Deploy never deletes server files: a deploy of `mcp.yaml` that would leave a file you deleted locally, or a migration the server wrote, on the server is blocked and names the file (`benmore delete-file <path>` or `benmore pull`, then review again). |
| Inserts into an enrolled table fail with `write rejected (insert <table>): revision ledger row missing` after a reload, or `mcp status` shows `revision_enrollment: out_of_order` | Another trigger on the table (an encrypted, computed or blind-index field) fires before the connector's revision triggers. Every load puts the revision triggers first again; run `benmore mcp enable <app> --writes` or reload to reorder them (nothing is re-approved). |
| `revision enrollment universe changed; explicit repair is required`, or `mcp status` shows `revision_enrollment: changed` | The reviewed commands now read or write a different set of tables. Run `benmore mcp enable <app> --writes`: it re-enrolls for the new set. |
| Review names an excluded path such as `static/.env`, `flows/.git/` or `static/data.db-wal` | Remove or rename the protected file or directory outside `static/` and `flows/`, then review again. Ordinary non-MCP pushes retain the CLI's existing write-time normalization. |
| MCP push, `write_file` or `edit_file` says source needs normalization | Apply the suggested normalization, review the resulting source, then push or write again; MCP delivery and the write tools never change reviewed bytes. |
| `unknown flag` from `benmore mcp status|enable|disable` | Use only the documented action flags and spell each option exactly; unknown owner-switch flags fail before a request is sent. |
| No reviewed manifest loaded / authority unavailable | Check owner status on the correct instance; deployment or operator provisioning is still required. |
| `pending route-changing migration DDL is unsupported` on an existing database | A pending ALTER/DROP/PRAGMA migration could change routes under the live manifest. Apply it in a separate reviewed step (remove the manifest, boot, restore it and review again). A fresh database applies its migrations first and then checks the manifest, so this only affects existing data (a retried first boot counts as fresh until one load completes). |
| `operation lifecycle requires configured ENCRYPTION_KEY` | The app declares commands and its environment has no durable key. Hosted: the push or deploy that adds commands restarts the app and pins one; `benmore restart <app> --env <env>` does the same. Self-hosted: set `ENCRYPTION_KEY` before starting. |
| `destructive Prisma schema transition is unsupported`, or `mcp.yaml not written: the server's schema.prisma removes the model of table ...` | A reviewed manifest blocks a migration that drops a table (for example the scaffold's `notes`). From `benmore deploy` (or a multi-file push) the refused `mcp.yaml` is the batch's last write, so the server reloads the files already written without it: the schema change applies and the CLI pulls the `migrations/` file it wrote. Then `benmore mcp review . --reviewed` and deploy again. Otherwise, in this order: keep the reviewed `mcp.yaml` off the server (a first connector has none there; one reviewed for the old schema is stale and already off; delete one reviewed for the new schema with `benmore delete-file mcp.yaml --app <app> --env <env>`); push `schema.prisma` and wait for the reload to migrate; `benmore pull` the `migrations/` file the server wrote; `benmore mcp review . --reviewed`; deploy again. Command flows can stay: while no `mcp.yaml` is loaded they load without being exposed. |
| Read succeeds locally but connector request is denied | Recheck the current app user, role, tenant, scope, grant, audience and owner switches. |

The connector covers scoped OAuth, reads, approved commands, recovery,
files/artifacts, reviewed MCP Apps resources and pinned external connections,
each with configuration and host prerequisites; it never exposes an HTTP route
automatically. Generic external write proxies and resource subscriptions are
unsupported.
