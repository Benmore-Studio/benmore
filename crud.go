//go:build !cli

package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// RegisterCRUD sets up automatic CRUD API routes for all tables.
// requireAPIAuth checks if the app requires authentication and rejects unauthenticated API requests.
// Tables listed in auth.public_api OR with access:<table>:<op>: anon in app.yaml are exempt.
// Returns true if the request should be blocked (caller should return immediately).
//
// v2.7.29 fix: previously this gate ran BEFORE the declarative
// `access:` system (v2.7.12) - so a table marked `read: anon` would
// still be rejected with 401 on any app with `auth:` configured. That
// silently broke the canonical "logged-out viewers can read public
// data" pattern that `read: anon` exists to enable. Now requireAPIAuth
// peeks at the access mode for the (table, op) tuple and bails out of
// the auth gate when the developer explicitly opted into anon for
// this op. The legacy `auth.public_api` whitelist still works as a
// shorthand for tables that are anon for every op.
func requireAPIAuth(w http.ResponseWriter, r *http.Request, app *App, table string) bool {
	// Auth is opt-in: only enforce when the developer wrote an `auth:`
	// block in app.yaml. Check `len(...)`, not nil - the map is always
	// initialized non-nil during config load, so a nil-check would
	// silently make every app require auth even with no `auth:` block.
	if app.Design == nil || len(app.Design.Auth) == 0 {
		return false // no auth configured - all APIs public
	}
	// Check if this table is in the public_api whitelist (legacy escape hatch).
	if publicTables, ok := app.Design.Auth["public_api"]; ok {
		for _, t := range strings.Split(fmt.Sprintf("%v", publicTables), ",") {
			if strings.TrimSpace(t) == table {
				return false // whitelisted as public
			}
		}
	}
	// New v2.7.29: declarative `access:` config can opt this op into
	// anon access. We resolve the op for the current method and check
	// if the mode is "anon" - if so, skip the auth gate entirely.
	// EnforceCRUDAccess still runs downstream and enforces the per-op
	// rules; this just stops requireAPIAuth from masking them.
	if app.Access != nil {
		op := accessOpForMethod(r.Method)
		hasUID := hasColumn(app, table, "user_id")
		hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
		if app.Access.AllowsAnon(app.Access.ModeFor(table, op, hasUID, hasGroupKey)) {
			return false // declarative access: anon - let the request through
		}
	}
	session := getSession(app, r)
	if session == nil {
		// N19 hint: when reading an owner-scoped table without an
		// explicit access: rule, point the agent at access.read: anon.
		// An earlier app build built a custom /api/feed flow before
		// discovering this was the right lever.
		body := `{"error":"authentication required"}`
		op := accessOpForMethod(r.Method)
		hasUID := hasColumn(app, table, "user_id")
		if op == OpRead && hasUID && !app.Access.HasExplicitRule(table, op) {
			body = `{"error":"authentication required","hint":"This table is owner-scoped (visitors see 401). For a public feed, declare ` + "`access:\\n  " + table + ":\\n    read: anon`" + ` in app.yaml. Run benmore docs for the full access-mode catalogue."}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(body))
		return true
	}
	// Meter API request (session already resolved, no extra DB call)
	Increment(meterScope(session), "api_requests")
	if r.Method != "GET" && r.Method != "HEAD" {
		Increment(meterScope(session), "api_mutations")
	}
	return false
}

// accessOpForMethod maps the HTTP method to the declarative-access op
// name used by access.yaml. /api/<table>/batch and other non-canonical
// shapes still pass through this map; sub-route gates downstream
// (handleBatchCreate, etc.) re-check ops they may interpret differently.
func accessOpForMethod(method string) AccessOp {
	switch method {
	case "GET", "HEAD":
		return "read"
	case "POST":
		return "write"
	case "PATCH", "PUT":
		return "update"
	case "DELETE":
		return "delete"
	}
	return "read"
}

func RegisterCRUD(mux *http.ServeMux, app *App) {
	tables, err := GetTableNames(app.DB)
	if err != nil {
		return
	}

	for _, table := range tables {
		t := table // capture for closure
		// POST /api/{table} - create
		mux.HandleFunc(fmt.Sprintf("POST /api/%s", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleCreate(w, r, app, t)
		})

		// GET /api/{table} - list
		mux.HandleFunc(fmt.Sprintf("GET /api/%s", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleList(w, r, app, t)
		})

		// GET /api/{table}/{id} - read
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleRead(w, r, app, t)
		})

		// PATCH /api/{table}/{id} - update
		mux.HandleFunc(fmt.Sprintf("PATCH /api/%s/", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleUpdate(w, r, app, t)
		})

		// PATCH /api/{table} - singleton-row upsert for tables with UNIQUE(user_id).
		// Closes the profile/settings save loop: one row per user, no ID needed.
		mux.HandleFunc(fmt.Sprintf("PATCH /api/%s", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleSingletonUpdate(w, r, app, t)
		})

		// DELETE /api/{table}/{id} - delete
		mux.HandleFunc(fmt.Sprintf("DELETE /api/%s/", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleDelete(w, r, app, t)
		})

		// POST /api/{table}/batch - batch create (JSON array)
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/batch", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleBatchCreate(w, r, app, t)
		})

		// PATCH /api/{table}/batch - bulk update (JSON: {ids: [...], fields: {...}})
		mux.HandleFunc(fmt.Sprintf("PATCH /api/%s/batch", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleBatchUpdate(w, r, app, t)
		})

		// DELETE /api/{table}/batch - bulk delete (JSON: {ids: [...]})
		mux.HandleFunc(fmt.Sprintf("DELETE /api/%s/batch", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleBatchDelete(w, r, app, t)
		})

		// POST /api/{table}/ingest - streaming NDJSON ingestion
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/ingest", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) { return }
			handleStreamingIngest(w, r, app, t)
		})
	}

	// POST /api/_transaction - atomic cross-table operations
	mux.HandleFunc("POST /api/_transaction", func(w http.ResponseWriter, r *http.Request) {
		if requireAPIAuth(w, r, app, "_transaction") {
			return
		}
		handleTransaction(w, r, app)
	})
}

// appendHXTrigger appends an event to the HX-Trigger response header,
// preserving anything already set. HTMX parses comma-separated names.
// We use this so every CRUD mutation can fire "benmore:changed" - the
// auto-refresh shim in layout.go listens for that event and soft-reloads
// the page, which keeps <query> stat cards in sync with the table they
// read from. Without this, agents end up reinventing JS reload hacks on
// every page (and burning a dozen turns doing it).
func appendHXTrigger(w http.ResponseWriter, event string) {
	existing := w.Header().Get("HX-Trigger")
	if existing == "" {
		w.Header().Set("HX-Trigger", event)
		return
	}
	w.Header().Set("HX-Trigger", existing+", "+event)
}

// requiresUserIDInsert reports whether a table has a NOT NULL user_id
// column - meaning anonymous inserts cannot succeed.
func requiresUserIDInsert(cols []Column) bool {
	for _, c := range cols {
		if c.Name == "user_id" && c.NotNull {
			return true
		}
	}
	return false
}

func handleCreate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Declarative access gate (v2.7.12). app.yaml `access:` config
	// decides who may CREATE. Default-private floor: tables without
	// user_id / group_key fall through to admin-only. See access.go.
	if !EnforceCRUDAccess(w, r, app, table, OpWrite, 0) {
		return
	}

	// Optional storage-cap enforcement: refuse writes when the app's DB
	// exceeds a configured size cap. No cap is enforced unless one is
	// configured (checkStorageCap is a no-op by default), so a self-hosted
	// app is never silently capped.
	if reason, blocked := checkStorageCap(app); blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInsufficientStorage)
		fmt.Fprintf(w, `{"error":"storage cap reached","detail":%q}`, reason)
		return
	}

	// Idempotency: if X-Idempotency-Key header present, check for
	// duplicate. Scope by user_id so two callers with the same key
	// don't accidentally read each other's cached response.
	idempotencyKey := r.Header.Get("X-Idempotency-Key")
	var idempUserID int64
	if s := getSession(app, r); s != nil {
		idempUserID = s.UserID
	}
	if cached, status, found := CheckIdempotency(app.DB, idempotencyKey, idempUserID); found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(cached))
		return
	}

	// Parse request body: multipart (file uploads), JSON, or form-encoded
	if strings.Contains(r.Header.Get("Content-Type"), "multipart") {
		r.ParseMultipartForm(maxUploadSize)
	} else if r.Header.Get("Content-Type") == "application/json" {
		// JSON body → parse into r.Form so the rest of the handler works uniformly
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			r.Form = make(map[string][]string)
			for k, v := range body {
				r.Form.Set(k, jsonToFormValue(v))
			}
		}
	} else {
		r.ParseForm()
	}

	// Handle file uploads - check for file inputs and save them
	if r.MultipartForm != nil {
		for fieldName, fileHeaders := range r.MultipartForm.File {
			if len(fileHeaders) > 0 {
				// Save the uploaded file
				path, err := HandleFileUpload(app, r, fieldName, table, 0, nil)
				if err != nil {
					httpError(w, err.Error(), http.StatusBadRequest)
					return
				}
				if path != "" {
					// Store the file path as a form value so it gets saved to DB
					r.Form.Set(fieldName, path)
				}
			}
		}
	}

	// Validate CSRF
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Validate fields against :validate rules in HTML
	rules := ExtractValidationRules(app, table)
	if len(rules) > 0 {
		if errors := ValidateFields(r, rules); len(errors) > 0 {
			FormatValidationErrors(w, r, errors)
			return
		}
	}

	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	var fields []string
	var placeholders []string
	var values []any

	// Get session for user_id injection
	session := getSession(app, r)

	// Scope enforcement
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	// Auth pre-check: if this table has a NOT NULL user_id column,
	// an anonymous insert cannot succeed (the FK / NOT NULL would
	// fail at execute time). Return 401 with a clear message instead
	// of the cryptic SQLite error agents have historically debugged
	// by spawning a custom flow to "set user_id" - which never works
	// because the flow path collides with this same POST.
	if session == nil && requiresUserIDInsert(cols) {
		httpJSON(w, http.StatusUnauthorized, map[string]any{
			"error":  "auth required",
			"detail": fmt.Sprintf("the %s table has a user_id column that's NOT NULL - anonymous inserts would fail the FK / NOT NULL constraint. Either log the user in before this POST, OR make user_id optional in schema.prisma (`userId Int?`) to allow anonymous rows.", table),
		})
		return
	}

	// member-of write mode (v2.7.164): inserting into a membership-scoped
	// CHILD table (the table carries the rule's join column, e.g.
	// messages.room_id) requires membership in the parent the new row
	// points at - the row-scope EXISTS can't run pre-insert, so the
	// check happens here (shared with the batch/ingest/tx paths via
	// memberOfCreateDenial). Parent-table creates (join column absent →
	// joins on id) pass through; the founder auto-join below makes the
	// new row readable by its creator. 404 on a non-member parent so
	// parent existence doesn't leak.
	if d := memberOfCreateDenial(app, table, session, r.FormValue); d != nil {
		writeMemberOfDenial(w, r, d)
		return
	}

	// Protected fields - never accept from user input
	protected := map[string]bool{
		"user_id":       true,
		"created_at":    true,
		"updated_at":    true,
		"password_hash": true,
		"role":          true,
	}
	// Protect org key from user input - it's auto-injected from session
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}

	// Surface stripped fields via response header. When a client (or
	// agent) submits a protected field, the framework silently swaps
	// the value out for the session-derived one. With no signal back,
	// agents writing tests of `POST /api/notes` with `user_id: 99`
	// can't tell their value was ignored. The header lets curl + the
	// MCP probe_route tool report which fields the framework rejected.
	var stripped []string
	for k := range r.Form {
		if protected[k] && k != "user_id" && (app.Group == nil || k != app.Group.Key) {
			stripped = append(stripped, k)
		}
	}
	if len(stripped) > 0 {
		w.Header().Set("X-Stripped-Fields", strings.Join(stripped, ","))
	}

	for _, col := range cols {
		if col.PK {
			continue // skip auto-increment ID
		}

		// Auto-inject user_id from session, never accept from form
		if col.Name == "user_id" {
			if session != nil {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, session.UserID)
			}
			continue
		}
		// Org key handling. Two distinct caller shapes:
		//
		//   - Non-admin with a resolved group → ALWAYS inherit from the
		//     session. Body value is ignored on purpose, so a caller
		//     can't plant a row into a tenant they don't belong to.
		//
		//   - Admin → honor an explicit body value. Admins legitimately
		//     write cross-group data (support tooling, seeding,
		//     impersonation flows). Without this branch, admin POSTs
		//     used to leave the org key NULL - bypassing any
		//     `@@unique([email, districtId])` constraint the developer
		//     declared, since `NULL != NULL` in SQLite.
		//
		// Either way, no further field-loop processing for this column.
		if app.Group != nil && col.Name == app.Group.Key {
			// Bypass admin (not stepped-in): honor body value.
			if session != nil && session.IsAdminBypass() {
				if v := strings.TrimSpace(r.Form.Get(col.Name)); v != "" {
					fields = append(fields, col.Name)
					placeholders = append(placeholders, "?")
					values = append(values, v)
				}
				continue
			}
			// Everyone else (ordinary group members AND stepped-in
			// admins) inherits from the session's EFFECTIVE group.
			// For an admin acting-as tenant T, that's T - so writes
			// land in T, not in whatever the body claims.
			if session != nil && session.EffectiveHasGroup() {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, session.EffectiveGroupID())
			}
			continue
		}

		// Skip protected fields
		if protected[col.Name] {
			continue
		}

		val := r.FormValue(col.Name)
		if val == "" {
			// Nullable column with no value: skip and let SQLite store
			// NULL.
			if !col.NotNull {
				continue
			}
			// NOT NULL column with a DEFAULT: skip too, so the DEFAULT
			// kicks in. Previously we inserted "" into INTEGER/BOOLEAN
			// columns, leaving rows with `completed: ""` (string) where
			// the schema declared the column INTEGER NOT NULL DEFAULT 0.
			// SQLite is loose-typed so it didn't error, but downstream
			// clients hit "true"/"" instead of the expected 0/1.
			if col.Default != "" {
				continue
			}
			// NOT NULL with no default - fall through and let SQLite
			// reject the insert with a clearer error than silently
			// storing the empty string.
		}

		fields = append(fields, col.Name)
		placeholders = append(placeholders, "?")
		values = append(values, val)
	}

	if len(fields) == 0 {
		httpError(w, "No fields provided", http.StatusBadRequest)
		return
	}

	// Fire before-hooks (can abort the operation)
	beforeRow := make(map[string]any)
	for i, f := range fields {
		beforeRow[f] = values[i]
	}
	injectSessionContext(beforeRow, session)
	// Cross-field validators (declarative rules from validators.yaml)
	if err := ValidateCrossField(app.Validators, table, beforeRow); err != nil {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := FireBeforeHooks(app, "insert", table, beforeRow); err != nil {
		httpError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table,
		strings.Join(fields, ", "),
		strings.Join(placeholders, ", "),
	)

	result, err := app.DB.Exec(sql, values...)
	if err != nil {
		// Guided error for the multi-tenant founding moment: the group
		// key is stripped from client bodies and auto-injected from the
		// session, so a user with NO group yet hits a bare NOT NULL
		// constraint here and has no idea why. Point at the actual
		// levers instead of the raw SQLite error.
		if app.Group != nil && app.Group.Key != "" &&
			strings.Contains(err.Error(), fmt.Sprintf("NOT NULL constraint failed: %s.%s", table, app.Group.Key)) {
			httpJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error": fmt.Sprintf("Insert failed: %s is the tenant key - it cannot be set by clients and is auto-injected from the session's group, but this user has no group membership yet.", app.Group.Key),
				"hint":  fmt.Sprintf("Bootstrap the tenant first: declare `groups.bootstrap: {org_table: <orgs>}` in app.yaml and POST /api/_groups/create (creates the org + this user's founding membership atomically), or insert a row into %s for this user server-side. See api(at:\"scoping\").", app.Group.Table),
			})
			return
		}
		httpError(w, fmt.Sprintf("Insert failed: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Retrieve the new row's ID - for UUID tables, fetch the TEXT PK via rowid
	var id any
	var idStr string
	if app.IsUUIDTable(table) {
		var uuidID string
		err := app.DB.QueryRow(fmt.Sprintf("SELECT id FROM %s WHERE rowid = last_insert_rowid()", table)).Scan(&uuidID)
		if err != nil {
			httpError(w, "Insert succeeded but failed to retrieve UUID", http.StatusInternalServerError)
			return
		}
		id = uuidID
		idStr = uuidID
	} else {
		intID, _ := result.LastInsertId()
		id = intID
		idStr = fmt.Sprintf("%d", intID)
	}

	// Founder auto-join (v2.7.164): when this table's READ mode is
	// member-of and the membership join targets this table's own id
	// (the new row IS the parent - a room, a channel, a project), the
	// creator gets a membership row automatically. Without it the
	// creator couldn't read back the row they just made (the classic
	// member-of chicken-and-egg). Idempotent via ON CONFLICT DO NOTHING;
	// a failure (e.g. the membership table has other NOT NULL columns
	// without defaults) never fails the create - it's logged and
	// surfaced in a response header so the developer sees it.
	if rule := memberOfFor(app, table, OpRead); rule != nil && session != nil && rule.localJoinCol(app, table) == "id" {
		if err := memberOfAutoJoin(app, rule, id, session); err != nil {
			log.Printf("member-of auto-join into %s failed for %s id=%v: %v", rule.Table, table, id, err)
			w.Header().Set("X-Member-Of-AutoJoin", "failed: "+err.Error())
		}
	}

	// Fire insert hooks
	row := make(map[string]any)
	for i, f := range fields {
		row[f] = values[i]
	}
	row["id"] = id
	injectSessionContext(row, session)
	FireHooks(app, "insert", table, row)
	FireFlowsForEvent(app, "on_insert", table, row)
	FireWebhookSubscriptions(app, "insert", table, row, session)
	Broadcast(app, table, "insert", session)
	LogAudit(app, "insert", table, idStr, session, nil, row)
	appendHXTrigger(w, "benmore:changed")

	// If HTMX request, return empty (triggers page refresh)
	if isHTMX(r) {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}

	// JSON response. Pre-2.7.33 we returned just {id, status:"created"} -
	// agents writing `const {room_key} = await bm.api.post('huddles', …)`
	// got undefined and burned debugging time chasing the missing value.
	// A real-time flow tripped on this twice. Now we read the full
	// inserted row back and return it, with `status:"created"` and the
	// canonical `id` preserved for backwards compatibility. Computed
	// defaults (created_at, updated_at, DEFAULT-clauses) come back too.
	//
	// The read is a single SELECT against the just-written row; cheap
	// even on hot paths. Errors from the read fall back to the legacy
	// shape so a transient query failure can't turn a successful insert
	// into a 500.
	resp := map[string]any{"id": id, "status": "created"}
	if full, ok := loadInsertedRow(app, table, idStr); ok {
		for k, v := range full {
			if _, exists := resp[k]; !exists {
				resp[k] = v
			}
		}
	} else {
		// Best-effort fallback: surface the bound values so the caller
		// at least sees what they sent. Computed columns are absent
		// in this branch.
		for i, f := range fields {
			if _, exists := resp[f]; !exists {
				resp[f] = values[i]
			}
		}
	}
	// Apply the same role-based masking the GET path uses, so an unauthorized
	// caller never gets plaintext back in the create response (the row's owner
	// and admins see plaintext via self/role unmask; everyone else sees masked).
	MaskEncryptedFields(app.Encrypted, table, []map[string]any{resp}, getSession(app, r))
	w.Header().Set("Content-Type", "application/json")
	body, _ := json.Marshal(resp)
	SaveIdempotency(app.DB, idempotencyKey, idempUserID, string(body), http.StatusOK)
	w.Write(body)
}

// isTruthyQuery reports whether the named query-string parameter is
// present and looks like "yes" - `1`, `true`, `yes`, or just present
// without a value. Used by the auto-CRUD `?count=true` short-circuit
// so any of these forms work:
//
//	?count
//	?count=1
//	?count=true
//	?count_only=true
func isTruthyQuery(r *http.Request, key string) bool {
	if !r.URL.Query().Has(key) {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key)))
	switch v {
	case "", "1", "true", "yes", "on":
		return true
	}
	return false
}

// loadInsertedRow reads the just-inserted row back so the create
// response can include every column - including DB-generated defaults
// (created_at, updated_at, DEFAULTs, computed columns). Returns false
// on any read error so the caller can fall back to the legacy shape.
//
// Strictly scoped to the row matched by id: this never widens the
// query, never honors filters, and never participates in the access
// gate (the insert already passed the gate). Sensitive columns
// declared by the framework's user-table denylist are filtered out so
// a POST to _benmore_users-shaped tables can't leak password_hash.
func loadInsertedRow(app *App, table, idStr string) (map[string]any, bool) {
	q := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table)
	rows, err := app.DB.Query(q, idStr)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, false
	}
	if !rows.Next() {
		return nil, false
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, false
	}
	out := make(map[string]any, len(cols))
	for i, c := range cols {
		if isSensitiveUserColumn(c) {
			continue
		}
		out[c] = coerceSQLValue(vals[i])
	}
	// Decrypt encrypted columns just like the GET read path (scanRows calls
	// DecryptRowFields). Without this the POST-create response handed back the
	// raw enc:v1:<hex> ciphertext - the encrypt trigger fired on INSERT, but
	// this read-back didn't decrypt - so clients saw ciphertext until a
	// follow-up GET. (Role-based MASKING is applied by the caller via
	// MaskEncryptedFields, since that needs the session.)
	DecryptRowFields(out)
	return out, true
}

// coerceSQLValue normalises the values database/sql returns so the
// JSON-encoded response matches what a fresh GET /api/<table>/{id}
// would yield. SQLite returns []byte for TEXT in some drivers and
// time.Time for DATETIME in others - both serialize ugly without
// this nudge.
//
// v2.7.60+: a zero time.Time (the Go zero value, which the driver
// can emit when it scans a NULL DATETIME column into time.Time
// destination types) maps to nil → JSON null. Pre-v2.7.60 we
// formatted the zero value verbatim and shipped
// "0001-01-01T00:00:00Z" to API callers - a clear-as-day bug for
// any nullable DateTime column. Non-zero times still format to
// RFC3339 in UTC.
func coerceSQLValue(v any) any {
	switch t := v.(type) {
	case []byte:
		return string(t)
	case time.Time:
		if t.IsZero() {
			return nil
		}
		return t.UTC().Format(time.RFC3339)
	case *time.Time:
		// Defensive: a *time.Time scan destination would yield
		// either nil (NULL column) or a pointer to a populated
		// value. Treat nil-pointer and zero-time identically - both
		// map to JSON null.
		if t == nil || t.IsZero() {
			return nil
		}
		return t.UTC().Format(time.RFC3339)
	}
	return v
}

func handleList(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Declarative access gate (v2.7.12). Decides whether the request
	// can hit this endpoint AT ALL. Also drives the per-row filter
	// below: when mode is `anon`/`everyone`, we skip the implicit
	// owner-WHERE so the list reads broadly (still respects
	// `scopes.public_read_when` if set).
	if !EnforceCRUDAccess(w, r, app, table, OpRead, 0) {
		return
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	readMode := app.Access.ModeFor(table, OpRead, hasUID, hasGroupKey)
	allowBroaderRows := app.Access.ReadAllowsBroaderRows(readMode)

	session := getSession(app, r)

	// Scope enforcement
	if session != nil {
		if err := checkScope(session, table, "read"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	// Read audit logging (batched, non-blocking)
	if IsReadAudited(app, table) {
		LogReadAccess(table, "", "list", session)
	}

	// Field selection: ?fields=name,email (default: all)
	fields := selectFields(r, "*")
	baseSQL := fmt.Sprintf("SELECT %s FROM %s", fields, table)

	// Soft delete filter: exclude deleted rows if table has deleted_at
	hasWhere := false
	if hasColumn(app, table, "deleted_at") {
		baseSQL += " WHERE deleted_at IS NULL"
		hasWhere = true
	}

	// Platform admins normally bypass all CRUD scoping. EXCEPTION:
	// an admin who has stepped into a tenant via /api/_auth/act_as
	// is intentionally scoped TO that tenant for the duration of the
	// step-in - IsAdminBypass returns false while ActingAsGroup is set.
	isAdmin := session.IsAdminBypass()

	// Per-table public-read override from app.yaml `scopes:`. When
	// configured, this SQL fragment names rows visible to ANY caller
	// (anonymous or authenticated, owner or not) regardless of
	// user_id ownership. Owner reads still see their private rows
	// too - the standard owner filter is OR'd in below for sessions.
	publicReadWhen := ""
	if app.Scopes != nil {
		if sc, ok := app.Scopes[table]; ok {
			publicReadWhen = sc.PublicReadWhen
		}
	}

	var scopeArgs []any // args for parameterized ACL subquery
	if !isAdmin && !allowBroaderRows {
		// Build access filter: owner/group scoping OR explicit ACL grant
		// OR (if configured) the public_read_when SQL fragment.
		// SKIPPED when readMode is `anon`/`everyone` - the developer
		// explicitly opted into broad reads via `access:` and we honor
		// that without forcing them to also write `scopes.public_read_when`.
		var accessFilter string

		if session != nil {
			// member-of read mode: the membership EXISTS predicate IS
			// the filter (tenant clause AND'd inside when the table is
			// group-keyed). Without this branch a member-of table with
			// neither user_id nor group key would fall through every
			// filter below and list ALL rows.
			if rule := memberOfFor(app, table, OpRead); rule != nil {
				accessFilter, scopeArgs = memberOfPredicate(app, table, rule, session, "view")
			}

			// Group scoping applies uniformly - including the
			// membership table itself (e.g., user_roles). A caller in
			// district 7 should see all user_roles rows for district 7
			// (the team directory), not just their own row. A caller
			// with no resolved group falls through to user_id scoping
			// below, which still surfaces their pending invite.
			useGroupScope := accessFilter == "" && session.EffectiveHasGroup() && app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)

			if useGroupScope {
				aclSQL, aclArgs := aclFilter(table, session.Email, "view")
				accessFilter = fmt.Sprintf("(%s = ? OR %s)", app.Group.Key, aclSQL)
				scopeArgs = append(scopeArgs, session.EffectiveGroupID())
				scopeArgs = append(scopeArgs, aclArgs...)
			} else if accessFilter == "" && hasColumn(app, table, "user_id") {
				aclSQL, aclArgs := aclFilter(table, session.Email, "view")
				accessFilter = fmt.Sprintf("(user_id = ? OR %s)", aclSQL)
				scopeArgs = append(scopeArgs, session.UserID)
				scopeArgs = append(scopeArgs, aclArgs...)
			}
		}

		// Public-read-when fragment widens whatever filter we built
		// (or stands alone for anonymous callers when no other filter
		// applies). When NEITHER applies, the request returns nothing
		// - same behavior as before.
		if publicReadWhen != "" {
			if accessFilter != "" {
				accessFilter = "(" + accessFilter + " OR (" + publicReadWhen + "))"
			} else {
				accessFilter = "(" + publicReadWhen + ")"
			}
		}

		if accessFilter != "" {
			if hasWhere {
				baseSQL += " AND " + accessFilter
			} else {
				baseSQL += " WHERE " + accessFilter
				hasWhere = true
			}
		}
	}

	// Full-text search: ?q=foo. When the table has @@fulltext in
	// schema.prisma, the framework joined a SQLite FTS5 virtual table
	// at boot - route through it for BM25-ranked results. Falls
	// through to no-filter when FTS isn't configured for this table
	// (client should narrow with `where:` or use a custom search
	// flow). FTS5's MATCH syntax is parameterized so user input
	// can't break out of the query - but FTS5 has its OWN syntax for
	// the MATCH expression where `.`, `:`, `*`, `@`, etc. are special.
	// A raw `alice.garcia@cyberdyne.ai` triggers `fts5: syntax error
	// near "."` (a real app session). escapeFTS5Query wraps each
	// whitespace-separated token as a quoted phrase, which makes any
	// special chars literal while preserving multi-word AND-search.
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		ftsTable, ftsCols := FTSTableFor(app.Tables, table)
		if ftsTable != "" {
			var clause string
			if ftsTrigramUsable(q) {
				// Trigram MATCH: indexed substring search (contains).
				clause = fmt.Sprintf("%s.id IN (SELECT rowid FROM %s WHERE %s MATCH ?)", table, ftsTable, ftsTable)
				scopeArgs = append(scopeArgs, escapeFTS5Query(q))
			} else if lc, largs := buildFTSLikeFallback(table, ftsCols, q); lc != "" {
				// Sub-3-char query - trigram can't tokenize it; LIKE fallback.
				clause = lc
				scopeArgs = append(scopeArgs, largs...)
			}
			if clause != "" {
				if hasWhere {
					baseSQL += " AND " + clause
				} else {
					baseSQL += " WHERE " + clause
					hasWhere = true
				}
			}
		}
	}

	// Cursor pagination: ?cursor=X&limit=N (keyset, fast for large datasets)
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		limit := queryInt(r, "limit", 20)
		if limit > 500 {
			limit = 500
		}
		if hasWhere {
			baseSQL += " AND id > ?"
		} else {
			baseSQL += " WHERE id > ?"
		}
		baseSQL += fmt.Sprintf(" ORDER BY id ASC LIMIT %d", limit)
		cursorArgs := append(scopeArgs, cursor)
		rows, err := QueryRows(app.DB, baseSQL, cursorArgs...)
		if err != nil {
			httpError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Relationship includes on cursor-paginated results
		if inc := r.URL.Query().Get("include"); inc != "" {
			ResolveIncludes(app, table, rows, inc, session)
		}
		var nextCursor any
		if len(rows) == limit {
			nextCursor = rows[len(rows)-1]["id"]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data":        rows,
			"next_cursor": nextCursor,
			"limit":       limit,
		})
		return
	}

	// Apply filtering, sorting, pagination from query params
	colAllowlist := make(map[string]bool)
	if cols, err := GetTableColumns(app.DB, table); err == nil {
		for _, c := range cols {
			colAllowlist[c.Name] = true
		}
	}

	// `?count=true` (alias: `?count_only=true`) short-circuits the row
	// fetch and returns just `{count: N}` - the true total of rows that
	// would match (with WHERE filters applied) BUT ignoring the LIMIT /
	// page cap. A real app hit "50 records showing but actual count is
	// 693" three times because the auto-CRUD list defaults to a 50-row
	// page cap and the JS read `data.length`. With a dedicated count
	// endpoint, the SDK's `bm.table('x').count()` answers "how many?"
	// in one round-trip without re-deriving via a custom flow. WHERE
	// filters (`?where[col]=val`, `?col__op=val`, `?q=…`) ARE honored
	// - pass them to count a filtered subset.
	if isTruthyQuery(r, "count") || isTruthyQuery(r, "count_only") {
		whereSQL, whereArgs := applyAPIWhereWithApp(baseSQL, r, table, app, colAllowlist)
		countSQL := "SELECT COUNT(*) FROM (" + whereSQL + ")"
		countArgs := append(scopeArgs, whereArgs...)
		var total int64
		if err := app.DB.QueryRow(countSQL, countArgs...).Scan(&total); err != nil {
			httpError(w, "count failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"count": total})
		return
	}

	sql, filterArgs := applyAPIFiltersWithApp(baseSQL, r, table, app, colAllowlist)
	allArgs := append(scopeArgs, filterArgs...)

	rows, err := QueryRows(app.DB, sql, allArgs...)
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Relationship includes: ?include=contact,tasks (batched, no N+1)
	if inc := r.URL.Query().Get("include"); inc != "" {
		ResolveIncludes(app, table, rows, inc, session)
	}

	// Mask encrypted fields for unauthorized roles (v2.7.58+: pass
	// the full session so the multi-role / join-table grants are
	// honored, not just the primary _benmore_users.role column).
	MaskEncryptedFields(app.Encrypted, table, rows, session)

	w.Header().Set("Content-Type", "application/json")

	// Pagination metadata: if ?page= is used, wrap in {data, total, page, per_page}
	if r.URL.Query().Get("page") != "" {
		// Count total rows (same base query without LIMIT/OFFSET) - pass scope args for parameterized WHERE
		countSQL := "SELECT COUNT(*) FROM (" + baseSQL + ")"
		var total int
		app.DB.QueryRow(countSQL, scopeArgs...).Scan(&total)
		page := queryInt(r, "page", 1)
		perPage := queryInt(r, "per_page", 20)
		json.NewEncoder(w).Encode(map[string]any{
			"data":     rows,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		})
	} else {
		// Always emit `[]` for empty result sets, never `null`. A nil
		// slice serializes to `null` by default, which breaks client
		// code that does `.length` or `.map(...)` on the response.
		if rows == nil {
			rows = []map[string]any{}
		}
		json.NewEncoder(w).Encode(rows)
	}
}

func handleRead(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Coarse access gate (v2.7.12). Per-row owner/group filtering still
	// runs below - this just blocks listing modes the caller can't
	// touch at all (e.g. `read: admin` on `system_logs`).
	if !EnforceCRUDAccess(w, r, app, table, OpRead, 0) {
		return
	}
	id := extractID(r.URL.Path, table)
	if id == "" {
		httpError(w, "Missing ID", http.StatusBadRequest)
		return
	}

	// Point-in-time query: ?as_of=2026-03-01T00:00:00Z
	if asOf := r.URL.Query().Get("as_of"); asOf != "" {
		session := getSession(app, r)
		if session != nil {
			if err := checkScope(session, table, "read"); err != nil {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
				return
			}
		}
		if session == nil || !canAccessRow(app, table, id, session) {
			httpError(w, "Not found", http.StatusNotFound)
			return
		}
		row, err := handlePointInTime(app, table, id, asOf, session)
		if err != nil {
			httpError(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(row)
		return
	}

	// SECURITY: enforce scoping on reads
	readSQL := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table)
	readArgs := []any{id}
	// Soft delete filter
	if hasColumn(app, table, "deleted_at") {
		readSQL += " AND deleted_at IS NULL"
	}
	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "read"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	// Read audit logging (batched, non-blocking)
	if IsReadAudited(app, table) {
		LogReadAccess(table, id, "read", session)
	}
	if !session.IsAdminBypass() {
		// member-of mode replaces owner/group scoping (tenant clause
		// AND'd inside the predicate when the table is group-keyed).
		if rule := memberOfFor(app, table, OpRead); rule != nil && session != nil {
			pred, pargs := memberOfPredicate(app, table, rule, session, "view")
			readSQL += " AND " + pred
			readArgs = append(readArgs, pargs...)
		} else if readUseGroup := session != nil && session.EffectiveHasGroup() && app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key); readUseGroup {
			aclSQL, aclArgs := aclFilter(table, session.Email, "view")
			readSQL += fmt.Sprintf(" AND (%s = ? OR %s)", app.Group.Key, aclSQL)
			readArgs = append(readArgs, session.EffectiveGroupID())
			readArgs = append(readArgs, aclArgs...)
		} else if session != nil && hasColumn(app, table, "user_id") {
			aclSQL, aclArgs := aclFilter(table, session.Email, "view")
			readSQL += fmt.Sprintf(" AND (user_id = ? OR %s)", aclSQL)
			readArgs = append(readArgs, session.UserID)
			readArgs = append(readArgs, aclArgs...)
		}
	}

	rows, err := QueryRows(app.DB, readSQL, readArgs...)
	if err != nil || len(rows) == 0 {
		httpError(w, "Not found", http.StatusNotFound)
		return
	}

	// Relationship includes: ?include=contact,tasks
	if inc := r.URL.Query().Get("include"); inc != "" {
		ResolveIncludes(app, table, rows, inc, session)
	}

	// Mask encrypted fields for unauthorized roles (v2.7.58+:
	// session-aware; see MaskEncryptedFields docstring).
	MaskEncryptedFields(app.Encrypted, table, rows, session)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows[0])
}

func handleUpdate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Coarse access gate (v2.7.12). `update: admin` blocks non-admins
	// before we even look at the row. The existing owner-WHERE on the
	// UPDATE statement still enforces per-row in `self`/`group` modes.
	if !EnforceCRUDAccess(w, r, app, table, OpUpdate, 0) {
		return
	}
	id := extractID(r.URL.Path, table)
	if id == "" {
		httpError(w, "Missing ID", http.StatusBadRequest)
		return
	}

	// CSRF validation - HX-Request header is trivially forgeable, never bypass CSRF for it
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Record lock check - reject if locked by another user
	if lockSession := getSession(app, r); lockSession != nil {
		if locked, lockedBy := CheckLock(app.DB, table, id, lockSession.UserID); locked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			resp := lockErrorResponse(app.DevMode, lockedBy)
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	if err := r.ParseForm(); err != nil {
		httpError(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Accept both form values and JSON body
	fields := getUpdateFields(r)

	// Build allowlist of valid column names for this table
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}
	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}

	// Protected fields - never accept from user input
	protected := map[string]bool{
		"id": true, "user_id": true, "created_at": true,
		"updated_at": true, "password_hash": true, "role": true, "_csrf": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	// Block workflow-controlled fields (must use transition API)
	for _, f := range workflowProtectedFields(app, table) {
		protected[f] = true
	}

	var sets []string
	var values []any
	for k, v := range fields {
		// SECURITY: only allow known column names, block protected fields
		if protected[k] || !validCols[k] {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = ?", k))
		values = append(values, v)
	}

	if len(sets) == 0 {
		httpError(w, "No fields to update", http.StatusBadRequest)
		return
	}

	// Fire before-hooks (can abort)
	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	// member-of: re-pointing a child row's join column (PATCHing a
	// message's room_id to a different room) must verify membership in
	// the NEW parent - the row-scope WHERE only proves membership in
	// the row's CURRENT parent. 404 so the target's existence doesn't
	// leak to non-members. (Shared with batch update via
	// memberOfRepointDenial.)
	if d := memberOfRepointDenial(app, table, session, func(col string) string { return fields[col] }); d != nil {
		writeMemberOfDenial(w, r, d)
		return
	}

	beforeRow := make(map[string]any)
	beforeRow["id"] = id
	for k, v := range fields {
		beforeRow[k] = v
	}
	injectSessionContext(beforeRow, session)
	// Cross-field validators on update - check rules against the MERGED data
	// (existing row + submitted changes)
	if err := ValidateCrossField(app.Validators, table, beforeRow); err != nil {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := FireBeforeHooks(app, "update", table, beforeRow); err != nil {
		httpError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// Capture old row for audit log before updating - with same scoping as the UPDATE
	oldScopeSQL := ""
	var oldScopeArgs []any
	if !session.IsAdminBypass() {
		if rule := memberOfFor(app, table, OpUpdate); rule != nil && session != nil {
			pred, pargs := memberOfPredicate(app, table, rule, session, "edit")
			oldScopeSQL = " AND " + pred
			oldScopeArgs = append(oldScopeArgs, pargs...)
		} else if oldUseGroup := session != nil && session.EffectiveHasGroup() && app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key); oldUseGroup {
			aclSQL, aclArgs := aclFilter(table, session.Email, "edit")
			oldScopeSQL = fmt.Sprintf(" AND (%s = ? OR %s)", app.Group.Key, aclSQL)
			oldScopeArgs = append(oldScopeArgs, session.EffectiveGroupID())
			oldScopeArgs = append(oldScopeArgs, aclArgs...)
		} else if session != nil && hasColumn(app, table, "user_id") {
			aclSQL, aclArgs := aclFilter(table, session.Email, "edit")
			oldScopeSQL = fmt.Sprintf(" AND (user_id = ? OR %s)", aclSQL)
			oldScopeArgs = append(oldScopeArgs, session.UserID)
			oldScopeArgs = append(oldScopeArgs, aclArgs...)
		}
	}
	prefetchArgs := append([]any{id}, oldScopeArgs...)
	oldRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?%s", table, oldScopeSQL), prefetchArgs...)

	// Auto-set updated_at if column exists
	if hasColumn(app, table, "updated_at") && !protected["updated_at"] {
		// updated_at is protected from user input but we set it here
		sets = append(sets, "updated_at = datetime('now')")
	}

	values = append(values, id)
	sql := fmt.Sprintf("UPDATE %s SET %s WHERE id = ?", table, strings.Join(sets, ", "))

	// Soft delete filter: cannot update deleted records
	if hasColumn(app, table, "deleted_at") {
		sql += " AND deleted_at IS NULL"
	}

	// Optimistic concurrency: if client sends _expected_updated_at, enforce it
	if expected := r.FormValue("_expected_updated_at"); expected != "" && hasColumn(app, table, "updated_at") {
		sql += " AND updated_at = ?"
		values = append(values, expected)
	}

	// SECURITY: enforce scoping on updates (owner/org OR explicit ACL edit grant)
	if !session.IsAdminBypass() {
		if rule := memberOfFor(app, table, OpUpdate); rule != nil && session != nil {
			pred, pargs := memberOfPredicate(app, table, rule, session, "edit")
			sql += " AND " + pred
			values = append(values, pargs...)
		} else if updateUseGroup := session != nil && session.EffectiveHasGroup() && app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key); updateUseGroup {
			aclSQL, aclArgs := aclFilter(table, session.Email, "edit")
			sql += fmt.Sprintf(" AND (%s = ? OR %s)", app.Group.Key, aclSQL)
			values = append(values, session.EffectiveGroupID())
			values = append(values, aclArgs...)
		} else if session != nil && hasColumn(app, table, "user_id") {
			aclSQL, aclArgs := aclFilter(table, session.Email, "edit")
			sql += fmt.Sprintf(" AND (user_id = ? OR %s)", aclSQL)
			values = append(values, session.UserID)
			values = append(values, aclArgs...)
		}
	}

	result, err := app.DB.Exec(sql, values...)
	if err != nil {
		httpError(w, fmt.Sprintf("Update failed: %s", err.Error()), http.StatusBadRequest)
		return
	}
	// Check rows affected for optimistic concurrency conflict
	affected, _ := result.RowsAffected()
	if affected == 0 {
		// Could be scoping (not authorized) or concurrency conflict
		if r.FormValue("_expected_updated_at") != "" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{"error": "conflict", "message": "Record was modified by another user"})
			return
		}
		httpError(w, "Not found or not authorized", http.StatusNotFound)
		return
	}

	// Fire update hooks - fetch the updated row for context
	updatedRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table), id)
	if len(updatedRows) > 0 {
		injectSessionContext(updatedRows[0], session)
		// Inject old_* fields so hooks can reference previous values: {{old_status}}, {{old_amount}}
		if len(oldRows) > 0 {
			for k, v := range oldRows[0] {
				updatedRows[0]["old_"+k] = v
			}
		}
		FireHooks(app, "update", table, updatedRows[0])
		FireFlowsForEvent(app, "on_update", table, updatedRows[0])
		FireWebhookSubscriptions(app, "update", table, updatedRows[0], session)
		Broadcast(app, table, "update", session)
	}
	var oldRow map[string]any
	if len(oldRows) > 0 {
		oldRow = oldRows[0]
	}
	var newRow map[string]any
	if len(updatedRows) > 0 {
		newRow = updatedRows[0]
	}
	LogAudit(app, "update", table, id, session, oldRow, newRow)
	appendHXTrigger(w, "benmore:changed")

	if isHTMX(r) {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "updated"})
}

// tableHasUniqueUserID reports whether `table` has a single-column UNIQUE
// constraint on user_id (a "one row per user" singleton). Used to gate the
// PATCH /api/{table} (no ID) upsert route.
func tableHasUniqueUserID(db *sql.DB, table string) bool {
	rows, err := db.Query(fmt.Sprintf("PRAGMA index_list(%s)", table))
	if err != nil {
		return false
	}
	defer rows.Close()

	type idx struct {
		name   string
		unique bool
	}
	var indexes []idx
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin sql.NullString
		var partial sql.NullInt64
		// SQLite returns: seq, name, unique, origin, partial
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			continue
		}
		if unique == 1 {
			indexes = append(indexes, idx{name: name, unique: true})
		}
	}
	for _, ix := range indexes {
		colRows, err := db.Query(fmt.Sprintf("PRAGMA index_info(%s)", ix.name))
		if err != nil {
			continue
		}
		var cols []string
		for colRows.Next() {
			var seqno, cid int
			var cname string
			if err := colRows.Scan(&seqno, &cid, &cname); err != nil {
				continue
			}
			cols = append(cols, cname)
		}
		colRows.Close()
		if len(cols) == 1 && cols[0] == "user_id" {
			return true
		}
	}
	return false
}

// handleSingletonUpdate implements the upsert-by-user_id pattern used by
// profile/settings pages: PATCH /api/{table} with no ID resolves the current
// user's row (or creates it) and applies the patched fields.
//
// Requires the table to have a UNIQUE(user_id) constraint - otherwise the
// route is meaningless and we return a helpful 400 telling the developer how
// to enable it.
// handleSingletonUpdate has no EnforceCRUDAccess call of its own ON
// PURPOSE: it dispatches to handleUpdate (existing row) or handleCreate
// (first write), and each runs the gate for its actual op (OpUpdate vs
// OpWrite). Gating OpUpdate here would wrongly reject the create branch
// on tables whose update mode is stricter than write. The only ungated
// work before dispatch is a row-existence lookup whose result is never
// returned to the caller.
func handleSingletonUpdate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	if !hasColumn(app, table, "user_id") {
		httpError(w, fmt.Sprintf("PATCH /api/%s requires a user_id column. Add user_id Int @unique to the model, or PATCH /api/%s/{id} with a specific row ID.", table, table), http.StatusBadRequest)
		return
	}
	if !tableHasUniqueUserID(app.DB, table) {
		httpError(w, fmt.Sprintf("PATCH /api/%s (singleton upsert) requires UNIQUE(user_id). Add @unique to user_id in the model, or PATCH /api/%s/{id} with a specific row ID.", table, table), http.StatusBadRequest)
		return
	}

	// Look up the existing row by user_id. If it exists, dispatch through
	// the normal update path (so all hooks/audit/scoping run). If not, fall
	// through to handleCreate so the row is materialized with user_id set
	// from the session.
	var existingID sql.NullString
	row := app.DB.QueryRow(fmt.Sprintf("SELECT CAST(id AS TEXT) FROM %s WHERE user_id = ? LIMIT 1", table), session.UserID)
	_ = row.Scan(&existingID)

	if existingID.Valid && existingID.String != "" {
		// Rewrite path to /api/{table}/{id} so handleUpdate can extract it.
		r.URL.Path = fmt.Sprintf("/api/%s/%s", table, existingID.String)
		handleUpdate(w, r, app, table)
		return
	}

	// No existing row - let handleCreate auto-inject user_id from session.
	handleCreate(w, r, app, table)
}

func handleDelete(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Coarse access gate (v2.7.12). `delete: admin` blocks non-admins
	// before the row lookup. Per-row scoping still applies for self/group.
	if !EnforceCRUDAccess(w, r, app, table, OpDelete, 0) {
		return
	}
	id := extractID(r.URL.Path, table)
	if id == "" {
		httpError(w, "Missing ID", http.StatusBadRequest)
		return
	}

	// CSRF validation - HX-Request header is trivially forgeable, never bypass CSRF for it
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// SECURITY: enforce scoping on deletes
	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "delete"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	scopeSQL := ""
	var scopeArgs []any
	if !session.IsAdminBypass() {
		if rule := memberOfFor(app, table, OpDelete); rule != nil && session != nil {
			pred, pargs := memberOfPredicate(app, table, rule, session, "delete")
			scopeSQL = " AND " + pred
			scopeArgs = append(scopeArgs, pargs...)
		} else if deleteUseGroup := session != nil && session.EffectiveHasGroup() && app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key); deleteUseGroup {
			aclSQL, aclArgs := aclFilter(table, session.Email, "delete")
			scopeSQL = fmt.Sprintf(" AND (%s = ? OR %s)", app.Group.Key, aclSQL)
			scopeArgs = append(scopeArgs, session.EffectiveGroupID())
			scopeArgs = append(scopeArgs, aclArgs...)
		} else if session != nil && hasColumn(app, table, "user_id") {
			aclSQL, aclArgs := aclFilter(table, session.Email, "delete")
			scopeSQL = fmt.Sprintf(" AND (user_id = ? OR %s)", aclSQL)
			scopeArgs = append(scopeArgs, session.UserID)
			scopeArgs = append(scopeArgs, aclArgs...)
		}
	}

	// Fetch row before delete (for hooks) - with same scoping as the delete
	prefetchArgs := append([]any{id}, scopeArgs...)
	deletedRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?%s", table, scopeSQL), prefetchArgs...)

	// Fire before-hooks (can abort)
	if len(deletedRows) > 0 {
		beforeRow := deletedRows[0]
		injectSessionContext(beforeRow, session)
		if err := FireBeforeHooks(app, "delete", table, beforeRow); err != nil {
			httpError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	// Soft delete: if table has deleted_at column, UPDATE instead of DELETE
	var deleteSQL string
	if hasColumn(app, table, "deleted_at") {
		deleteSQL = fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE id = ?%s AND deleted_at IS NULL", table, scopeSQL)
	} else {
		deleteSQL = fmt.Sprintf("DELETE FROM %s WHERE id = ?%s", table, scopeSQL)
	}
	deleteArgs := append([]any{id}, scopeArgs...)

	result, err := app.DB.Exec(deleteSQL, deleteArgs...)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			httpError(w, fmt.Sprintf("Cannot delete: other records reference this %s. Delete those first.", table), http.StatusConflict)
		} else {
			httpError(w, "Delete failed", http.StatusBadRequest)
		}
		return
	}
	// Check if anything was actually deleted (owner scoping may prevent it)
	rows, _ := result.RowsAffected()
	if rows == 0 {
		httpError(w, "Not found or not authorized", http.StatusNotFound)
		return
	}

	// Cascade soft deletes to child tables
	if hasColumn(app, table, "deleted_at") {
		cascadeSoftDelete(app, table, id)
	}

	// Fire delete hooks
	if len(deletedRows) > 0 {
		injectSessionContext(deletedRows[0], session)
		FireHooks(app, "delete", table, deletedRows[0])
		FireFlowsForEvent(app, "on_delete", table, deletedRows[0])
		FireWebhookSubscriptions(app, "delete", table, deletedRows[0], session)
		Broadcast(app, table, "delete", session)
		LogAudit(app, "delete", table, id, session, deletedRows[0], nil)
	}
	appendHXTrigger(w, "benmore:changed")

	if isHTMX(r) {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "deleted"})
}

func extractID(path, table string) string {
	prefix := fmt.Sprintf("/api/%s/", table)
	if strings.HasPrefix(path, prefix) {
		return strings.TrimPrefix(path, prefix)
	}
	return ""
}

func getUpdateFields(r *http.Request) map[string]string {
	fields := make(map[string]string)

	// Try JSON body first
	if r.Header.Get("Content-Type") == "application/json" {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			for k, v := range body {
				fields[k] = jsonToFormValue(v)
			}
			return fields
		}
	}

	// Fall back to form values. Coerce boolean-like strings ("true"/
	// "false") to "1"/"0" so they line up with SQLite INTEGER columns
	// - otherwise the checkbox-via-hx-vals pattern writes the literal
	// string "true" into a boolean column and downstream queries
	// (`CASE WHEN x THEN ... END`) treat it as falsy.
	for k, v := range r.Form {
		if len(v) > 0 {
			fields[k] = coerceBoolString(v[0])
		}
	}

	// Also check hx-vals (JSON in query param)
	if hxVals := r.URL.Query().Get("hx-vals"); hxVals != "" {
		var vals map[string]string
		if err := json.Unmarshal([]byte(hxVals), &vals); err == nil {
			for k, v := range vals {
				fields[k] = v
			}
		}
	}

	return fields
}

// jsonToFormValue converts a JSON-decoded value into the string shape
// the form-encoded handlers expect. Booleans become "1" or "0" (not
// "true"/"false") so they line up with SQLite INTEGER columns. Without
// this, an HTMX checkbox using `hx-vals='js:{completed: event.target.checked}'`
// - the canonical pattern in the build docs - writes the literal string
// "true" into the column. SQLite stores it (loose typing), but
// downstream `CASE WHEN completed THEN 1 ELSE 0 END` queries treat the
// string as 0, and `{{if .completed}}` in templates treats it as truthy
// (non-empty string), giving the user a checkbox that says "checked"
// but a stat card that says "0 done".
func jsonToFormValue(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "1"
		}
		return "0"
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// coerceBoolString turns literal "true"/"false" form values into
// "1"/"0". Form-encoded submissions from `hx-vals='js:{...:bool}'`
// arrive as strings, so this is the last-mile catch for the same
// issue jsonToFormValue handles for the JSON body case.
func coerceBoolString(s string) string {
	switch strings.ToLower(s) {
	case "true":
		return "1"
	case "false":
		return "0"
	}
	return s
}

func hasColumn(app *App, table, column string) bool {
	for _, t := range app.Tables {
		if t.Name == table {
			for _, c := range t.Columns {
				if c.Name == column {
					return true
				}
			}
		}
	}
	return false
}

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return defaultVal
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return defaultVal
	}
	if n < 1 {
		return defaultVal
	}
	return n
}

func httpError(w http.ResponseWriter, msg string, code int) {
	http.Error(w, msg, code)
}

func handleBatchCreate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row create (M5, 2026-06-11
	// audit): before this, `access: write: admin` / `all: off` tables
	// were writable through /batch.
	if !EnforceCRUDAccess(w, r, app, table, OpWrite, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	var items []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		httpError(w, "Expected JSON array", http.StatusBadRequest)
		return
	}
	if len(items) == 0 {
		httpError(w, "Empty array", http.StatusBadRequest)
		return
	}

	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	protected := map[string]bool{
		"user_id": true, "created_at": true, "updated_at": true,
		"password_hash": true, "role": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}

	// Wrap entire batch in a transaction
	tx, err := app.DB.Begin()
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Extract validation rules once for the table
	validationRules := ExtractValidationRules(app, table)

	isUUID := app.IsUUIDTable(table)
	var ids []any
	for _, item := range items {
		// member-of: every batch item must land in a parent the caller is
		// a member of - same gate as single-row create (M5). All-or-
		// nothing: one bad item rolls the whole batch back.
		if d := memberOfCreateDenial(app, table, session, func(col string) string {
			if v, ok := item[col]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}); d != nil {
			tx.Rollback()
			writeMemberOfDenial(w, r, d)
			return
		}

		var fields []string
		var placeholders []string
		var values []any

		for _, col := range cols {
			if col.PK { continue }
			if col.Name == "user_id" {
				if session != nil {
					fields = append(fields, col.Name)
					placeholders = append(placeholders, "?")
					values = append(values, session.UserID)
				}
				continue
			}
			if app.Group != nil && col.Name == app.Group.Key && session != nil && session.EffectiveHasGroup() {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, session.EffectiveGroupID())
				continue
			}
			if protected[col.Name] { continue }

			if val, ok := item[col.Name]; ok && val != nil {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, fmt.Sprintf("%v", val))
			}
		}

		if len(fields) == 0 { continue }

		// Validate fields against rules
		if len(validationRules) > 0 {
			for field, rule := range validationRules {
				if val, ok := item[field]; ok {
					valStr := fmt.Sprintf("%v", val)
					for _, r := range strings.Split(rule, ",") {
						r = strings.TrimSpace(r)
						if r == "required" && valStr == "" {
							tx.Rollback()
							httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": fmt.Sprintf("Field '%s' is required", field)})
							return
						}
					}
				} else if strings.Contains(rule, "required") {
					tx.Rollback()
					httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": fmt.Sprintf("Field '%s' is required", field)})
					return
				}
			}
		}

		// Build before-hook row and fire before-hooks
		beforeRow := make(map[string]any)
		for i, f := range fields {
			beforeRow[f] = values[i]
		}
		injectSessionContext(beforeRow, session)
		if err := FireBeforeHooks(app, "insert", table, beforeRow); err != nil {
			tx.Rollback()
			httpError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		sqlStr := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
			table, strings.Join(fields, ", "), strings.Join(placeholders, ", "))
		result, err := tx.Exec(sqlStr, values...)
		if err != nil {
			tx.Rollback()
			httpError(w, fmt.Sprintf("Batch insert failed: %s", err.Error()), http.StatusBadRequest)
			return
		}

		var id any
		if isUUID {
			var uuidID string
			err := tx.QueryRow(fmt.Sprintf("SELECT id FROM %s WHERE rowid = last_insert_rowid()", table)).Scan(&uuidID)
			if err != nil {
				tx.Rollback()
				httpError(w, "Batch insert failed: could not retrieve UUID", http.StatusInternalServerError)
				return
			}
			id = uuidID
		} else {
			intID, _ := result.LastInsertId()
			id = intID
		}
		ids = append(ids, id)

		// Collect row data for post-commit hooks
		row := make(map[string]any)
		for i, f := range fields {
			row[f] = values[i]
		}
		row["id"] = id
		injectSessionContext(row, session)
	}

	if err := tx.Commit(); err != nil {
		httpError(w, "Commit failed", http.StatusInternalServerError)
		return
	}

	// Fire hooks and audit AFTER commit - hooks write to DB and would deadlock inside the tx
	for _, id := range ids {
		LogAudit(app, "create", table, fmt.Sprintf("%v", id), session, nil, nil)
	}

	Broadcast(app, table, "insert", session)
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ids": ids, "count": len(ids), "status": "created"})
}

// ingestLimiter limits streaming ingestion to 5 requests per minute per user (expensive operation).
var ingestLimiter = NewRateLimiter(5, time.Minute)

// handleStreamingIngest accepts NDJSON (newline-delimited JSON) for bulk data ingestion.
// Single transaction, no after-hooks (performance), before-hooks fire per row.
// Returns: {"ingested": N, "errors": N, "duration_ms": N, "status": "completed"}
func handleStreamingIngest(w http.ResponseWriter, r *http.Request, app *App, table string) {
	start := time.Now()

	// Same coarse access gate as the single-row create (M5).
	if !EnforceCRUDAccess(w, r, app, table, OpWrite, 0) {
		return
	}

	// CSRF check (Bearer bypass)
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Auth + scope check
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if err := checkScope(session, table, "write"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	// Rate limit: 5 ingestions per minute per user
	rateLimitKey := fmt.Sprintf("ingest:user:%d", session.UserID)
	if !ingestLimiter.Allow(rateLimitKey) {
		http.Error(w, "Rate limit exceeded. Try again later.", http.StatusTooManyRequests)
		return
	}

	// Body size limit: 100MB
	const maxBodySize = 100 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	// Get table columns once for validation
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Build column allowlist and detect which columns exist
	validCols := make(map[string]bool)
	colMap := make(map[string]Column)
	for _, col := range cols {
		validCols[col.Name] = true
		colMap[col.Name] = col
	}

	// Protected fields
	protected := map[string]bool{
		"user_id": true, "created_at": true, "updated_at": true,
		"password_hash": true, "role": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}

	// Extract validation rules once
	validationRules := ExtractValidationRules(app, table)

	// Begin transaction
	tx, err := app.DB.Begin()
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	const maxRows = 100000
	const maxLineSize = 1024 * 1024 // 1MB max line length

	scanner := bufio.NewScanner(r.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	var ingested, errCount int
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()

		// Skip empty lines
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		// Enforce max row limit
		if ingested+errCount >= maxRows {
			tx.Rollback()
			httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"error":    fmt.Sprintf("exceeded maximum of %d rows per request", maxRows),
				"ingested": ingested,
				"errors":   errCount,
				"line":     lineNum,
			})
			return
		}

		// Parse JSON line
		var item map[string]any
		if err := json.Unmarshal(line, &item); err != nil {
			errCount++
			continue
		}

		// member-of: each row must land in a parent the caller is a
		// member of - same gate as single-row create (M5). Ingest's
		// per-row error semantics apply: the row is skipped and counted,
		// the rest of the stream continues.
		if d := memberOfCreateDenial(app, table, session, func(col string) string {
			if v, ok := item[col]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}); d != nil {
			errCount++
			continue
		}

		// Strip protected fields silently (same as handleCreate) and reject truly unknown columns
		for key := range item {
			if protected[key] {
				delete(item, key) // strip, don't reject
				continue
			}
			if !validCols[key] {
				errCount++
				item = nil
				break
			}
		}
		if item == nil {
			continue
		}

		// Build INSERT fields
		var fields []string
		var placeholders []string
		var values []any

		for _, col := range cols {
			if col.PK {
				continue
			}
			if col.Name == "user_id" {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, session.UserID)
				continue
			}
			if app.Group != nil && col.Name == app.Group.Key && session.EffectiveHasGroup() {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, session.EffectiveGroupID())
				continue
			}
			if protected[col.Name] {
				continue
			}

			if val, ok := item[col.Name]; ok && val != nil {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, fmt.Sprintf("%v", val))
			}
		}

		if len(fields) == 0 {
			errCount++
			continue
		}

		// Validate fields against rules
		skipRow := false
		if len(validationRules) > 0 {
			for field, rule := range validationRules {
				if val, ok := item[field]; ok {
					valStr := fmt.Sprintf("%v", val)
					for _, r := range strings.Split(rule, ",") {
						r = strings.TrimSpace(r)
						if r == "required" && valStr == "" {
							skipRow = true
							break
						}
					}
				} else if strings.Contains(rule, "required") {
					skipRow = true
				}
				if skipRow {
					break
				}
			}
		}
		if skipRow {
			errCount++
			continue
		}

		// Fire before-hooks (can abort individual rows)
		beforeRow := make(map[string]any)
		for i, f := range fields {
			beforeRow[f] = values[i]
		}
		injectSessionContext(beforeRow, session)
		if err := FireBeforeHooks(app, "insert", table, beforeRow); err != nil {
			errCount++
			continue
		}

		// Execute parameterized INSERT
		sqlStr := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
			table, strings.Join(fields, ", "), strings.Join(placeholders, ", "))
		_, err := tx.Exec(sqlStr, values...)
		if err != nil {
			errCount++
			continue
		}

		ingested++
	}

	// Check for scanner errors (including MaxBytesReader)
	if err := scanner.Err(); err != nil {
		if ingested == 0 {
			tx.Rollback()
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error":    "read error: " + err.Error(),
				"ingested": 0,
				"errors":   errCount,
			})
			return
		}
		// Partial read - commit what we have
		log.Printf("ingest: scanner error after %d rows: %v", ingested, err)
	}

	if ingested == 0 {
		tx.Rollback()
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error":    "no rows ingested",
			"ingested": 0,
			"errors":   errCount,
		})
		return
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{
			"error":    "commit failed",
			"ingested": 0,
			"errors":   errCount,
		})
		return
	}

	// Single audit log entry for the batch
	LogAudit(app, "ingest", table, fmt.Sprintf("batch:%d", ingested), session, nil, map[string]any{
		"ingested": ingested,
		"errors":   errCount,
	})

	// SSE broadcast
	Broadcast(app, table, "insert", session)
	appendHXTrigger(w, "benmore:changed")

	// Meter the ingestion
	Increment(meterScope(session), "ingest_rows")

	durationMs := time.Since(start).Milliseconds()
	httpJSON(w, http.StatusOK, map[string]any{
		"ingested":    ingested,
		"errors":      errCount,
		"duration_ms": durationMs,
		"status":      "completed",
	})
}

func handleBatchUpdate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row update (M5).
	if !EnforceCRUDAccess(w, r, app, table, OpUpdate, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	var body struct {
		IDs    []any             `json:"ids"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, "Expected JSON with ids and fields", http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 || len(body.Fields) == 0 {
		httpError(w, "ids and fields required", http.StatusBadRequest)
		return
	}

	// member-of: a batch update that re-points the join column must
	// verify membership in the NEW parent - same gate as single-row
	// update (M5). The per-row WHERE below only proves membership in
	// each row's CURRENT parent.
	if d := memberOfRepointDenial(app, table, session, func(col string) string { return body.Fields[col] }); d != nil {
		writeMemberOfDenial(w, r, d)
		return
	}

	// Build allowlist
	cols, _ := GetTableColumns(app.DB, table)
	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}
	protected := map[string]bool{
		"id": true, "user_id": true, "created_at": true,
		"updated_at": true, "password_hash": true, "role": true, "_csrf": true,
	}
	for _, f := range workflowProtectedFields(app, table) {
		protected[f] = true
	}

	var sets []string
	var values []any
	for k, v := range body.Fields {
		if protected[k] || !validCols[k] {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = ?", k))
		values = append(values, v)
	}
	if len(sets) == 0 {
		httpError(w, "No valid fields", http.StatusBadRequest)
		return
	}

	placeholders := make([]string, len(body.IDs))
	for i, id := range body.IDs {
		placeholders[i] = "?"
		values = append(values, id)
	}

	// Fire before-hooks per row - fetch existing rows first
	idPlaceholders := make([]string, len(body.IDs))
	idArgs := make([]any, len(body.IDs))
	for i, id := range body.IDs {
		idPlaceholders[i] = "?"
		idArgs[i] = id
	}
	oldRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", table, strings.Join(idPlaceholders, ",")), idArgs...)
	oldRowIndex := make(map[string]map[string]any)
	for _, row := range oldRows {
		if id, ok := row["id"]; ok {
			oldRowIndex[fmt.Sprintf("%v", id)] = row
		}
	}

	for _, id := range body.IDs {
		beforeRow := make(map[string]any)
		beforeRow["id"] = id
		for k, v := range body.Fields {
			beforeRow[k] = v
		}
		injectSessionContext(beforeRow, session)
		if err := FireBeforeHooks(app, "update", table, beforeRow); err != nil {
			httpError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	sqlStr := fmt.Sprintf("UPDATE %s SET %s WHERE id IN (%s)",
		table, strings.Join(sets, ", "), strings.Join(placeholders, ","))

	// SECURITY: enforce org/owner scoping + ACL on batch update
	if !session.IsAdminBypass() {
		if rule := memberOfFor(app, table, OpUpdate); rule != nil && session != nil {
			pred, pargs := memberOfPredicate(app, table, rule, session, "edit")
			sqlStr += " AND " + pred
			values = append(values, pargs...)
		} else if session != nil && session.EffectiveHasGroup() && app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key) {
			aclSQL, aclArgs := aclFilter(table, session.Email, "edit")
			sqlStr += fmt.Sprintf(" AND (%s = ? OR %s)", app.Group.Key, aclSQL)
			values = append(values, session.EffectiveGroupID())
			values = append(values, aclArgs...)
		} else if session != nil && hasColumn(app, table, "user_id") {
			aclSQL, aclArgs := aclFilter(table, session.Email, "edit")
			sqlStr += fmt.Sprintf(" AND (user_id = ? OR %s)", aclSQL)
			values = append(values, session.UserID)
			values = append(values, aclArgs...)
		}
	}

	result, err := app.DB.Exec(sqlStr, values...)
	if err != nil {
		httpError(w, fmt.Sprintf("Batch update failed: %s", err.Error()), http.StatusBadRequest)
		return
	}
	affected, _ := result.RowsAffected()

	// Fire after-hooks and audit per row
	updatedRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", table, strings.Join(idPlaceholders, ",")), idArgs...)
	for _, row := range updatedRows {
		idStr := fmt.Sprintf("%v", row["id"])
		injectSessionContext(row, session)
		FireHooks(app, "update", table, row)
		FireFlowsForEvent(app, "on_update", table, row)
		FireWebhookSubscriptions(app, "update", table, row, session)
		LogAudit(app, "update", table, idStr, session, oldRowIndex[idStr], row)
	}

	Broadcast(app, table, "update", session)
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"updated": affected, "status": "updated"})
}

func handleBatchDelete(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row delete (M5).
	if !EnforceCRUDAccess(w, r, app, table, OpDelete, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "delete"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	var body struct {
		IDs []any `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, "Expected JSON with ids", http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 {
		httpError(w, "ids required", http.StatusBadRequest)
		return
	}

	placeholders := make([]string, len(body.IDs))
	values := make([]any, len(body.IDs))
	for i, id := range body.IDs {
		placeholders[i] = "?"
		values[i] = id
	}

	// Fetch rows before delete (for before-hooks and audit)
	prefetchRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", table, strings.Join(placeholders, ",")), values...)

	// Fire before-hooks per row
	for _, row := range prefetchRows {
		injectSessionContext(row, session)
		if err := FireBeforeHooks(app, "delete", table, row); err != nil {
			httpError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	// Soft delete if table has deleted_at, otherwise hard delete
	var sql string
	if hasColumn(app, table, "deleted_at") {
		sql = fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE id IN (%s) AND deleted_at IS NULL",
			table, strings.Join(placeholders, ","))
	} else {
		sql = fmt.Sprintf("DELETE FROM %s WHERE id IN (%s)",
			table, strings.Join(placeholders, ","))
	}

	// SECURITY: enforce org/owner scoping + ACL on batch delete
	if !session.IsAdminBypass() {
		if rule := memberOfFor(app, table, OpDelete); rule != nil && session != nil {
			pred, pargs := memberOfPredicate(app, table, rule, session, "delete")
			sql += " AND " + pred
			values = append(values, pargs...)
		} else if session != nil && session.EffectiveHasGroup() && app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key) {
			aclSQL, aclArgs := aclFilter(table, session.Email, "delete")
			sql += fmt.Sprintf(" AND (%s = ? OR %s)", app.Group.Key, aclSQL)
			values = append(values, session.EffectiveGroupID())
			values = append(values, aclArgs...)
		} else if session != nil && hasColumn(app, table, "user_id") {
			aclSQL, aclArgs := aclFilter(table, session.Email, "delete")
			sql += fmt.Sprintf(" AND (user_id = ? OR %s)", aclSQL)
			values = append(values, session.UserID)
			values = append(values, aclArgs...)
		}
	}

	result, err := app.DB.Exec(sql, values...)
	if err != nil {
		httpError(w, fmt.Sprintf("Batch delete failed: %s", err.Error()), http.StatusBadRequest)
		return
	}
	affected, _ := result.RowsAffected()

	// Cascade soft deletes for each deleted row
	if hasColumn(app, table, "deleted_at") {
		for _, row := range prefetchRows {
			if id, ok := row["id"]; ok {
				cascadeSoftDelete(app, table, fmt.Sprintf("%v", id))
			}
		}
	}

	// Fire after-hooks and audit per row
	for _, row := range prefetchRows {
		idStr := fmt.Sprintf("%v", row["id"])
		injectSessionContext(row, session)
		FireHooks(app, "delete", table, row)
		FireFlowsForEvent(app, "on_delete", table, row)
		FireWebhookSubscriptions(app, "delete", table, row, session)
		LogAudit(app, "delete", table, idStr, session, row, nil)
	}

	Broadcast(app, table, "delete", session)
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted": affected, "status": "deleted"})
}

// cascadeSoftDelete soft-deletes child rows in tables that have foreign keys
// pointing to the deleted parent. Only affects child tables that also have
// a deleted_at column (convention-based cascading).
func cascadeSoftDelete(app *App, parentTable string, parentID string) {
	// Walk the JoinMap to find child tables with FKs pointing at parentTable
	for childTable, fks := range app.JoinMap {
		for fkCol, fk := range fks {
			if fk.Table != parentTable || fk.Column != "id" {
				continue
			}
			// Only cascade if the child table also uses soft delete
			if !hasColumn(app, childTable, "deleted_at") {
				continue
			}
			result, err := app.DB.Exec(
				fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE %s = ? AND deleted_at IS NULL", childTable, fkCol),
				parentID,
			)
			if err != nil {
				log.Printf("CASCADE SOFT DELETE ERROR [%s.%s → %s]: %s", childTable, fkCol, parentTable, err)
			} else {
				affected, _ := result.RowsAffected()
				if affected > 0 {
					log.Printf("CASCADE SOFT DELETE: %d rows in %s (via %s = %s)", affected, childTable, fkCol, parentID)
					BroadcastUnscoped(app, childTable, "delete")
				}
			}
		}
	}
}

// getCascadedChildIDs returns IDs of rows that were just cascade soft-deleted.
func getCascadedChildIDs(app *App, childTable, fkCol, parentID string) []string {
	rows, err := QueryRows(app.DB,
		fmt.Sprintf("SELECT id FROM %s WHERE %s = ? AND deleted_at IS NOT NULL", childTable, fkCol),
		parentID)
	if err != nil {
		return nil
	}
	var ids []string
	for _, row := range rows {
		if id, ok := row["id"]; ok {
			ids = append(ids, fmt.Sprintf("%v", id))
		}
	}
	return ids
}

// ===== Cross-Table Transactions =====

// transactionOp represents a single operation within an atomic transaction.
type transactionOp struct {
	Table  string         `json:"table"`
	Action string         `json:"action"` // "insert", "update", "delete"
	Data   map[string]any `json:"data"`   // field values for insert/update
	ID     any            `json:"id"`     // row ID for update/delete
	Ref    string         `json:"ref"`    // FK field to set from a prior operation's ID (e.g., "order_id")
	RefOp  int            `json:"ref_op"` // index of prior operation whose ID to use
}

// transactionResult is the result of one operation in the transaction.
type transactionResult struct {
	Table  string `json:"table"`
	Action string `json:"action"`
	ID     any    `json:"id"`
}

// handleTransaction executes multiple CRUD operations atomically in a single transaction.
// If any operation fails, the entire transaction rolls back.
//
// Request: POST /api/_transaction
// Body: {"operations": [{table, action, data, id?, ref?, ref_op?}, ...]}
//
// The "ref" field enables forward references: if operation 0 inserts an order and
// operation 1 inserts a line item, set ref="order_id" and ref_op=0 on operation 1
// to automatically set line_items.order_id = the ID from operation 0.
func handleTransaction(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	var body struct {
		Operations []transactionOp `json:"operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if len(body.Operations) == 0 {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "no operations"})
		return
	}

	// Validate all tables exist and actions are valid
	validTables := make(map[string]bool)
	tables, _ := GetTableNames(app.DB)
	for _, t := range tables {
		validTables[t] = true
	}
	for i, op := range body.Operations {
		if !validTables[op.Table] {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("operation %d: unknown table '%s'", i, op.Table),
			})
			return
		}
		if op.Action != "insert" && op.Action != "update" && op.Action != "delete" {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("operation %d: invalid action '%s' (must be insert, update, or delete)", i, op.Action),
			})
			return
		}
		if op.Ref != "" && (op.RefOp < 0 || op.RefOp >= i) {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("operation %d: ref_op must reference a prior operation (0-%d)", i, i-1),
			})
			return
		}
		// Scope check per operation
		scopeAction := "write"
		if op.Action == "delete" {
			scopeAction = "delete"
		}
		if err := checkScope(session, op.Table, scopeAction); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{
				"error": fmt.Sprintf("operation %d: %s", i, err.Error()),
			})
			return
		}
		// Coarse access gate per operation (M5, 2026-06-11 audit) - the
		// same EnforceCRUDAccess every single-row handler runs. Before
		// this, `access: write: admin` / `all: off` tables were writable
		// through /api/_transaction.
		opAccess := OpWrite
		switch op.Action {
		case "update":
			opAccess = OpUpdate
		case "delete":
			opAccess = OpDelete
		}
		if !EnforceCRUDAccess(w, r, app, op.Table, opAccess, 0) {
			return
		}
	}

	// Begin transaction
	tx, err := app.DB.Begin()
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "transaction start failed"})
		return
	}
	defer tx.Rollback()

	results := make([]transactionResult, len(body.Operations))

	for i, op := range body.Operations {
		// Resolve forward reference
		if op.Ref != "" && i > 0 {
			refID := results[op.RefOp].ID
			if refID != nil {
				if op.Data == nil {
					op.Data = make(map[string]any)
				}
				op.Data[op.Ref] = refID
			}
		}

		// member-of pre-write check (M5), mirroring the single-row paths.
		// Carve-out: when the join column is ref-fed from a PRIOR op in
		// this same transaction (op.Ref names the column), the parent was
		// just created by this caller inside the uncommitted tx -
		// memberOfHas queries app.DB and can't see it, and creator-of-
		// parent-in-same-tx is authorized by construction (matches the
		// founder auto-join semantics on the single-row create path).
		memberOfVal := func(col string) string {
			if op.Ref == col {
				return ""
			}
			if v, ok := op.Data[col]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}
		joinColRefFed := func(accessOp AccessOp) bool {
			if op.Ref == "" {
				return false
			}
			rule := memberOfFor(app, op.Table, accessOp)
			return rule != nil && rule.localJoinCol(app, op.Table) == op.Ref
		}

		switch op.Action {
		case "insert":
			if d := memberOfCreateDenial(app, op.Table, session, memberOfVal); d != nil && !joinColRefFed(OpWrite) {
				writeMemberOfDenial(w, r, d)
				return
			}
			id, err := txInsert(tx, app, op.Table, op.Data, session)
			if err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": fmt.Sprintf("operation %d (insert %s): %s", i, op.Table, err),
				})
				return
			}
			results[i] = transactionResult{Table: op.Table, Action: "insert", ID: id}

		case "update":
			if d := memberOfRepointDenial(app, op.Table, session, memberOfVal); d != nil {
				writeMemberOfDenial(w, r, d)
				return
			}
			rowID := fmt.Sprintf("%v", op.ID)
			if err := txUpdate(tx, app, op.Table, rowID, op.Data, session); err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": fmt.Sprintf("operation %d (update %s/%s): %s", i, op.Table, rowID, err),
				})
				return
			}
			results[i] = transactionResult{Table: op.Table, Action: "update", ID: op.ID}

		case "delete":
			rowID := fmt.Sprintf("%v", op.ID)
			if err := txDelete(tx, app, op.Table, rowID, session); err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": fmt.Sprintf("operation %d (delete %s/%s): %s", i, op.Table, rowID, err),
				})
				return
			}
		}
	}

	// Commit
	if err := tx.Commit(); err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "commit failed"})
		return
	}

	// Post-commit: fire hooks, audit, SSE for each operation
	for _, res := range results {
		if res.ID != nil {
			LogAudit(app, res.Action, res.Table, fmt.Sprintf("%v", res.ID), session, nil, nil)
			Broadcast(app, res.Table, res.Action, session)
		}
	}
	appendHXTrigger(w, "benmore:changed")

	httpJSON(w, http.StatusOK, map[string]any{
		"status":  "committed",
		"count":   len(results),
		"results": results,
	})
}

// txInsert performs a single INSERT within a transaction.
// Enforces protected fields and auto-injects user_id/org_id.
// Returns the new row's ID (int64 for INTEGER PK, string for UUID PK).
func txInsert(tx *sql.Tx, app *App, table string, data map[string]any, session *Session) (any, error) {
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		return nil, err
	}

	protected := map[string]bool{
		"user_id": true, "created_at": true, "updated_at": true,
		"password_hash": true, "role": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	for _, f := range workflowProtectedFields(app, table) {
		protected[f] = true
	}

	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}

	var fields []string
	var placeholders []string
	var values []any

	// Auto-inject user_id
	if session != nil && validCols["user_id"] {
		fields = append(fields, "user_id")
		placeholders = append(placeholders, "?")
		values = append(values, session.UserID)
	}
	// Auto-inject org key - EFFECTIVE group so a stepped-in admin's created
	// rows land in the acted-as tenant, not the admin's (usually empty) native group.
	if app.Group != nil && app.Group.Key != "" && session != nil && session.EffectiveHasGroup() && validCols[app.Group.Key] {
		fields = append(fields, app.Group.Key)
		placeholders = append(placeholders, "?")
		values = append(values, session.EffectiveGroupID())
	}

	for k, v := range data {
		if protected[k] || !validCols[k] {
			continue
		}
		fields = append(fields, k)
		placeholders = append(placeholders, "?")
		values = append(values, v)
	}

	if len(fields) == 0 {
		return nil, fmt.Errorf("no valid fields")
	}

	sqlStr := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(fields, ", "), strings.Join(placeholders, ", "))

	result, err := tx.Exec(sqlStr, values...)
	if err != nil {
		return nil, err
	}

	if app.IsUUIDTable(table) {
		var uuidID string
		err := tx.QueryRow(fmt.Sprintf("SELECT id FROM %s WHERE rowid = last_insert_rowid()", table)).Scan(&uuidID)
		if err != nil {
			return nil, fmt.Errorf("insert succeeded but failed to retrieve UUID: %w", err)
		}
		return uuidID, nil
	}
	id, err := result.LastInsertId()
	return id, err
}

// txUpdate performs a single UPDATE within a transaction.
// Enforces protected fields and scoping.
func txUpdate(tx *sql.Tx, app *App, table string, id string, data map[string]any, session *Session) error {
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		return err
	}

	protected := map[string]bool{
		"id": true, "user_id": true, "created_at": true,
		"updated_at": true, "password_hash": true, "role": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	for _, f := range workflowProtectedFields(app, table) {
		protected[f] = true
	}

	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}

	var sets []string
	var values []any
	for k, v := range data {
		if protected[k] || !validCols[k] {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = ?", k))
		values = append(values, v)
	}
	if len(sets) == 0 {
		return fmt.Errorf("no valid fields")
	}

	// Auto-set updated_at
	if validCols["updated_at"] {
		sets = append(sets, "updated_at = datetime('now')")
	}

	sqlStr := fmt.Sprintf("UPDATE %s SET %s WHERE id = ?", table, strings.Join(sets, ", "))
	values = append(values, id)

	// Scoping (owner/org OR explicit ACL)
	if !session.IsAdminBypass() {
		if rule := memberOfFor(app, table, OpUpdate); rule != nil {
			pred, pargs := memberOfPredicate(app, table, rule, session, "edit")
			sqlStr += " AND " + pred
			values = append(values, pargs...)
		} else if app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key) && session.EffectiveHasGroup() {
			aclSQL, aclArgs := aclFilter(table, session.Email, "edit")
			sqlStr += fmt.Sprintf(" AND (%s = ? OR %s)", app.Group.Key, aclSQL)
			values = append(values, session.EffectiveGroupID())
			values = append(values, aclArgs...)
		} else if hasColumn(app, table, "user_id") {
			aclSQL, aclArgs := aclFilter(table, session.Email, "edit")
			sqlStr += fmt.Sprintf(" AND (user_id = ? OR %s)", aclSQL)
			values = append(values, session.UserID)
			values = append(values, aclArgs...)
		}
	}

	result, err := tx.Exec(sqlStr, values...)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("not found or not authorized")
	}
	return nil
}

// txDelete performs a single DELETE (or soft delete) within a transaction.
// Enforces scoping.
func txDelete(tx *sql.Tx, app *App, table string, id string, session *Session) error {
	var sqlStr string
	var values []any

	if hasColumn(app, table, "deleted_at") {
		sqlStr = fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE id = ? AND deleted_at IS NULL", table)
	} else {
		sqlStr = fmt.Sprintf("DELETE FROM %s WHERE id = ?", table)
	}
	values = append(values, id)

	// Scoping (owner/org OR explicit ACL)
	if !session.IsAdminBypass() {
		if rule := memberOfFor(app, table, OpDelete); rule != nil {
			pred, pargs := memberOfPredicate(app, table, rule, session, "delete")
			sqlStr += " AND " + pred
			values = append(values, pargs...)
		} else if app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key) && session.EffectiveHasGroup() {
			aclSQL, aclArgs := aclFilter(table, session.Email, "delete")
			sqlStr += fmt.Sprintf(" AND (%s = ? OR %s)", app.Group.Key, aclSQL)
			values = append(values, session.EffectiveGroupID())
			values = append(values, aclArgs...)
		} else if hasColumn(app, table, "user_id") {
			aclSQL, aclArgs := aclFilter(table, session.Email, "delete")
			sqlStr += fmt.Sprintf(" AND (user_id = ? OR %s)", aclSQL)
			values = append(values, session.UserID)
			values = append(values, aclArgs...)
		}
	}

	result, err := tx.Exec(sqlStr, values...)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("not found or not authorized")
	}
	return nil
}
