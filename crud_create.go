//go:build !cli

package main

// Record creation and loading newly inserted rows.

import (
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

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
	if reason, blocked := checkStorageCap(app, 0); blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInsufficientStorage)
		fmt.Fprintf(w, `{"error":"storage cap reached","detail":%q}`, reason)
		return
	}

	idempotencyKey := r.Header.Get("X-Idempotency-Key")
	if len(idempotencyKey) > 256 || idempotencyKey != "" && strings.Contains(r.Header.Get("Content-Type"), "multipart") {
		httpJSON(w, 400, map[string]any{"error": "idempotency requires a key of at most 256 bytes and a non-multipart body"})
		return
	}

	// Parse request body: multipart (file uploads), JSON, or form-encoded
	if strings.Contains(r.Header.Get("Content-Type"), "multipart") {
		r.ParseMultipartForm(maxUploadSize)
	} else if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		// JSON body → parse into r.Form so the rest of the handler works uniformly
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body == nil {
			httpJSON(w, 400, map[string]any{"error": "expected a JSON object"})
			return
		} else {
			r.Form = make(map[string][]string)
			for k, v := range body {
				r.Form.Set(k, jsonToFormValue(v))
			}
		}
	} else {
		r.ParseForm()
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

	if idempotencyKey != "" && session == nil {
		httpJSON(w, 401, map[string]any{"error": "idempotency requires authentication"})
		return
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
		"user_id":                  true,
		"created_at":               true,
		"updated_at":               true,
		"password_hash":            true,
		"password_change_required": true,
		"role":                     true,
	}
	// Protect org key from user input - it's auto-injected from session
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	// H-10: protect the configurable in-tenant RoleField (e.g. member_role)
	// on the membership table so a member cannot self-elevate via CRUD.
	if app.Group != nil && app.Group.RoleField != "" && app.Group.Table != "" && table == app.Group.Table {
		protected[app.Group.RoleField] = true
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

	tx, err := app.DB.Begin()
	if err != nil {
		httpJSON(w, 500, map[string]any{"error": "transaction start failed"})
		return
	}
	defer tx.Rollback()
	var idempKey, fingerprint string
	if idempotencyKey != "" {
		idempKey, fingerprint = createIdempotencyIdentity(r, table, session, idempotencyKey)
		if _, err := tx.Exec("DELETE FROM _benmore_idempotency WHERE key=? AND user_id=? AND created_at < datetime('now', '-1 day')", idempKey, session.UserID); err != nil {
			httpJSON(w, 500, map[string]any{"error": "idempotency unavailable"})
			return
		}
		var cached, previous string
		var status int
		err := tx.QueryRow("SELECT response, status_code, fingerprint FROM _benmore_idempotency WHERE key=? AND user_id=?", idempKey, session.UserID).Scan(&cached, &status, &previous)
		if err == nil {
			if !hmac.Equal([]byte(previous), []byte(fingerprint)) {
				httpJSON(w, 409, map[string]any{"error": "idempotency key already used with different input or authorization"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if isHTMX(r) {
				w.Header().Set("HX-Refresh", "true")
			}
			w.WriteHeader(status)
			w.Write([]byte(cached))
			return
		}
		if err != sql.ErrNoRows {
			httpJSON(w, 500, map[string]any{"error": "idempotency unavailable"})
			return
		}
		var legacy bool
		if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM _benmore_idempotency WHERE key=? AND user_id IN (?,0) AND fingerprint='' AND created_at >= datetime('now', '-1 day'))", idempotencyKey, session.UserID).Scan(&legacy); err != nil {
			httpJSON(w, 500, map[string]any{"error": "idempotency unavailable"})
			return
		}
		if legacy {
			httpJSON(w, 409, map[string]any{"error": "legacy idempotency key: verify the original operation before retrying"})
			return
		}

	}
	if d := memberOfCreateDenialWith(tx, app, table, session, r.FormValue); d != nil {
		writeMemberOfDenial(w, r, d)
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
	if err := fireBeforeHooksWith(tx, app, "insert", table, beforeRow); err != nil {
		httpError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	insertSQL := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table,
		strings.Join(fields, ", "),
		strings.Join(placeholders, ", "),
	)

	var id any
	err = tx.QueryRow(insertSQL+" RETURNING id", values...).Scan(&id)
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

	idStr := fmt.Sprint(id)

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
		if err := memberOfAutoJoinWith(tx, app, rule, id, session); err != nil {
			log.Printf("member-of auto-join into %s failed for %s id=%v: %v", rule.Table, table, id, err)
			w.Header().Set("X-Member-Of-AutoJoin", "failed: "+err.Error())
		}
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
	if full, ok := loadInsertedRowWith(tx, table, idStr); ok {
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
	MaskEncryptedFields(app.Encrypted, table, []map[string]any{resp}, session)
	body, err := json.Marshal(resp)
	if err != nil {
		httpJSON(w, 500, map[string]any{"error": "response encoding failed"})
		return
	}
	if isHTMX(r) {
		body = nil
	}
	if idempotencyKey != "" {
		if _, err := tx.Exec("INSERT INTO _benmore_idempotency (key,user_id,response,status_code,fingerprint) VALUES (?,?,?,?,?)", idempKey, session.UserID, string(body), http.StatusOK, fingerprint); err != nil {
			httpJSON(w, 500, map[string]any{"error": "idempotency save failed"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		httpJSON(w, 500, map[string]any{"error": "commit failed"})
		return
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

	if isHTMX(r) {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
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
	return loadInsertedRowWith(app.DB, table, idStr)
}

func loadInsertedRowWith(db mutationQuerier, table, idStr string) (map[string]any, bool) {
	key := cryptoKeyForQuerier(db)
	q := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table)
	rows, err := db.Query(q, idStr)
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
	DecryptRowFields(out, key)
	return out, true
}
