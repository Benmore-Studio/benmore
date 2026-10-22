//go:build !cli

package main

// Record creation and loading newly inserted rows.

import (
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// requiresUserIDInsert reports whether a table has a NOT NULL user_id
// column - meaning anonymous inserts cannot succeed.
func requiresUserIDInsert(cols []Column) bool {
	for _, c := range cols {
		if identIs(c.Name, "user_id") && c.NotNull {
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

	var jsonBody map[string]any
	// Parse request body: multipart (file uploads), JSON, or form-encoded
	if strings.Contains(r.Header.Get("Content-Type"), "multipart") {
		release, ok := acquireUploadSlot(w, r, uploadClientKey(app, r))
		if !ok {
			return
		}
		defer release()
		err := r.ParseMultipartForm(uploadMemoryThreshold)
		defer removeMultipartTemp(r)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large (set MAX_UPLOAD_BODY_BYTES to accept several large files at once)"})
				return
			}
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed multipart body"})
			return
		}
	} else if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		// JSON body → parse into r.Form so the rest of the handler works uniformly
		var body map[string]any
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&body); err != nil || body == nil {
			httpJSON(w, 400, map[string]any{"error": "expected a JSON object"})
			return
		} else {
			jsonBody = body
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
		serverError(w, r, app, table+" create", err, "Server error")
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

	// The groups membership table takes a tenant admin unless the app
	// declared its own rule (groups_membership_manage.go).
	if writeMembershipManageDenial(w, membershipCreateDenial(app.DB, app, table, session)) {
		return
	}

	// Command-owned columns are never writable through generic CRUD, admin or
	// not. Checked after the scope gate (a scope-less token learns nothing) and
	// before uploads are stored or any row is touched.
	createKeys := mapKeys(r.Form)
	if r.MultipartForm != nil {
		createKeys = append(createKeys, mapKeys(r.MultipartForm.File)...)
	}
	if v := ownedFieldViolation(app, table, createKeys...); v != nil {
		writeOwnedFieldRefusal(w, v)
		return
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

	// Protected fields - never accept from user input. The set covers the
	// owner, tenant key, in-tenant role field and computed columns, and
	// matches names case-insensitively (a column declared USER_ID is still
	// the owner column to the scoping SQL).
	protected := protectedCreateFields(app, table)
	isGroupKey := func(name string) bool { return app.Group != nil && identIs(name, app.Group.Key) }

	// Surface stripped fields via response header. When a client (or
	// agent) submits a protected field, the framework silently swaps
	// the value out for the session-derived one. With no signal back,
	// agents writing tests of `POST /api/notes` with `user_id: 99`
	// can't tell their value was ignored. The header lets curl + the
	// MCP probe_route tool report which fields the framework rejected.
	var stripped []string
	for k := range r.Form {
		if protected.has(k) && !identIs(k, "user_id") && !isGroupKey(k) {
			stripped = append(stripped, k)
		} else if workflowCreateStateRefused(app, table, k, r.FormValue(k)) {
			stripped = append(stripped, k)
		}
	}
	if len(stripped) > 0 {
		w.Header().Set("X-Stripped-Fields", strings.Join(stripped, ","))
	}

	// submitted: the columns written from the request itself, for the
	// before-hooks' {{_submitted}} (not the framework-filled user_id and
	// tenant key).
	var submitted []string
	submittedValues := make(map[string]any) // client-supplied values, for the FK visibility gate
	schemaCols := prismaWriteColumns(app, table)
	for _, col := range cols {
		if col.PK {
			continue // skip auto-increment ID
		}

		// Auto-inject user_id from session, never accept from form
		if identIs(col.Name, "user_id") {
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
		if isGroupKey(col.Name) {
			// Bypass admin (not stepped-in): honor body value.
			if session != nil && session.IsAdminBypass() {
				if v := strings.TrimSpace(r.Form.Get(col.Name)); v != "" {
					fields = append(fields, col.Name)
					placeholders = append(placeholders, "?")
					values = append(values, v)
					submitted = append(submitted, col.Name)
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
		if protected.has(col.Name) {
			continue
		}

		// Validate the original JSON shape, including an explicit null. HTML
		// empty controls retain the existing optional/default omission behavior.
		if declared, ok := schemaCols[col.Name]; ok {
			raw, sent := jsonBody[col.Name]
			if jsonBody == nil {
				_, sent = r.Form[col.Name]
				raw = r.FormValue(col.Name)
			}
			if !sent && declared.NotNull && declared.Default == "" {
				httpJSON(w, 422, map[string]any{"error": col.Name + " is required"})
				return
			}
			if sent && !workflowCreateStateRefused(app, table, col.Name, raw) && (jsonBody != nil || raw != "" || (declared.NotNull && declared.Default == "")) {
				normalized, err := normalizePrismaValue(declared, raw)
				if err != nil {
					httpJSON(w, 422, map[string]any{"error": err.Error()})
					return
				}
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, normalized)
				submitted = append(submitted, col.Name)
				submittedValues[col.Name] = normalized
				continue
			}
		}
		val := r.FormValue(col.Name)
		if val != "" && workflowCreateStateRefused(app, table, col.Name, val) {
			val = "" // a new row starts in the workflow's initial state
		}
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
		if _, sent := r.Form[col.Name]; sent {
			submitted = append(submitted, col.Name)
			submittedValues[col.Name] = val
		}
	}

	if len(fields) == 0 {
		httpError(w, "No fields provided", http.StatusBadRequest)
		return
	}

	tx, err := app.DB.Begin()
	if err != nil {
		serverErrorJSON(w, r, app, table+" create", err, "transaction start failed")
		return
	}
	defer tx.Rollback()
	var idempKey, fingerprint string
	if idempotencyKey != "" {
		idempKey, fingerprint = createIdempotencyIdentity(r, table, session, idempotencyKey)
		if _, err := tx.Exec("DELETE FROM _benmore_idempotency WHERE key=? AND user_id=? AND created_at < datetime('now', '-1 day')", idempKey, session.UserID); err != nil {
			serverErrorJSON(w, r, app, table+" create", err, "idempotency unavailable")
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
			serverErrorJSON(w, r, app, table+" create", err, "idempotency unavailable")
			return
		}
		var legacy bool
		if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM _benmore_idempotency WHERE key=? AND user_id IN (?,0) AND fingerprint='' AND created_at >= datetime('now', '-1 day'))", idempotencyKey, session.UserID).Scan(&legacy); err != nil {
			serverErrorJSON(w, r, app, table+" create", err, "idempotency unavailable")
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
	// A submitted foreign key must name a parent the caller can read;
	// missing and forbidden parents get the same refusal.
	if writeFKTargetDenial(w, foreignKeyTargetDenial(tx, app, table, session, submittedValues)) {
		return
	}

	if err := materializeUUIDDefaults(tx, prismaUUIDDefaultColumns(schemaCols, cols), &fields, &values); err != nil {
		serverErrorJSON(w, r, app, table+" create", err, "could not resolve defaults")
		return
	}
	if err := materializeValidatorDefaults(tx, app.validatorConfig(), table, cols, &fields, &values); err != nil {
		serverErrorJSON(w, r, app, table+" create", err, "could not resolve defaults")
		return
	}
	for len(placeholders) < len(fields) {
		placeholders = append(placeholders, "?")
	}

	// Fire before-hooks (can abort the operation)
	beforeRow := make(map[string]any)
	for i, f := range fields {
		beforeRow[f] = values[i]
	}
	markSubmittedFields(beforeRow, submitted)
	injectSessionContext(beforeRow, session)
	// Cross-field validators (declarative rules from validators.yaml)
	if err := ValidateCrossField(app.validatorConfig(), table, beforeRow); err != nil {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := fireBeforeHooksWith(tx, app, "insert", table, beforeRow); err != nil {
		httpError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	writeFields, writeValues, err := sealNativeCiphertextLiterals(tx, app, table, fields, values)
	if err != nil {
		serverErrorJSON(w, r, app, table+" create", err, "could not seal encrypted input")
		return
	}
	for len(placeholders) < len(writeFields) {
		placeholders = append(placeholders, "?")
	}

	insertSQL := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		quoteIdent(table),
		strings.Join(quoteIdents(writeFields), ", "),
		strings.Join(placeholders, ", "),
	)

	var id any
	err = tx.QueryRow(insertSQL+" RETURNING id", writeValues...).Scan(&id)
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
		if respondStorageFull(w, app, err) || respondDatabaseBusy(w, err) {
			return
		}
		httpError(w, "Insert failed: "+publicConstraintMessage(app, "insert "+table, err), http.StatusBadRequest)
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
	if rule := memberOfFor(app, table, OpRead); rule != nil && session != nil && memberOfAutoJoins(app, table, rule) {
		if err := memberOfAutoJoinWith(tx, app, rule, id, session); err != nil {
			log.Printf("member-of auto-join into %s failed for %s id=%v: %v", rule.Table, table, id, err)
			w.Header().Set("X-Member-Of-AutoJoin", "failed: "+err.Error())
		}
	}

	// JSON response. Pre-2.7.33 we returned just {id, status:"created"} -
	// agents writing `const {room_key} = await bm.api.post('huddles', …)`
	// got undefined and burned debugging time chasing the missing value.
	// A real-time flow tripped on this twice. Now we read the full
	// inserted row back and return it, with the canonical `id` preserved.
	// The legacy `status:"created"` marker is added only for tables without
	// a status column, so it cannot replace an app's value (including NULL).
	// Computed defaults (created_at, updated_at, DEFAULT-clauses) come back too.
	//
	// The read is a single SELECT against the just-written row; cheap
	// even on hot paths. Errors from the read fall back to the legacy
	// shape so a transient query failure can't turn a successful insert
	// into a 500.
	resp := map[string]any{"id": id}
	if !hasColumnInList(cols, "status") {
		resp["status"] = "created"
	}
	if full, ok := loadInsertedRowWith(tx, app, table, idStr); ok {
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
	sanitizeResponseRows(app, table, []map[string]any{resp}, session)
	body, err := json.Marshal(resp)
	if err != nil {
		serverErrorJSON(w, r, app, table+" create", err, "response encoding failed")
		return
	}
	if isHTMX(r) {
		body = nil
	}
	if idempotencyKey != "" {
		if _, err := tx.Exec("INSERT INTO _benmore_idempotency (key,user_id,response,status_code,fingerprint) VALUES (?,?,?,?,?)", idempKey, session.UserID, string(body), http.StatusOK, fingerprint); err != nil {
			if respondStorageFull(w, app, err) {
				return
			}
			serverErrorJSON(w, r, app, table+" create", err, "idempotency save failed")
			return
		}
	}
	row := make(map[string]any)
	for i, f := range fields {
		row[f] = values[i]
	}
	row["id"] = id
	// The audit row commits (or rolls back) with the insert, on the same
	// write lock, instead of a second write after commit that could be lost.
	if err := LogAuditTx(tx, app, "insert", table, idStr, session, nil, row); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverErrorJSON(w, r, app, table+" create", err, "audit write failed")
		return
	}
	if err := tx.Commit(); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverErrorJSON(w, r, app, table+" create", err, "commit failed")
		return
	}
	// Fire insert hooks
	injectSessionContext(row, session)
	FireHooks(app, "insert", table, row)
	FireFlowsForEvent(app, "on_insert", table, row)
	FireWebhookSubscriptions(app, "insert", table, row, session)
	Broadcast(app, table, "insert", session)
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
// gate (the insert already passed the gate). Hidden columns
// (apiHiddenColumn - secrets, tokens, blind indexes) are filtered out
// with the same predicate every read response uses.
func loadInsertedRow(app *App, table, idStr string) (map[string]any, bool) {
	return loadInsertedRowWith(app.DB, app, table, idStr)
}

func loadInsertedRowWith(db mutationQuerier, app *App, table, idStr string) (map[string]any, bool) {
	key := cryptoKeyForQuerier(db)
	q := "SELECT * FROM " + quoteIdent(table) + " WHERE id = ?"
	rows, err := db.Query(q, idStr)
	if err != nil {
		return nil, false
	}
	// Use the canonical decoder so decrypted INTEGER/REAL values retain
	// the same JSON types as GET/list, along with Boolean and nullable dates.
	// scanRowsLimit owns rows.Close and uses this database's encryption key.
	decoded, err := scanRowsLimitHookDecrypt(rows, key, 1, nil, nativeRowDecryptor(app, table))
	if err != nil || len(decoded) != 1 {
		return nil, false
	}
	out := decoded[0]
	for c := range out {
		if apiHiddenColumn(app, table, c) {
			delete(out, c)
		}
	}
	// The caller applies role-based masking after this shared decoding.
	return out, true
}
