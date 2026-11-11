//go:build !cli

package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
)

const frameworkTestUser = "_test_user@benmore.test"

// GenerateFrameworkTests auto-generates test cases based on the app's features.
// Tests are returned as in-memory AppTestFile structs - never written to disk.
func GenerateFrameworkTests(app *App) []AppTestFile {
	var files []AppTestFile
	files = append(files, generatePageTests(app))
	files = append(files, generateCRUDTests(app))
	files = append(files, generateSecurityTests(app))
	files = append(files, generateLifecycleTests(app))
	files = append(files, generateRestoreTests(app))
	files = append(files, generateAuditTests(app))
	files = append(files, generateBatchTests(app))
	files = append(files, generateOwnedFieldTests(app))
	files = append(files, generateDocsTests(app))
	if NeedsAuth(app) {
		files = append(files, generateAuthTests(app))
		files = append(files, generatePasswordChangeTests(app))
	}
	files = append(files, generateSEOTests(app))
	// Search removed - opinionated feature, not a framework concern
	// Export tests removed - export is CLI-only
	files = append(files, generatePerformanceTests(app))
	if IsPWAEnabled(app) {
		files = append(files, generatePWATests(app))
	}
	files = append(files, generateErrorTests(app))
	files = append(files, generateErrorReportingTests(app))
	if app.Workflows != nil && len(app.Workflows.Workflows) > 0 {
		files = append(files, generateWorkflowTests(app))
	}
	if len(app.UUIDTables) > 0 {
		files = append(files, generateUUIDTests(app))
	}
	// SPA tests removed in v2.4.0 - there is no JSX bundle pipeline anymore.

	// Filter out empty files
	var out []AppTestFile
	for _, f := range files {
		if len(f.Tests) > 0 {
			out = append(out, f)
		}
	}
	return out
}

func generatePasswordChangeTests(app *App) AppTestFile {
	return AppTestFile{Name: "_framework_password_change", Tests: map[string]AppTestCase{
		"anonymous_change_denied": {Anon: true, Steps: []AppTestStep{{
			API: "POST " + passwordChangeAPIPath, Expect: AppTestExpect{Status: http.StatusUnauthorized},
		}}},
		"anonymous_form_requires_login": {Anon: true, Steps: []AppTestStep{{
			Get: passwordChangePagePath, Expect: AppTestExpect{Status: http.StatusSeeOther, Redirect: app.Paths.Login},
		}}},
	}}
}

// ===== Page Tests =====

func generatePageTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	for route, page := range app.Pages {
		safeName := strings.ReplaceAll(strings.TrimPrefix(route, "/"), "/", "_")
		if safeName == "" {
			safeName = "index"
		}

		if page.Auth == "required" || page.Require != "" {
			// Anonymous → redirect to login page (discovered path)
			tests["page_"+safeName+"_auth_redirect"] = AppTestCase{
				Anon: true,
				Steps: []AppTestStep{{
					Get:    route,
					Expect: AppTestExpect{Status: 303, Redirect: app.Paths.Login},
				}},
			}

			if page.Require != "" {
				// Page has require="field:value" - test that the framework DENIES
				// access to users who don't have the required attribute.
				// This proves the require gating works.
				tests["page_"+safeName+"_require_denied"] = AppTestCase{
					AsUser: frameworkTestUser,
					Steps: []AppTestStep{{
						Get:    route,
						Expect: AppTestExpect{Status: 403},
					}},
				}
			} else if role := pageRole(page); role != "" && !pageRoleAllowed(app, &Session{Role: "user"}, role) {
				// Generated tests authenticate as an ordinary user; respect page-level
				// role gates instead of mistaking their expected 403 for a page failure.
				tests["page_"+safeName+"_role_denied"] = AppTestCase{
					AsUser: frameworkTestUser,
					Steps: []AppTestStep{{
						Get:    route,
						Expect: AppTestExpect{Status: http.StatusForbidden},
					}},
				}
			} else {
				// Authenticated → renders (no require gate)
				tests["page_"+safeName+"_authenticated"] = AppTestCase{
					AsUser: frameworkTestUser,
					Steps: []AppTestStep{{
						Get: route,
						Expect: AppTestExpect{
							Status:      200,
							NotContains: []string{`class="benmore-error"`},
						},
					}},
				}
			}
		} else {
			// Public → renders
			tests["page_"+safeName+"_public"] = AppTestCase{
				Anon: true,
				Steps: []AppTestStep{{
					Get: route,
					Expect: AppTestExpect{
						Status:      200,
						NotContains: []string{`class="benmore-error"`},
					},
				}},
			}
		}
	}

	return AppTestFile{Name: "_framework_pages", Tests: tests}
}

// ===== CRUD Tests =====

func generateCRUDTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	tables := userTables(app)
	// Access posture of the synthetic framework test user (a plain
	// authenticated user: role "user", no group, no extra role grants). A
	// table its access mode or role scopes refuse gets the declared refusal
	// asserted; elsewhere the generator asserts what it can prove and
	// tolerates denials it can't see (before-hooks, tenancy).
	session := plainGeneratedSession(app)

	for _, table := range tables {
		readDenial := generatedReadDenial(app, table, session)

		// List
		listExpect := AppTestExpect{Status: 200}
		if readDenial.denied() {
			listExpect = readDenial.expect()
		}
		tests["list_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps:  []AppTestStep{{Get: fmt.Sprintf("/api/%s", table), Expect: listExpect}},
		}

		// Create
		tests["create_"+table] = generatedCreateTest(app, table, "_framework_crud/create_"+table, session)

		// Offset pagination
		paginateExpect := AppTestExpect{Status: 200, Contains: []string{`"total"`, `"data"`}}
		if readDenial.denied() {
			paginateExpect = readDenial.expect()
		}
		tests["paginate_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps:  []AppTestStep{{Get: fmt.Sprintf("/api/%s?page=1&per_page=5&sort=id&order=desc", table), Expect: paginateExpect}},
		}

		// Cursor pagination
		cursorExpect := AppTestExpect{Status: 200, Contains: []string{`"next_cursor"`}}
		if readDenial.denied() {
			cursorExpect = readDenial.expect()
		}
		tests["cursor_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps:  []AppTestStep{{Get: fmt.Sprintf("/api/%s?cursor=0&limit=5", table), Expect: cursorExpect}},
		}
	}

	return AppTestFile{Name: "_framework_crud", Tests: tests}
}

// generatedReadDenial is the refusal a list or read of table gets from
// session: a closed read mode (404, like an unmatched route) or role scopes
// that do not grant <table>:read (403).
func generatedReadDenial(app *App, table string, session *Session) generatedDenial {
	if crudReadClosed(app, table) {
		return generatedRouteDenial
	}
	return generatedCRUDDenial(app, table, OpRead, session)
}

// generatedCreateTest is the auto-CRUD create journey for table. A create the
// access mode or role scopes refuse asserts that refusal; otherwise it creates
// any required parent first and asserts success, strictly where the plain
// user can definitely write. A row that can't be built keeps the tolerant
// probe where the write was never guaranteed, and is skipped with the reason
// where success would be asserted.
func generatedCreateTest(app *App, table, key string, session *Session) AppTestCase {
	create := fmt.Sprintf("POST /api/%s", table)
	if denial := generatedCRUDDenial(app, table, OpWrite, session); denial.denied() {
		return AppTestCase{AsUser: frameworkTestUser, Steps: []AppTestStep{{API: create, Data: smartFormData(app, table, tableColumns(app, table)), Expect: denial.expect()}}}
	}
	writeOK := generatedWriteGuaranteed(app, table, session)
	row := planGeneratedRow(app, table, key, session)
	if row.Skip != "" {
		if !writeOK {
			return AppTestCase{AsUser: frameworkTestUser, Steps: []AppTestStep{{API: create, Data: smartFormData(app, table, tableColumns(app, table)), Expect: AppTestExpect{StatusIn: crudWriteAcceptable}}}}
		}
		return AppTestCase{AsUser: frameworkTestUser, Skip: row.Skip}
	}
	expect := AppTestExpect{Status: 200}
	if !writeOK {
		expect = AppTestExpect{StatusIn: crudWriteAcceptable}
	}
	steps := append(row.Steps, AppTestStep{API: create, Data: row.Data, Expect: expect})
	return AppTestCase{AsUser: generatedActor(row, key, ""), Steps: steps}
}

// generatedActor is the identity a journey built on row signs in as: the
// shared framework user, or one of the test's own when the row is limited to
// one per account. role is the identity's role ("" = user).
func generatedActor(row generatedRow, key, role string) string {
	if row.OwnUser {
		return generatedOwnUser(key, role)
	}
	return frameworkTestUser
}

// crudWriteAcceptable is the set of statuses an auto-CRUD create may return
// for the synthetic framework test user when the table is not provably
// writable by a plain authenticated user. It is success (200/201) OR a
// well-formed access-control denial: 401 (unauth), 403 (forbidden / CSRF),
// 404 (the framework's "don't leak existence" posture on access denial),
// 422 (RBAC / before_insert hook abort). 400 and 5xx are deliberately
// excluded so malformed-data and server bugs still fail the test.
var crudWriteAcceptable = []int{200, 201, 401, 403, 404, 422}

// crudReadClosed reports whether the plain synthetic framework user is denied
// at the coarse read gate. The generator must assert the configured 404 for
// admin/role/permission/off modes instead of misreporting secure apps as
// broken. Row-scoped modes reach the list handler and return a scoped or empty
// 200 response for that authenticated user.
func crudReadClosed(app *App, table string) bool {
	if app == nil {
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, OpRead, hasUID, hasGroupKey)
	switch mode {
	case "anon", "everyone", "self", "group":
		return false
	case "off", "admin":
		return true
	}
	if strings.HasPrefix(mode, "role:") || strings.HasPrefix(mode, "perm:") {
		return true
	}
	if strings.HasPrefix(mode, "member-of:") {
		return parseMemberOf(mode) == nil
	}
	if strings.HasPrefix(mode, "owner_or_role:") {
		return strings.TrimSpace(strings.TrimPrefix(mode, "owner_or_role:")) == ""
	}
	return true
}

// crudWriteGuaranteed reports whether the synthetic framework test user can
// DEFINITELY create a row in this table. Only owner/public-writable tables
// its access mode and role scopes admit, with no tenancy gate and no
// before_insert hook, qualify; everything else - group scoping (the
// synthetic user has no group), admin/role/perm/member-of modes, write: off,
// a role whose scopes don't grant <table>:write, or an app before_insert
// hook that may abort - can legitimately deny the write, so a strict 200
// assertion would be a false failure.
func crudWriteGuaranteed(app *App, table string) bool {
	return generatedWriteGuaranteed(app, table, plainGeneratedSession(app))
}

// firstWritableTable returns the first table the synthetic framework test
// user can definitely write, or "" if none.
func firstWritableTable(app *App, tables []string) string {
	for _, t := range tables {
		if crudWriteGuaranteed(app, t) {
			return t
		}
	}
	return ""
}

// firstWritableRow returns the first table the synthetic framework test user
// can definitely write and the planned row for the test named key, for the
// audit/batch/security generators, which need a real successful write.
// needData asks for a row with at least one column of its own; batch asks for
// one that two rows of a single batch can share without colliding.
func firstWritableRow(app *App, tables []string, key string, needData, batch bool) (string, generatedRow) {
	session := plainGeneratedSession(app)
	for _, t := range tables {
		if !generatedWriteGuaranteed(app, t, session) {
			continue
		}
		row := planGeneratedRow(app, t, key, session)
		if row.Skip != "" || (needData && len(row.Data) == 0) || (batch && (!row.Batchable || row.OwnUser)) {
			continue
		}
		return t, row
	}
	return "", generatedRow{}
}

// ===== Security Tests =====

func generateSecurityTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	tables := userTables(app)

	// Anonymous POST rejected (no CSRF, no auth). Prefer a table whose
	// create needs a signed-in caller; otherwise assert the gate the first
	// table declares (an access rule that removes the route, or the CSRF
	// check of an anonymous-write table). An app without tables has no
	// auto-CRUD route to probe.
	if len(tables) > 0 {
		target, anonExpect := tables[0], generatedAnonCreateExpect(app, tables[0])
		for _, t := range tables {
			if e := generatedAnonCreateExpect(app, t); e.Status == http.StatusUnauthorized {
				target, anonExpect = t, e
				break
			}
		}
		tests["csrf_auth_rejection"] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				API:    fmt.Sprintf("POST /api/%s", target),
				Data:   map[string]any{"name": "hacker"},
				Expect: anonExpect,
			}},
		}
	}

	// Bearer auth skips CSRF (the CSRF skip is auth-type based, not role
	// based). Prefer a table the synthetic user can definitely write so a
	// clean 200 proves the bypass; otherwise accept success or an
	// access-control denial that is NOT a CSRF rejection. A CSRF failure
	// surfaces as 403 "Invalid CSRF token", so excluding 403 keeps the
	// test's teeth unless a refusal is predicted (generatedCRUDDenial): an
	// access rule on an unreadable table answers 404, on a readable one 403
	// "access rules do not let you", and a role-scope refusal 403 "scope
	// denied"; all are checked after CSRF, so asserting them still proves the
	// bypass.
	if bearerTable, row := firstWritableRow(app, tables, "_framework_security/bearer_skips_csrf", false, false); bearerTable != "" {
		tests["bearer_skips_csrf"] = AppTestCase{
			AsUser: generatedActor(row, "_framework_security/bearer_skips_csrf", ""),
			Steps: append(row.Steps, AppTestStep{
				API:    fmt.Sprintf("POST /api/%s", bearerTable),
				Data:   row.Data,
				Bearer: true,
				Expect: AppTestExpect{Status: 200},
			}),
		}
	} else if len(tables) > 0 {
		bearerTable := tables[0]
		bearerExpect := AppTestExpect{StatusIn: []int{200, 201, 401, 404, 422}}
		if denial := generatedCRUDDenial(app, bearerTable, OpWrite, plainGeneratedSession(app)); denial.denied() {
			bearerExpect = denial.expect()
		} else if membershipManageGated(app, bearerTable, OpWrite) {
			// The groups membership table answers a non-admin's create with 403
			// (managing members takes a tenant admin); a CSRF rejection is told
			// apart by its text instead.
			bearerExpect = AppTestExpect{StatusIn: crudWriteAcceptable, NotContains: []string{"Invalid CSRF token"}}
		}
		tests["bearer_skips_csrf"] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps: []AppTestStep{{
				API:    fmt.Sprintf("POST /api/%s", bearerTable),
				Data:   smartFormData(app, bearerTable, tableColumns(app, bearerTable)),
				Bearer: true,
				Expect: bearerExpect,
			}},
		}
	}

	// Security headers (check on a public endpoint). Probe a route
	// that's guaranteed public regardless of mode - /health works for
	// both gotmpl and SPA apps. Previously hit /login which only
	// exists in gotmpl mode and 404s in SPA mode.
	tests["security_headers_csp"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get: "/health",
			Expect: AppTestExpect{
				Status: 200,
			},
		}},
	}

	tests["security_headers_xfo"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get: "/health",
			Expect: AppTestExpect{
				Status:  200,
				Headers: map[string]string{"X-Content-Type-Options": "nosniff"},
			},
		}},
	}

	// Admin requires auth. The current framework emits 307 (temporary
	// redirect, preserves method) for legacy /admin → /_admin; for
	// anonymous GETs that's equivalent to a 303. Accept either by
	// pointing at /_admin directly, which 303-redirects to /login.
	//
	// With the panel switched off nothing of the framework's answers there:
	// the router's 404, or the app's own page when one claims the path (an
	// HTML app's index fallback answers 200, where the panel would redirect).
	adminExpect := AppTestExpect{Status: http.StatusSeeOther}
	adminSkip := ""
	if !app.FeatureEnabled("admin") {
		adminExpect = AppTestExpect{Status: http.StatusNotFound}
		if expect, skip, owned := appOwnedPageExpect(app, "/_admin", false); owned {
			adminExpect, adminSkip = expect, skip
		}
	}
	tests["admin_requires_auth"] = AppTestCase{
		Anon: true,
		Skip: adminSkip,
		Steps: []AppTestStep{{
			Get:    "/_admin",
			Expect: adminExpect,
		}},
	}

	return AppTestFile{Name: "_framework_security", Tests: tests}
}

// ===== CRUD Lifecycle Tests =====

func generateLifecycleTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	tables := userTables(app)
	session := plainGeneratedSession(app)

	for _, table := range tables {
		if !hasColumn(app, table, "deleted_at") {
			continue
		}
		// The journey creates a row and reads the list back: a table whose
		// access mode or role scopes refuse either has its refusal asserted
		// by the CRUD tests instead.
		if generatedCRUDDenial(app, table, OpWrite, session).denied() || generatedReadDenial(app, table, session).denied() {
			continue
		}
		key := "_framework_lifecycle/lifecycle_" + table
		row := planGeneratedRow(app, table, key, session)
		if row.Skip != "" {
			tests["lifecycle_"+table] = AppTestCase{AsUser: frameworkTestUser, Skip: row.Skip}
			continue
		}

		cols := tableColumns(app, table)
		data := row.Data
		literal := func(col Column) bool {
			v, ok := data[col.Name].(string)
			return ok && !strings.HasPrefix(v, "{{") && encryptedDefFor(app, table, col.Name) == nil
		}

		// Find a text column to use as identifier for read assertions: one
		// the create sets in plaintext (an encrypted column is stored as
		// ciphertext), preferring one whose value can be this test's own.
		identCol := ""
		identVal := ""
		ownValue := false
		for _, pass := range []bool{true, false} {
			for _, col := range cols {
				if identCol != "" || col.PK || col.Name == "user_id" || col.Name == "created_at" || col.Name == "updated_at" || col.Name == "deleted_at" || !literal(col) {
					continue
				}
				if !(strings.Contains(strings.ToUpper(col.Type), "TEXT") || col.Type == "") || (pass && generatedEnumLikeColumn(col.Name)) {
					continue
				}
				identCol = col.Name
				if v, ok := generatedUniqueValue(col, key+"#ident"); ok && pass {
					data[col.Name] = v
					ownValue = true
				}
				identVal = fmt.Sprintf("%v", data[col.Name])
			}
		}
		if identCol == "" {
			continue
		}

		// Multi-step lifecycle: create → read → update → read → delete → read-after-delete
		updateCol := ""
		for _, col := range cols {
			if col.Name != identCol && col.Name != "user_id" && col.Name != "created_at" && col.Name != "updated_at" && col.Name != "deleted_at" && !col.PK && literal(col) && !strings.HasSuffix(col.Name, "_id") {
				updateCol = col.Name
				break
			}
		}
		// The steps below name the table and these columns in SQL. From here
		// the three hold the names as SQL writes them (quoted), so one named
		// like an SQL keyword (`order`, `from`) is still a name; routes and
		// test names use route.
		route := table
		table := quoteIdent(table)
		identCol = quoteIdent(identCol)
		if updateCol != "" {
			updateCol = quoteIdent(updateCol)
		}

		steps := append(row.Steps,
			// Step 1: Create
			AppTestStep{
				API:  fmt.Sprintf("POST /api/%s", route),
				Data: data,
				Expect: AppTestExpect{
					Status:   200,
					Contains: []string{`"id"`},
				},
			},
			// Step 2: Verify via SQL (since we don't have the ID in JSON path yet)
			AppTestStep{
				SQL:    fmt.Sprintf("SELECT * FROM %s WHERE %s = '%s' AND deleted_at IS NULL", table, identCol, identVal),
				Expect: AppTestExpect{Rows: expectRows(1)},
			},
		)

		if updateCol != "" {
			// Step 3: Update via SQL (since we need the ID)
			steps = append(steps, AppTestStep{
				SQL: fmt.Sprintf("UPDATE %s SET %s = 'lifecycle_updated' WHERE %s = '%s'", table, updateCol, identCol, identVal),
			})
			// Step 4: Verify update
			steps = append(steps, AppTestStep{
				SQL:    fmt.Sprintf("SELECT * FROM %s WHERE %s = '%s' AND %s = 'lifecycle_updated'", table, identCol, identVal, updateCol),
				Expect: AppTestExpect{Rows: expectRows(1)},
			})
		}

		// Step 5: Soft delete via SQL
		steps = append(steps, AppTestStep{
			SQL: fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE %s = '%s'", table, identCol, identVal),
		})
		// Step 6: Verify soft-deleted row is filtered from API reads
		steps = append(steps, AppTestStep{
			Get: fmt.Sprintf("/api/%s", route),
			Expect: AppTestExpect{
				Status:      200,
				NotContains: []string{identVal},
			},
		})

		// A value of the test's own needs no cleanup; a shared one is cleared
		// first so another test's row cannot satisfy or spoil the checks.
		var setup []AppTestSetup
		if !ownValue {
			setup = []AppTestSetup{{SQL: fmt.Sprintf("DELETE FROM %s WHERE %s = '%s'", table, identCol, identVal)}}
		}
		tests["lifecycle_"+route] = AppTestCase{
			AsUser: generatedActor(row, key, ""),
			Setup:  setup,
			Steps:  steps,
		}
	}

	return AppTestFile{Name: "_framework_lifecycle", Tests: tests}
}

// ===== Audit Tests =====

func generateAuditTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	tables := userTables(app)

	// Pick a table the synthetic test user can actually write - otherwise the
	// create is access-denied (groups / RBAC / before-hook) and the audit-row
	// assertion can't run. Skip the suite entirely when no such table exists.
	const key = "_framework_audit/audit_trail_logged"
	table, row := firstWritableRow(app, tables, key, true, false)
	if table == "" {
		return AppTestFile{Name: "_framework_audit", Tests: tests}
	}

	// Create a record, then verify the audit log captured it
	tests["audit_trail_logged"] = AppTestCase{
		AsUser: generatedActor(row, key, ""),
		Setup: []AppTestSetup{
			{SQL: fmt.Sprintf("DELETE FROM _benmore_audit_log WHERE table_name = '%s'", table)},
		},
		Steps: append(row.Steps,
			AppTestStep{
				API:    fmt.Sprintf("POST /api/%s", table),
				Data:   row.Data,
				Expect: AppTestExpect{Status: 200},
			},
			AppTestStep{
				SQL:    fmt.Sprintf("SELECT * FROM _benmore_audit_log WHERE table_name = '%s' AND action = 'insert'", table),
				Expect: AppTestExpect{Rows: expectRows(1)},
			},
		),
	}

	return AppTestFile{Name: "_framework_audit", Tests: tests}
}

// ===== Batch Tests =====

func generateBatchTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	tables := userTables(app)

	if len(tables) == 0 {
		return AppTestFile{Name: "_framework_batch", Tests: tests}
	}

	// Pick a table the synthetic test user can actually write; the batch test
	// asserts a successful 2-row create, so an access-gated table can't run
	// it, and neither can one whose unique indexes two rows would share.
	const key = "_framework_batch/batch_create"
	table, row := firstWritableRow(app, tables, key, false, true)
	if table == "" {
		return AppTestFile{Name: "_framework_batch", Tests: tests}
	}
	cols := tableColumns(app, table)

	// Build two JSON records, each with unique columns of its own
	rec1 := row.Variant(key + "#1")
	rec2 := row.Variant(key + "#2")
	// Differentiate them slightly
	for _, col := range cols {
		if _, set := rec1[col.Name]; set && (col.Name == "name" || strings.HasSuffix(col.Name, "_name")) && !row.varies(col.Name) {
			rec1[col.Name] = "Batch One"
			rec2[col.Name] = "Batch Two"
			break
		}
	}

	tests["batch_create_"+table] = AppTestCase{
		AsUser: frameworkTestUser,
		Steps: append(row.Steps, AppTestStep{
			API:       fmt.Sprintf("POST /api/%s/batch", table),
			JSONArray: []any{rec1, rec2},
			Bearer:    true,
			Expect:    AppTestExpect{Status: 200, Contains: []string{`"count":2`}},
		}),
	}

	return AppTestFile{Name: "_framework_batch", Tests: tests}
}

// generateOwnedFieldTests asserts that generic CRUD refuses every column a
// command owns (`command.owns`), for a table the synthetic user can write.
func generateOwnedFieldTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	app.mu.RLock()
	flows := app.Flows
	app.mu.RUnlock()
	for _, flow := range flows {
		if flow.Command == nil {
			continue
		}
		for _, own := range flow.Command.Owns {
			if firstWritableTable(app, []string{own.Table}) == "" {
				continue
			}
			tests["owned_field_"+own.Table+"_"+own.Column+"_refused"] = AppTestCase{
				AsUser: frameworkTestUser,
				Steps: []AppTestStep{{
					API:    fmt.Sprintf("POST /api/%s", own.Table),
					JSON:   map[string]any{own.Column: "framework-test"},
					Bearer: true,
					Expect: AppTestExpect{Status: http.StatusForbidden, Contains: []string{"field_owned_by_command"}},
				}},
			}
		}
	}
	return AppTestFile{Name: "_framework_owned_fields", Tests: tests}
}

// ===== Docs Tests =====

func generateDocsTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	status := http.StatusOK
	if !app.FeatureEnabled("docs") {
		status = http.StatusNotFound
	}

	tests["api_docs_json"] = AppTestCase{
		AsUser: frameworkTestUser,
		Steps: []AppTestStep{{
			Get:    "/api/_docs",
			Expect: AppTestExpect{Status: status, Contains: docsTestContains(status, `"endpoints"`)},
		}},
	}

	if _, appOwnsDocs := app.Pages["/docs"]; !appOwnsDocs {
		htmlExpect := AppTestExpect{Status: status, Contains: docsTestContains(status, "API Documentation", "Copy for LLM")}
		markdownExpect := AppTestExpect{
			Status:   status,
			Contains: docsTestContains(status, "# API Documentation", "## Authentication", "## Platform features"),
		}
		skip := ""
		if status == http.StatusNotFound {
			// With the framework docs off, the app's own page may answer
			// /docs (an HTML app's index fallback). It must not be the
			// framework's docs.
			if expect, why, owned := appOwnedPageExpect(app, "/docs", true); owned {
				skip = why
				htmlExpect, markdownExpect = expect, expect
				htmlExpect.NotContains = []string{"Copy for LLM"}
				markdownExpect.NotContains = []string{"## Platform features"}
			}
		}
		tests["api_docs_html"] = AppTestCase{
			AsUser: frameworkTestUser,
			Skip:   skip,
			Steps: []AppTestStep{{
				Get:    "/docs",
				Expect: htmlExpect,
			}},
		}

		// Markdown export (Copy-for-LLM): non-empty and carries the top-level
		// section headings drawn from the same docs model.
		tests["api_docs_markdown"] = AppTestCase{
			AsUser: frameworkTestUser,
			Skip:   skip,
			Steps: []AppTestStep{{
				Get:    "/docs?format=md",
				Expect: markdownExpect,
			}},
		}
	}

	return AppTestFile{Name: "_framework_docs", Tests: tests}
}

func docsTestContains(status int, values ...string) []string {
	if status != http.StatusOK {
		return nil
	}
	return values
}

// ===== Auth Tests =====

func generateAuthTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	// Auth-page GET tests apply when the app SHIPS a gotmpl page for
	// each auth surface. SPA apps own login/signup inside their React
	// bundle and don't expose a separate /login.html - for those, we
	// instead verify the POST endpoint accepts requests (CSRF gate
	// returns 303 on missing token, anything other than 404 is fine).
	if pageExists(app, app.Paths.Login) {
		tests["login_page"] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				Get:    app.Paths.Login,
				Expect: AppTestExpect{Status: 200},
			}},
		}
	} else {
		// SPA mode: POST /login exists, GET does not. Verify the POST
		// handler registered by hitting it without CSRF - should
		// redirect (303 to ?error=) rather than 404.
		tests["login_post_registered"] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				API:    "POST " + app.Paths.Login,
				Expect: AppTestExpect{Status: 303},
			}},
		}
	}

	if pageExists(app, app.Paths.Signup) {
		tests["signup_page"] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				Get:    app.Paths.Signup,
				Expect: AppTestExpect{Status: 200},
			}},
		}
	} else {
		signupExpect := AppTestExpect{Status: http.StatusSeeOther}
		if authFeatureDisabled(app, "signup") {
			signupExpect = AppTestExpect{Status: http.StatusNotFound}
		}
		tests["signup_post_registered"] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				API:    "POST " + app.Paths.Signup,
				Expect: signupExpect,
			}},
		}
	}

	if pageExists(app, app.Paths.ForgotPassword) {
		tests["forgot_password_page"] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				Get:    app.Paths.ForgotPassword,
				Expect: AppTestExpect{Status: 200},
			}},
		}
	}

	// Token endpoint: create a user first, then test the token exchange.
	// The checks follow the handler's order. A social-only app refuses every
	// password exchange; an email-domain rule refuses an address outside it,
	// so the exchange is proven with an identity inside the first allowed
	// domain and the refusal is asserted for the shared test address; an app
	// that requires the emailed sign-in code refuses the password exchange
	// (it would skip the code) and says so. A username or phone sign-in app
	// gets that identifier set on the test identity first.
	tokenUser := frameworkTestUser
	tokenExpect := AppTestExpect{Status: 200, Contains: []string{`"token"`}}
	var tokenSetup []AppTestSetup
	login := frameworkTestUser
	switch authIdentifier(app) {
	case "phone":
		login = "+15550100199"
		tokenSetup = []AppTestSetup{{SQL: "UPDATE _benmore_users SET phone = '" + login + "' WHERE id = {{user_id}}"}}
	case "username":
		login = "_fw_token_user"
		tokenSetup = []AppTestSetup{{SQL: "UPDATE _benmore_users SET username = '" + login + "' WHERE id = {{user_id}}"}}
	}
	if authFeatureDisabled(app, "api_tokens") {
		tokenExpect = AppTestExpect{Status: http.StatusNotFound}
	} else if oauthOnly(app) {
		tokenExpect = AppTestExpect{Status: http.StatusForbidden, Contains: []string{"password auth is disabled"}}
	} else if allowed, reason := emailAllowedForApp(app, frameworkTestUser); authIdentifier(app) == "email" && !allowed {
		domain := ""
		if app.Design != nil {
			for _, d := range strings.Split(app.Design.Auth["domain"], ",") {
				if d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "@"))); d != "" {
					domain = d
					break
				}
			}
		}
		if domain == "" {
			tokenExpect = AppTestExpect{Status: http.StatusForbidden, Contains: []string{reason}}
		} else {
			tests["token_endpoint_email_gate"] = AppTestCase{
				AsUser: frameworkTestUser,
				Steps: []AppTestStep{{
					API:    "POST /api/_auth/token",
					JSON:   map[string]any{"email": frameworkTestUser, "password": "testpass123"},
					Expect: AppTestExpect{Status: http.StatusForbidden, Contains: []string{reason}},
				}},
			}
			tokenUser = "_test_user@" + domain
			login = tokenUser
			if otpLoginEnabled(app) {
				tokenExpect = AppTestExpect{Status: 403, Contains: []string{"otp_required"}}
			} else if roleRequiresMFAEnrollment(app, "user") {
				tokenExpect = AppTestExpect{Status: 403, Contains: []string{"mfa_required"}}
			}
		}
	} else if otpLoginEnabled(app) {
		tokenExpect = AppTestExpect{Status: 403, Contains: []string{"otp_required"}}
	} else if roleRequiresMFAEnrollment(app, "user") {
		// loginTestUser gives a user of a listed role a TOTP factor nobody
		// knows, so the password exchange asks for the code.
		tokenExpect = AppTestExpect{Status: 403, Contains: []string{"mfa_required"}}
	}
	tests["token_endpoint"] = AppTestCase{
		AsUser: tokenUser,
		Setup:  tokenSetup,
		Steps: []AppTestStep{{
			API:    "POST /api/_auth/token",
			JSON:   map[string]any{"email": login, "password": "testpass123"},
			Expect: tokenExpect,
		}},
	}

	return AppTestFile{Name: "_framework_auth", Tests: tests}
}

// ===== SEO Tests =====

func generateSEOTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	seoEndpoints := []struct{ path, contains, name string }{
		{"/sitemap.xml", "<urlset", "sitemap"},
		{"/robots.txt", "User-agent", "robots"},
		{"/llms.txt", "# ", "llms_txt"},
		{"/feed.xml", "<feed", "feed"},
		{"/.well-known/security.txt", "Contact:", "security_txt"},
	}

	for _, ep := range seoEndpoints {
		expect := AppTestExpect{Status: 200, Contains: []string{ep.contains}}
		switch ep.name {
		case "sitemap":
			// An app's own static/sitemap.xml is served verbatim; it may be a
			// sitemap index, so assert the protocol namespace both forms declare.
			if _, err := app.readSourceFile("static/sitemap.xml"); err == nil {
				expect.Contains = []string{"sitemaps.org/schemas/sitemap"}
			}
		case "llms_txt":
			// `features.docs: auth` keeps the LLM discovery file behind sign-in.
			if app.Design != nil && app.Design.Features != nil && app.Design.Features.DocsRequireAuth() {
				expect = AppTestExpect{Status: http.StatusUnauthorized}
			}
		case "feed":
			expect.Contains = []string{ep.contains, "<updated>", "<author>"}
		case "security_txt":
			// RFC 9116 needs Contact and Expires: generated only from
			// seo.security_contact, else the app's own file, else 404.
			if _, err := app.readIncludeSource("static", ".well-known/security.txt"); err == nil {
				break
			}
			if securityTxtContact(app) == "" {
				expect = AppTestExpect{Status: http.StatusNotFound}
			} else {
				expect.Contains = []string{ep.contains, "Expires:"}
			}
		}
		tests["seo_"+ep.name] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				Get:    ep.path,
				Expect: expect,
			}},
		}
	}

	return AppTestFile{Name: "_framework_seo", Tests: tests}
}

// ===== Search Tests =====

// Search removed - opinionated feature, developer builds their own if needed.
// Export tests removed - export is CLI-only, not HTTP.

// ===== Performance Tests =====

// healthFastAttempts is how many times health_fast asks for /health before it
// reports the endpoint as slow.
const healthFastAttempts = 5

func generatePerformanceTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	// /health must stay cheap: 10 ms. The bound is on the fastest of a few
	// requests (AppTestStep.DurationAttempts), because one request's wall
	// clock also holds the machine's load at that moment (a race-detector
	// build, other apps' tests, a compile): a single measurement failed
	// correct apps there. A /health that is slow is slow every time.
	tests["health_fast"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get: "/health",
			Expect: AppTestExpect{
				Status:      200,
				MaxDuration: "10ms",
			},
			DurationAttempts: healthFastAttempts,
		}},
	}

	return AppTestFile{Name: "_framework_performance", Tests: tests}
}

// ===== PWA Tests =====

func generatePWATests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	tests["pwa_manifest"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get:    "/manifest.json",
			Expect: AppTestExpect{Status: 200},
		}},
	}

	tests["pwa_service_worker"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get:    "/sw.js",
			Expect: AppTestExpect{Status: 200},
		}},
	}

	tests["pwa_registration_script"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get:    pwaRegisterPath,
			Expect: AppTestExpect{Status: 200, Contains: "serviceWorker.register('/sw.js')"},
		}},
	}

	// The worker stores this page for whoever is offline on the device, so
	// it must not carry a CSRF token.
	tests["pwa_offline_page"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get:    pwaOfflinePath,
			Expect: AppTestExpect{Status: 200, NotContains: "csrf-token"},
		}},
	}

	return AppTestFile{Name: "_framework_pwa", Tests: tests}
}

// ===== Error Handling Tests =====

func generateErrorTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	// Probe an asset-looking path so the test exercises the real 404 branch.
	// Non-asset routes intentionally fall back to static/index.html (SPA-style)
	// when the HTML scaffold is in use, so /nonexistent-route would 200.
	tests["unknown_route_404"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get:    "/nonexistent-route-xyz.css",
			Expect: AppTestExpect{Status: 404},
		}},
	}

	return AppTestFile{Name: "_framework_errors", Tests: tests}
}

// ===== Helpers =====

func generateErrorReportingTests(app *App) AppTestFile {
	fakeProviderKey := "sk_live_" + strings.Repeat("0", 24)
	return AppTestFile{Name: "_framework_error_reporting", Tests: map[string]AppTestCase{
		"anonymous_capture_is_grouped_and_scrubbed": {Anon: true, Steps: []AppTestStep{
			{Post: "/api/_errors", JSON: map[string]any{"kind": "error", "message": "framework-error-reporting-probe " + fakeProviderKey}, Expect: AppTestExpect{Status: 204}},
			{Flush: "errors"},
			{SQL: `SELECT group_key FROM _benmore_error_groups WHERE source='client' AND message LIKE 'framework-error-reporting-probe%' AND message NOT LIKE '%sk_live_%' AND sample NOT LIKE '%sk_live_%'`, Expect: AppTestExpect{Rows: expectRows(1)}},
		}},
	}}
}

// userTables returns non-framework table names.
func userTables(app *App) []string {
	tables, err := GetTableNames(app.DB)
	if err != nil {
		return nil
	}
	var out []string
	for _, t := range tables {
		if !strings.HasPrefix(t, "_benmore_") {
			out = append(out, t)
		}
	}
	return out
}

// tableColumns returns columns for a table, excluding framework internals.
func tableColumns(app *App, table string) []Column {
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		return nil
	}
	return cols
}

// smartFormData builds form data from columns using smartTestValue.
// Skips auto-managed fields and actual foreign keys, whose parent fixtures must
// be supplied explicitly. A required scalar ending in _id is not itself an FK.
func smartFormData(app *App, table string, cols []Column) map[string]any {
	data := make(map[string]any)
	// Physical FKs also matter when the generator is used before JoinMap was
	// populated. Metadata inspection only: never assume an existing parent ID.
	if app == nil || app.DB == nil {
		return data
	}
	declared, err := GetForeignKeys(app.DB, table)
	if err != nil {
		// Unknown relationship metadata is not evidence that a column is an
		// ordinary scalar. Keep the prerequisite failure visible in the test.
		return data
	}
	refs := foreignKeyRefs(app, table)
	for name, ref := range declared {
		refs[name] = ref
	}
	for _, col := range cols {
		if col.PK || col.Name == "created_at" || col.Name == "updated_at" || col.Name == "deleted_at" {
			continue
		}
		if col.Name == "user_id" || (strings.HasSuffix(col.Name, "_id") && (!col.NotNull || col.Default != "")) {
			continue
		}
		foreign := false
		for name := range refs {
			if identIs(name, col.Name) {
				foreign = true
				break
			}
		}
		if foreign {
			continue
		}
		data[col.Name] = smartTestValue(col)
	}
	return data
}

// ===== UUID Tests =====

func generateUUIDTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	session := plainGeneratedSession(app)
	for table := range app.UUIDTables {
		if strings.HasPrefix(table, "_benmore_") {
			continue
		}
		// A table whose access mode or role scopes refuse the create has that
		// refusal asserted by create_<table>; these journeys need a row.
		if generatedCRUDDenial(app, table, OpWrite, session).denied() {
			continue
		}
		cols := tableColumns(app, table)
		// Each later step asserts what the app declares for the operation:
		// success, or the refusal of a closed mode or missing role scope.
		stepExpect := func(op AccessOp, success AppTestExpect) AppTestExpect {
			denial := generatedCRUDDenial(app, table, op, session)
			if op == OpRead {
				denial = generatedReadDenial(app, table, session)
			}
			if denial.denied() {
				return denial.expect()
			}
			return success
		}

		// UUID create: verify response ID is a string (not an integer).
		// A real status column owns that response field; only legacy tables
		// without it receive the operation marker.
		createContains := []string{`"id":"`}
		if !hasColumnInList(cols, "status") {
			createContains = append(createContains, `"status":"created"`)
		}
		createKey := "_framework_uuid/uuid_create_" + table
		row := planGeneratedRow(app, table, createKey, session)
		if row.Skip != "" {
			tests["uuid_create_"+table] = AppTestCase{AsUser: frameworkTestUser, Skip: row.Skip}
		} else {
			tests["uuid_create_"+table] = AppTestCase{
				AsUser: generatedActor(row, createKey, ""),
				Steps: append(row.Steps,
					AppTestStep{
						API:    fmt.Sprintf("POST /api/%s", table),
						Data:   row.Data,
						Bearer: true,
						Save:   map[string]string{"new_id": "id"},
						Expect: AppTestExpect{
							Status:   200,
							Contains: createContains,
						},
					},
					// Verify the UUID row is readable via GET
					AppTestStep{
						Get:    fmt.Sprintf("/api/%s/{{new_id}}", table),
						Expect: stepExpect(OpRead, AppTestExpect{Status: 200, Contains: []string{`"id":"`}}),
					},
				),
			}
		}

		// Like ordinary batch tests, a UUID batch success probe requires a
		// table the synthetic framework user is guaranteed to write, with
		// rows that do not share a unique value.
		batchKey := "_framework_uuid/uuid_batch_" + table
		if batch := planGeneratedRow(app, table, batchKey, session); batch.Skip == "" && len(batch.Data) > 0 && batch.Batchable && !batch.OwnUser && crudWriteGuaranteed(app, table) {
			tests["uuid_batch_"+table] = AppTestCase{
				AsUser: frameworkTestUser,
				Steps: append(batch.Steps, AppTestStep{
					API:       fmt.Sprintf("POST /api/%s/batch", table),
					JSONArray: []any{batch.Variant(batchKey + "#1"), batch.Variant(batchKey + "#2")},
					Bearer:    true,
					Expect: AppTestExpect{
						Status:   200,
						Contains: []string{`"ids"`, `"count":2`},
					},
				}),
			}
		}

		// UUID lifecycle: create → update → delete
		lifeKey := "_framework_uuid/uuid_lifecycle_" + table
		life := planGeneratedRow(app, table, lifeKey, session)
		if life.Skip != "" {
			tests["uuid_lifecycle_"+table] = AppTestCase{AsUser: frameworkTestUser, Skip: life.Skip}
			continue
		}
		// Use a schema-compatible value for the first editable scalar the
		// create itself sets (never a reference, unique or command-owned
		// column).
		updateData := make(map[string]any)
		for _, col := range cols {
			if col.PK || col.Name == "created_at" || col.Name == "updated_at" || col.Name == "deleted_at" || col.Name == "user_id" || strings.HasSuffix(col.Name, "_id") {
				continue
			}
			if v, set := life.Data[col.Name].(string); !set || strings.HasPrefix(v, "{{") || life.varies(col.Name) {
				continue
			}
			updateData[col.Name] = smartTestUpdateValue(col)
			break
		}
		if len(updateData) > 0 {
			tests["uuid_lifecycle_"+table] = AppTestCase{
				AsUser: generatedActor(life, lifeKey, ""),
				Steps: append(life.Steps,
					AppTestStep{
						API:    fmt.Sprintf("POST /api/%s", table),
						Data:   life.Data,
						Bearer: true,
						Save:   map[string]string{"uuid_id": "id"},
						Expect: AppTestExpect{
							Status: 200,
						},
					},
					AppTestStep{
						API:    fmt.Sprintf("PATCH /api/%s/{{uuid_id}}", table),
						Data:   updateData,
						Bearer: true,
						Expect: stepExpect(OpUpdate, AppTestExpect{Status: 200}),
					},
					AppTestStep{
						API:    fmt.Sprintf("DELETE /api/%s/{{uuid_id}}", table),
						Bearer: true,
						Expect: stepExpect(OpDelete, AppTestExpect{Status: 200}),
					},
				),
			}
		}
	}

	return AppTestFile{Name: "_framework_uuid", Tests: tests}
}

// ===== Workflow Tests =====

func generateWorkflowTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	for name, wf := range app.Workflows.Workflows {
		// A map's first target is not stable, and a conditional transition
		// needs app-specific fixture data that introspection cannot invent.
		targets := wf.Transitions[wf.Initial]
		var targetNames []string
		for to := range targets {
			targetNames = append(targetNames, to)
		}
		sort.Strings(targetNames)
		if len(targetNames) == 0 {
			continue
		}
		firstTarget := targetNames[0]
		var validTarget string
		for _, to := range targetNames {
			if targets[to].When == "" {
				validTarget = to
				break
			}
		}

		prefix := "wf_" + name + "_"
		table := wf.Table
		initial := wf.Initial
		field := wf.Field

		// journey creates a row in the initial state (and any required parent
		// first), then runs then. ok=false when the actor's access mode or
		// role scopes refuse the create, which the CRUD tests assert; a row
		// that can't be built is a skipped case with the reason.
		journey := func(key, user, asRole string, then AppTestStep) (AppTestCase, bool) {
			actor := generatedTestSession(app, user, asRole)
			if generatedCRUDDenial(app, table, OpWrite, actor).denied() {
				return AppTestCase{}, false
			}
			row := planGeneratedRow(app, table, key, actor)
			if row.Skip != "" {
				return AppTestCase{AsUser: user, AsRole: asRole, Skip: row.Skip}, true
			}
			// Force the initial state
			row.Data[field] = initial
			if row.OwnUser {
				user = generatedOwnUser(key, asRole)
			}
			return AppTestCase{
				AsUser: user,
				AsRole: asRole,
				Steps: append(row.Steps,
					AppTestStep{
						API:    fmt.Sprintf("POST /api/%s", table),
						Data:   row.Data,
						Save:   map[string]string{"entity_id": "id"},
						Expect: AppTestExpect{Status: 200},
					},
					then,
				),
			}, true
		}

		// Test: an unconditional transition succeeds with its declared role.
		// loginTestUser assigns a role only when first creating an identity;
		// never grant a role through the shared ordinary framework test user.
		// A role list is any-of: the ordinary user passes when it holds any
		// listed role, else a synthetic user holds the first one. A role:
		// naming no role admits only an admin, and no generated test is one.
		roles := workflowRoleNames(targets[validTarget].Role)
		if validTarget != "" && (len(roles) > 0 || targets[validTarget].Role == "") {
			user := frameworkTestUser
			asRole := ""
			if len(roles) > 0 && !slices.ContainsFunc(roles, func(role string) bool { return hasRole("user", role) }) {
				digest := sha256.Sum256([]byte(roles[0]))
				user = fmt.Sprintf("_test_workflow_%x@benmore.test", digest[:12])
				asRole = roles[0]
			}
			if tc, ok := journey("_framework_workflows/"+prefix+"valid_transition", user, asRole, AppTestStep{
				API:    fmt.Sprintf("POST /api/%s/{{entity_id}}/transition", table),
				JSON:   map[string]any{"to": validTarget},
				Bearer: true,
				Expect: AppTestExpect{
					Status:   200,
					Contains: []string{`"transitioned"`},
				},
			}); ok {
				tests[prefix+"valid_transition"] = tc
			}
		}

		// Test: invalid transition returns 409
		invalidTarget := ""
		for _, s := range wf.States {
			if _, ok := targets[s]; !ok && s != wf.Initial {
				invalidTarget = s
				break
			}
		}
		if invalidTarget != "" {
			if tc, ok := journey("_framework_workflows/"+prefix+"invalid_transition", frameworkTestUser, "", AppTestStep{
				API:    fmt.Sprintf("POST /api/%s/{{entity_id}}/transition", table),
				JSON:   map[string]any{"to": invalidTarget},
				Bearer: true,
				Expect: AppTestExpect{Status: 409},
			}); ok {
				tests[prefix+"invalid_transition"] = tc
			}
		}

		// Test: available transitions endpoint
		if tc, ok := journey("_framework_workflows/"+prefix+"available_transitions", frameworkTestUser, "", AppTestStep{
			Get: fmt.Sprintf("/api/%s/{{entity_id}}/transitions", table),
			Expect: AppTestExpect{
				Status:   200,
				Contains: []string{`"current"`, `"transitions"`},
			},
		}); ok {
			tests[prefix+"available_transitions"] = tc
		}

		// Test: unauthenticated transition rejected
		tests[prefix+"unauth_rejected"] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				API:    fmt.Sprintf("POST /api/%s/1/transition", wf.Table),
				JSON:   map[string]any{"to": firstTarget},
				Expect: AppTestExpect{Status: 401},
			}},
		}
	}

	return AppTestFile{Name: "_framework_workflows", Tests: tests}
}

// pageExists reports whether the app has a registered page at the
// given route. Used by the auth test generator to differentiate SPA
// apps (login/signup live inside a React bundle) from gotmpl apps
// (login.html, signup.html as separate files).
func pageExists(app *App, route string) bool {
	if route == "" || app == nil {
		return false
	}
	if _, ok := app.Pages[route]; ok {
		return true
	}
	return false
}

func findTestableTextCol(cols []Column) string {
	for _, col := range cols {
		if col.PK || strings.HasSuffix(col.Name, "_id") || col.Name == "created_at" || col.Name == "updated_at" || col.Name == "deleted_at" {
			continue
		}
		if strings.Contains(strings.ToUpper(col.Type), "TEXT") || col.Type == "" {
			return col.Name
		}
	}
	return "id"
}
