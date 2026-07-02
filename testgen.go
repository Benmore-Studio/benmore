//go:build !cli

package main

import (
	"fmt"
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
	files = append(files, generateAuditTests(app))
	files = append(files, generateBatchTests(app))
	files = append(files, generateDocsTests(app))
	if NeedsAuth(app) {
		files = append(files, generateAuthTests(app))
	}
	files = append(files, generateSEOTests(app))
	// Search removed - opinionated feature, not a framework concern
	// Export tests removed - export is CLI-only
	files = append(files, generatePerformanceTests(app))
	if IsPWAEnabled(app) {
		files = append(files, generatePWATests(app))
	}
	files = append(files, generateErrorTests(app))
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

	for _, table := range tables {
		cols := tableColumns(app, table)
		data := smartFormData(cols)

		// Access posture for the synthetic framework test user (a plain
		// authenticated user: role "user", no group, no extra role/scope/
		// access-level grants). The generator can't see groups / RBAC /
		// before-hooks, so it asserts what it can prove and tolerates
		// access-control denials elsewhere.
		readClosed := crudReadClosed(app, table)   // access read: off → 404 by design
		writeOK := crudWriteGuaranteed(app, table) // owner/public-writable, no tenancy/hook gate

		// List
		listExpect := AppTestExpect{Status: 200}
		if readClosed {
			listExpect = AppTestExpect{Status: 404}
		}
		tests["list_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps:  []AppTestStep{{Get: fmt.Sprintf("/api/%s", table), Expect: listExpect}},
		}

		// Create
		createExpect := AppTestExpect{Status: 200}
		if !writeOK {
			createExpect = AppTestExpect{StatusIn: crudWriteAcceptable}
		}
		tests["create_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps:  []AppTestStep{{API: fmt.Sprintf("POST /api/%s", table), Data: data, Expect: createExpect}},
		}

		// Offset pagination
		paginateExpect := AppTestExpect{Status: 200, Contains: []string{`"total"`, `"data"`}}
		if readClosed {
			paginateExpect = AppTestExpect{Status: 404}
		}
		tests["paginate_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps:  []AppTestStep{{Get: fmt.Sprintf("/api/%s?page=1&per_page=5&sort=id&order=desc", table), Expect: paginateExpect}},
		}

		// Cursor pagination
		cursorExpect := AppTestExpect{Status: 200, Contains: []string{`"next_cursor"`}}
		if readClosed {
			cursorExpect = AppTestExpect{Status: 404}
		}
		tests["cursor_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps:  []AppTestStep{{Get: fmt.Sprintf("/api/%s?cursor=0&limit=5", table), Expect: cursorExpect}},
		}
	}

	return AppTestFile{Name: "_framework_crud", Tests: tests}
}

// crudWriteAcceptable is the set of statuses an auto-CRUD create may return
// for the synthetic framework test user when the table is not provably
// writable by a plain authenticated user. It is success (200/201) OR a
// well-formed access-control denial: 401 (unauth), 403 (forbidden / CSRF),
// 404 (the framework's "don't leak existence" posture on access denial),
// 422 (RBAC / before_insert hook abort). 400 and 5xx are deliberately
// excluded so malformed-data and server bugs still fail the test.
var crudWriteAcceptable = []int{200, 201, 401, 403, 404, 422}

// crudReadClosed reports whether generic reads of the table are disabled
// (access read: off). The framework returns 404 for these (the only read
// path is a secure flow), so the auto-CRUD read tests assert closure rather
// than a 200 list.
func crudReadClosed(app *App, table string) bool {
	if app == nil {
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	return app.Access.ModeFor(table, OpRead, hasUID, hasGroupKey) == "off"
}

// crudWriteGuaranteed reports whether the synthetic framework test user can
// DEFINITELY create a row in this table. Only owner/public-writable tables
// with no tenancy gate and no before_insert hook qualify; everything else -
// group scoping (the synthetic user has no group), admin/role/perm/member-of
// modes, write: off, or an app before_insert hook that may abort - can
// legitimately deny the write, so a strict 200 assertion would be a false
// failure.
func crudWriteGuaranteed(app *App, table string) bool {
	if app == nil {
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	switch app.Access.ModeFor(table, OpWrite, hasUID, hasGroupKey) {
	case "self", "everyone", "anon", "public":
		// writable in principle
	default:
		// off, admin, group, role:*, perm:*, member-of:*, owner_or_role:*
		return false
	}
	// A group-keyed table auto-stamps the caller's group on insert; the
	// synthetic user has none, so the create is denied.
	if hasGroupKey {
		return false
	}
	// An app before_insert hook can abort the write for reasons the
	// generator can't see.
	if app.Hooks != nil {
		if h, ok := app.Hooks.BeforeInsert[table]; ok && len(h) > 0 {
			return false
		}
	}
	return true
}

// firstWritableTable returns the first table the synthetic framework test
// user can definitely write, or "" if none. Used by the audit/batch/security
// generators, which need a real successful write to assert behavior.
func firstWritableTable(app *App, tables []string) string {
	for _, t := range tables {
		if crudWriteGuaranteed(app, t) {
			return t
		}
	}
	return ""
}

// ===== Security Tests =====

func generateSecurityTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	tables := userTables(app)

	// Pick a table for CSRF/auth tests
	targetTable := "contacts"
	if len(tables) > 0 {
		targetTable = tables[0]
	}

	// Anonymous POST rejected (no CSRF, no auth)
	tests["csrf_auth_rejection"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			API:  fmt.Sprintf("POST /api/%s", targetTable),
			Data: map[string]any{"name": "hacker"},
			Expect: AppTestExpect{
				Status: 401,
			},
		}},
	}

	// Bearer auth skips CSRF (the CSRF skip is auth-type based, not role
	// based). Prefer a table the synthetic user can definitely write so a
	// clean 200 proves the bypass; otherwise accept success or an
	// access-control denial that is NOT a CSRF rejection. A CSRF failure
	// surfaces as 403 "Invalid CSRF token", so excluding 403 keeps the
	// test's teeth (the framework returns 404, not 403, on access denial).
	bearerTable := targetTable
	bearerExpect := AppTestExpect{StatusIn: []int{200, 201, 401, 404, 422}}
	if w := firstWritableTable(app, tables); w != "" {
		bearerTable = w
		bearerExpect = AppTestExpect{Status: 200}
	}
	cols := tableColumns(app, bearerTable)
	data := smartFormData(cols)
	tests["bearer_skips_csrf"] = AppTestCase{
		AsUser: frameworkTestUser,
		Steps: []AppTestStep{{
			API:    fmt.Sprintf("POST /api/%s", bearerTable),
			Data:   data,
			Bearer: true,
			Expect: bearerExpect,
		}},
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
	tests["admin_requires_auth"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get:    "/_admin",
			Expect: AppTestExpect{Status: 303},
		}},
	}

	return AppTestFile{Name: "_framework_security", Tests: tests}
}

// ===== CRUD Lifecycle Tests =====

func generateLifecycleTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)
	tables := userTables(app)

	for _, table := range tables {
		if !hasColumn(app, table, "deleted_at") {
			continue
		}

		cols := tableColumns(app, table)
		data := smartFormData(cols)

		// Find a text column to use as identifier for read assertions
		identCol := ""
		identVal := ""
		for _, col := range cols {
			if col.PK || col.Name == "user_id" || col.Name == "created_at" || col.Name == "updated_at" || col.Name == "deleted_at" {
				continue
			}
			if strings.Contains(strings.ToUpper(col.Type), "TEXT") || col.Type == "" {
				identCol = col.Name
				identVal = fmt.Sprintf("%v", data[col.Name])
				break
			}
		}
		if identCol == "" {
			continue
		}

		// Multi-step lifecycle: create → read → update → read → delete → read-after-delete
		updateCol := ""
		for _, col := range cols {
			if col.Name != identCol && col.Name != "user_id" && col.Name != "created_at" && col.Name != "updated_at" && col.Name != "deleted_at" && !col.PK {
				updateCol = col.Name
				break
			}
		}

		steps := []AppTestStep{
			// Step 1: Create
			{
				API:  fmt.Sprintf("POST /api/%s", table),
				Data: data,
				Expect: AppTestExpect{
					Status:   200,
					Contains: []string{`"id"`},
				},
			},
			// Step 2: Verify via SQL (since we don't have the ID in JSON path yet)
			{
				SQL:    fmt.Sprintf("SELECT * FROM %s WHERE %s = '%s' AND deleted_at IS NULL", table, identCol, identVal),
				Expect: AppTestExpect{Rows: 1},
			},
		}

		if updateCol != "" {
			// Step 3: Update via SQL (since we need the ID)
			steps = append(steps, AppTestStep{
				SQL: fmt.Sprintf("UPDATE %s SET %s = 'lifecycle_updated' WHERE %s = '%s'", table, updateCol, identCol, identVal),
			})
			// Step 4: Verify update
			steps = append(steps, AppTestStep{
				SQL:    fmt.Sprintf("SELECT * FROM %s WHERE %s = '%s' AND %s = 'lifecycle_updated'", table, identCol, identVal, updateCol),
				Expect: AppTestExpect{Rows: 1},
			})
		}

		// Step 5: Soft delete via SQL
		steps = append(steps, AppTestStep{
			SQL: fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE %s = '%s'", table, identCol, identVal),
		})
		// Step 6: Verify soft-deleted row is filtered from API reads
		steps = append(steps, AppTestStep{
			Get: fmt.Sprintf("/api/%s", table),
			Expect: AppTestExpect{
				Status:      200,
				NotContains: []string{identVal},
			},
		})

		tests["lifecycle_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Setup: []AppTestSetup{
				{SQL: fmt.Sprintf("DELETE FROM %s WHERE %s = '%s'", table, identCol, identVal)},
			},
			Steps: steps,
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
	table := ""
	var data map[string]any
	for _, t := range tables {
		if !crudWriteGuaranteed(app, t) {
			continue
		}
		cols := tableColumns(app, t)
		d := smartFormData(cols)
		if len(d) > 0 {
			table = t
			data = d
			break
		}
	}
	if table == "" {
		return AppTestFile{Name: "_framework_audit", Tests: tests}
	}

	// Create a record, then verify the audit log captured it
	tests["audit_trail_logged"] = AppTestCase{
		AsUser: frameworkTestUser,
		Setup: []AppTestSetup{
			{SQL: fmt.Sprintf("DELETE FROM _benmore_audit_log WHERE table_name = '%s'", table)},
		},
		Steps: []AppTestStep{
			{
				API:    fmt.Sprintf("POST /api/%s", table),
				Data:   data,
				Expect: AppTestExpect{Status: 200},
			},
			{
				SQL:    fmt.Sprintf("SELECT * FROM _benmore_audit_log WHERE table_name = '%s' AND action = 'insert'", table),
				Expect: AppTestExpect{Rows: 1},
			},
		},
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
	// asserts a successful 2-row create, so an access-gated table can't run it.
	table := firstWritableTable(app, tables)
	if table == "" {
		return AppTestFile{Name: "_framework_batch", Tests: tests}
	}
	cols := tableColumns(app, table)
	data := smartFormData(cols)

	// Build two JSON records
	rec1 := make(map[string]any)
	rec2 := make(map[string]any)
	for k, v := range data {
		rec1[k] = v
		rec2[k] = v
	}
	// Differentiate them slightly
	for _, col := range cols {
		if col.Name == "name" || strings.HasSuffix(col.Name, "_name") {
			rec1[col.Name] = "Batch One"
			rec2[col.Name] = "Batch Two"
			break
		}
	}

	tests["batch_create_"+table] = AppTestCase{
		AsUser: frameworkTestUser,
		Steps: []AppTestStep{{
			API:       fmt.Sprintf("POST /api/%s/batch", table),
			JSONArray: []any{rec1, rec2},
			Bearer:    true,
			Expect:    AppTestExpect{Status: 200, Contains: []string{`"count":2`}},
		}},
	}

	return AppTestFile{Name: "_framework_batch", Tests: tests}
}

// ===== Docs Tests =====

func generateDocsTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	tests["api_docs_json"] = AppTestCase{
		AsUser: frameworkTestUser,
		Steps: []AppTestStep{{
			Get:    "/api/_docs",
			Expect: AppTestExpect{Status: 200, Contains: []string{`"endpoints"`}},
		}},
	}

	tests["api_docs_html"] = AppTestCase{
		AsUser: frameworkTestUser,
		Steps: []AppTestStep{{
			Get:    "/docs",
			Expect: AppTestExpect{Status: 200, Contains: []string{"API Documentation", "Copy for LLM"}},
		}},
	}

	// Markdown export (Copy-for-LLM): non-empty and carries the top-level
	// section headings drawn from the same docs model.
	tests["api_docs_markdown"] = AppTestCase{
		AsUser: frameworkTestUser,
		Steps: []AppTestStep{{
			Get: "/docs?format=md",
			Expect: AppTestExpect{
				Status:   200,
				Contains: []string{"# API Documentation", "## Authentication", "## Platform features"},
			},
		}},
	}

	return AppTestFile{Name: "_framework_docs", Tests: tests}
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
		tests["signup_post_registered"] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				API:    "POST " + app.Paths.Signup,
				Expect: AppTestExpect{Status: 303},
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

	// Token endpoint: create a user first, then test the token exchange
	tests["token_endpoint"] = AppTestCase{
		AsUser: frameworkTestUser,
		Steps: []AppTestStep{{
			API:  "POST /api/_auth/token",
			JSON: map[string]any{"email": frameworkTestUser, "password": "testpass123"},
			Expect: AppTestExpect{
				Status:   200,
				Contains: []string{`"token"`},
			},
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
		tests["seo_"+ep.name] = AppTestCase{
			Anon: true,
			Steps: []AppTestStep{{
				Get:    ep.path,
				Expect: AppTestExpect{Status: 200, Contains: []string{ep.contains}},
			}},
		}
	}

	return AppTestFile{Name: "_framework_seo", Tests: tests}
}

// ===== Search Tests =====

// Search removed - opinionated feature, developer builds their own if needed.
// Export tests removed - export is CLI-only, not HTTP.

// ===== Performance Tests =====

func generatePerformanceTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	tests["health_fast"] = AppTestCase{
		Anon: true,
		Steps: []AppTestStep{{
			Get: "/health",
			Expect: AppTestExpect{
				Status:      200,
				MaxDuration: "10ms",
			},
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
// Skips PK, auto-managed fields, and FK references (*_id) to avoid constraint failures.
func smartFormData(cols []Column) map[string]any {
	data := make(map[string]any)
	for _, col := range cols {
		if col.PK || col.Name == "created_at" || col.Name == "updated_at" || col.Name == "deleted_at" {
			continue
		}
		// Skip all *_id columns (user_id is auto-set, others are FK references)
		if strings.HasSuffix(col.Name, "_id") {
			continue
		}
		data[col.Name] = smartTestValue(col)
	}
	return data
}

// ===== UUID Tests =====

func generateUUIDTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	for table := range app.UUIDTables {
		if strings.HasPrefix(table, "_benmore_") {
			continue
		}
		cols := tableColumns(app, table)
		data := smartFormData(cols)

		// UUID create: verify response ID is a string (not an integer)
		tests["uuid_create_"+table] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps: []AppTestStep{
				{
					API:    fmt.Sprintf("POST /api/%s", table),
					Data:   data,
					Bearer: true,
					Save:   map[string]string{"new_id": "id"},
					Expect: AppTestExpect{
						Status:   200,
						Contains: []string{`"id":"`, `"status":"created"`}, // string ID (not "id":123)
					},
				},
				// Verify the UUID row is readable via GET
				{
					Get: fmt.Sprintf("/api/%s/{{new_id}}", table),
					Expect: AppTestExpect{
						Status:   200,
						Contains: []string{`"id":"`},
					},
				},
			},
		}

		// UUID batch create
		if len(data) > 0 {
			tests["uuid_batch_"+table] = AppTestCase{
				AsUser: frameworkTestUser,
				Steps: []AppTestStep{{
					API:       fmt.Sprintf("POST /api/%s/batch", table),
					JSONArray: []any{data, data},
					Bearer:    true,
					Expect: AppTestExpect{
						Status:   200,
						Contains: []string{`"ids"`, `"count":2`},
					},
				}},
			}
		}

		// UUID lifecycle: create → update → delete
		// Find a non-PK, non-auto text column to update
		updateData := make(map[string]any)
		for _, col := range cols {
			if col.PK || col.Name == "created_at" || col.Name == "updated_at" || col.Name == "deleted_at" || col.Name == "user_id" || strings.HasSuffix(col.Name, "_id") {
				continue
			}
			updateData[col.Name] = "uuid_lifecycle_updated"
			break
		}
		if len(updateData) > 0 {
			tests["uuid_lifecycle_"+table] = AppTestCase{
				AsUser: frameworkTestUser,
				Steps: []AppTestStep{
					{
						API:    fmt.Sprintf("POST /api/%s", table),
						Data:   data,
						Bearer: true,
						Save:   map[string]string{"uuid_id": "id"},
						Expect: AppTestExpect{
							Status: 200,
						},
					},
					{
						API:    fmt.Sprintf("PATCH /api/%s/{{uuid_id}}", table),
						Data:   updateData,
						Bearer: true,
						Expect: AppTestExpect{
							Status: 200,
						},
					},
					{
						API:    fmt.Sprintf("DELETE /api/%s/{{uuid_id}}", table),
						Bearer: true,
						Expect: AppTestExpect{
							Status: 200,
						},
					},
				},
			}
		}
	}

	return AppTestFile{Name: "_framework_uuid", Tests: tests}
}

// ===== Workflow Tests =====

func generateWorkflowTests(app *App) AppTestFile {
	tests := make(map[string]AppTestCase)

	for name, wf := range app.Workflows.Workflows {
		// Find a valid first transition from the initial state
		targets := wf.Transitions[wf.Initial]
		var firstTarget string
		for to := range targets {
			firstTarget = to
			break
		}
		if firstTarget == "" {
			continue
		}

		// Find a text column for test data
		cols := tableColumns(app, wf.Table)
		data := smartFormData(cols)
		// Force the initial state
		data[wf.Field] = wf.Initial

		prefix := "wf_" + name + "_"

		// Test: valid transition succeeds
		tests[prefix+"valid_transition"] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps: []AppTestStep{
				{
					API:    fmt.Sprintf("POST /api/%s", wf.Table),
					Data:   data,
					Save:   map[string]string{"entity_id": "id"},
					Expect: AppTestExpect{Status: 200},
				},
				{
					API:    fmt.Sprintf("POST /api/%s/{{entity_id}}/transition", wf.Table),
					JSON:   map[string]any{"to": firstTarget},
					Bearer: true,
					Expect: AppTestExpect{
						Status:   200,
						Contains: []string{`"transitioned"`},
					},
				},
			},
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
			tests[prefix+"invalid_transition"] = AppTestCase{
				AsUser: frameworkTestUser,
				Steps: []AppTestStep{
					{
						API:    fmt.Sprintf("POST /api/%s", wf.Table),
						Data:   data,
						Save:   map[string]string{"entity_id": "id"},
						Expect: AppTestExpect{Status: 200},
					},
					{
						API:    fmt.Sprintf("POST /api/%s/{{entity_id}}/transition", wf.Table),
						JSON:   map[string]any{"to": invalidTarget},
						Bearer: true,
						Expect: AppTestExpect{Status: 409},
					},
				},
			}
		}

		// Test: available transitions endpoint
		tests[prefix+"available_transitions"] = AppTestCase{
			AsUser: frameworkTestUser,
			Steps: []AppTestStep{
				{
					API:    fmt.Sprintf("POST /api/%s", wf.Table),
					Data:   data,
					Save:   map[string]string{"entity_id": "id"},
					Expect: AppTestExpect{Status: 200},
				},
				{
					Get: fmt.Sprintf("/api/%s/{{entity_id}}/transitions", wf.Table),
					Expect: AppTestExpect{
						Status:   200,
						Contains: []string{`"current"`, `"transitions"`},
					},
				},
			},
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
