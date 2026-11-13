//go:build !cli

package main

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// The admin panel's edit of an account row took any text as the address,
// let an admin replace their own address with no proof of the password or the
// new inbox, wrote last_login_at, and kept changing roles while the users
// table was hidden. admin.yaml's readonly:, columns: and search: were read
// and never applied, and a job queued for a hidden table's row showed that
// row on the jobs pages.

// An address typed into the panel passes the rules sign-up applies: one plain
// mailbox, in a domain auth.domain admits.
func TestAdminPanelAddressEditMeetsSignUpRules(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	refused := func(path string, values url.Values, id int, want string) {
		t.Helper()
		w := f.form(ada, path, values)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `"error":"admin_email_refused"`) ||
			!strings.Contains(w.Body.String(), `"docs":"auth.admin_panel_accounts"`) || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("POST %s %v: %d %s", path, values, w.Code, w.Body.String())
		}
		if id != 0 && (f.user(id, "email") != "cy@example.com" || f.user(id, "first_name") == "Changed") {
			t.Fatalf("the refused edit wrote account %d: email %q, first_name %q", id, f.user(id, "email"), f.user(id, "first_name"))
		}
	}
	edit := "/_admin/api/_benmore_users/update/" + strconv.Itoa(userColsCy)
	for _, address := range []string{"cy@example.org,eve@evil.example", "not-an-address", "cy@example.org|x", "Cy <cy@example.org>", " cy@example.org"} {
		refused(edit, url.Values{"email": {address}, "first_name": {"Changed"}}, userColsCy, "valid email address")
	}
	refused("/_admin/api/_benmore_users/create", url.Values{"username": {"mallory"}, "email": {"a@example.org,b@evil.example"}}, 0, "valid email address")
	if n := f.count("SELECT COUNT(*) FROM _benmore_users WHERE username = 'mallory'"); n != 0 {
		t.Fatal("a create with a refused address still made the account")
	}

	// auth.domain / auth.allow_emails decide here as they do at sign-up.
	f.app.Design.Auth["domain"] = "example.com"
	f.app.Design.Auth["allow_emails"] = "founder@elsewhere.example"
	refused(edit, url.Values{"email": {"cy@elsewhere.example"}, "first_name": {"Changed"}}, userColsCy, "Only @example.com emails are allowed")
	refused("/_admin/api/_benmore_users/create", url.Values{"username": {"mallory"}, "email": {"mallory@elsewhere.example"}}, 0, "Only @example.com emails are allowed")
	if w := f.form(ada, edit, url.Values{"email": {"founder@elsewhere.example"}}); w.Code != http.StatusOK || f.user(userColsCy, "email") != "founder@elsewhere.example" {
		t.Fatalf("an address auth.allow_emails names: %d %s", w.Code, w.Body.String())
	}
	if w := f.form(ada, edit, url.Values{"email": {"cy2@example.com"}}); w.Code != http.StatusOK || f.user(userColsCy, "email") != "cy2@example.com" {
		t.Fatalf("an address in the allowed domain: %d %s", w.Code, w.Body.String())
	}
	if w := f.form(ada, "/_admin/api/_benmore_users/create", url.Values{"username": {"nell"}, "email": {"nell@example.com"}}); w.Code != http.StatusOK ||
		f.count("SELECT COUNT(*) FROM _benmore_users WHERE email = 'nell@example.com'") != 1 {
		t.Fatalf("create with an address in the allowed domain: %d %s", w.Code, w.Body.String())
	}
	// An edit that sends the stored address back is no change, whatever the
	// rules say about it now: the form sends every field.
	mustExecArgs(t, f.db, "UPDATE _benmore_users SET email = 'old@legacy.example' WHERE id = ?", userColsCy)
	if w := f.form(ada, edit, url.Values{"email": {"old@legacy.example"}, "last_name": {"Kept"}}); w.Code != http.StatusOK || f.user(userColsCy, "last_name") != "Kept" {
		t.Fatalf("an edit echoing an address the gate would refuse today: %d %s", w.Code, w.Body.String())
	}
}

// An admin's own address is changed by the email-change flow (the current
// password, then a link to the new inbox), never by the panel.
func TestAdminPanelRefusesTheCallersOwnAddress(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	second := f.session(userColsAda, "ada@example.com")
	own := "/_admin/api/_benmore_users/update/" + strconv.Itoa(userColsAda)
	for _, address := range []string{"ada@example.org", ""} {
		w := f.form(ada, own, url.Values{"email": {address}, "first_name": {"Changed"}})
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"error":"admin_own_email_protected"`) ||
			!strings.Contains(w.Body.String(), `"docs":"auth.email_change"`) || !strings.Contains(w.Body.String(), "/settings/profile") {
			t.Fatalf("an admin's own address %q through the panel: %d %s", address, w.Code, w.Body.String())
		}
	}
	if f.user(userColsAda, "email") != "ada@example.com" || f.user(userColsAda, "first_name") == "Changed" {
		t.Fatalf("the refused edit wrote the admin's row: %q %q", f.user(userColsAda, "email"), f.user(userColsAda, "first_name"))
	}
	if GetSessionFromDB(f.db, ada) == nil || GetSessionFromDB(f.db, second) == nil {
		t.Fatal("a refused change ended the admin's sessions")
	}
	// The same form with the address as stored saves the other fields.
	if w := f.form(ada, own, url.Values{"email": {"ada@example.com"}, "first_name": {"Ada"}}); w.Code != http.StatusOK || f.user(userColsAda, "first_name") != "Ada" {
		t.Fatalf("an edit of the admin's own row that keeps the address: %d %s", w.Code, w.Body.String())
	}
	// Another account that is no admin: still changed here, as documented.
	if w := f.form(ada, "/_admin/api/_benmore_users/update/"+strconv.Itoa(userColsCy), url.Values{"email": {"cy@example.org"}}); w.Code != http.StatusOK || f.user(userColsCy, "email") != "cy@example.org" {
		t.Fatalf("another account's address: %d %s", w.Code, w.Body.String())
	}
}

// last_login_at is kept by sign-in: the panel shows it and never writes it.
func TestAdminPanelNeverWritesLastLogin(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	mustExecArgs(t, f.db, "UPDATE _benmore_users SET last_login_at = '2026-03-04 05:06:07' WHERE id = ?", userColsCy)
	edit := "/_admin/api/_benmore_users/update/" + strconv.Itoa(userColsCy)
	w := f.form(ada, edit, url.Values{"last_login_at": {"2001-01-01 00:00:00"}, "first_name": {"Cy"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("X-Stripped-Fields"), "last_login_at") {
		t.Fatalf("update naming last_login_at: %d %s (stripped %q)", w.Code, w.Body.String(), w.Header().Get("X-Stripped-Fields"))
	}
	if got := f.user(userColsCy, "last_login_at"); !strings.HasPrefix(got, "2026-03-04") || f.user(userColsCy, "first_name") != "Cy" {
		t.Fatalf("after the update: last_login_at %q, first_name %q", got, f.user(userColsCy, "first_name"))
	}
	if w := f.form(ada, edit, url.Values{"last_login_at": {""}}); w.Code != http.StatusBadRequest || !strings.HasPrefix(f.user(userColsCy, "last_login_at"), "2026-03-04") {
		t.Fatalf("update naming only last_login_at: %d %s", w.Code, w.Body.String())
	}
	w = f.form(ada, "/_admin/api/_benmore_users/create", url.Values{"username": {"nell"}, "email": {"nell@example.com"}, "last_login_at": {"2001-01-01 00:00:00"}})
	if w.Code != http.StatusOK || f.count("SELECT COUNT(*) FROM _benmore_users WHERE username = 'nell' AND last_login_at IS NULL") != 1 {
		t.Fatalf("create naming last_login_at: %d %s", w.Code, w.Body.String())
	}
	// Shown on the user page, with no input.
	page := f.page(ada, "/_admin/_benmore_users/"+strconv.Itoa(userColsCy))
	if !strings.Contains(page, "2026-03-04") || strings.Contains(page, `name="last_login_at"`) {
		t.Fatal("the user page offers an input for last_login_at, or does not show it")
	}
	if strings.Contains(f.page(ada, "/_admin/_benmore_users"), `name="last_login_at"`) {
		t.Fatal("the create form offers an input for last_login_at")
	}
}

// A hidden users table has no panel write surface: the role form's endpoint
// answers as the table's other write routes do.
func TestAdminSetRoleFollowsAdminYAML(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	setRole := url.Values{"user_id": {strconv.Itoa(userColsCy)}, "role": {"admin"}}
	f.app.Admin = &AdminConfig{Tables: map[string]AdminTableConfig{"_Benmore_Users": {Hidden: true}}}
	if w := f.form(ada, "/_admin/set-role", setRole); w.Code != http.StatusNotFound || f.role(userColsCy) != "user" {
		t.Fatalf("set-role with the users table hidden: %d, role %q", w.Code, f.role(userColsCy))
	}
	f.app.Admin = &AdminConfig{Tables: map[string]AdminTableConfig{"_benmore_users": {Readonly: adminReadonly{Table: true}}}}
	if w := f.form(ada, "/_admin/set-role", setRole); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"error":"admin_table_read_only"`) || f.role(userColsCy) != "user" {
		t.Fatalf("set-role with the users table read-only: %d %s, role %q", w.Code, w.Body.String(), f.role(userColsCy))
	}
	if n := f.count("SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'role_changed'"); n != 0 {
		t.Fatalf("%d role changes were audited for refused requests", n)
	}
	f.app.Admin = nil
	if w := f.form(ada, "/_admin/set-role", setRole); w.Code != http.StatusSeeOther || f.role(userColsCy) != "admin" {
		t.Fatalf("set-role with no admin.yaml: %d, role %q", w.Code, f.role(userColsCy))
	}
}

const adminConfigYAML = `tables:
  Clients:
    readonly: true
  invoices:
    columns: [label, client_id]
    search: [label]
    readonly: [client_id]
`

// readonly: true makes a table one the panel shows and never writes.
func TestAdminYAMLReadOnlyTable(t *testing.T) {
	_, mux, admin := adminHiddenFixture(t, adminConfigYAML)
	for _, path := range []string{"/_admin/api/clients/create", "/_admin/api/clients/update/1", "/_admin/api/CLIENTS/delete/1"} {
		rec := crudScopeRequest(t, mux, http.MethodPost, path, admin, map[string]any{"name": "panel-written"})
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"error":"admin_table_read_only"`) ||
			!strings.Contains(rec.Body.String(), "read-only in admin.yaml") || !strings.Contains(rec.Body.String(), `"docs":"auth.admin_panel_config"`) {
			t.Fatalf("POST %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	list := adminPage(t, mux, admin, "/_admin/clients")
	if !strings.Contains(list, "first client") || !strings.Contains(list, "second client") {
		t.Fatal("a read-only table's rows are not listed, or one was written")
	}
	for _, control := range []string{"+ Create", "/_admin/api/clients/delete/", `id="admin-create"`, ">Edit<"} {
		if strings.Contains(list, control) {
			t.Errorf("the read-only table's list page has %q", control)
		}
	}
	record := adminPage(t, mux, admin, "/_admin/clients/1")
	if !strings.Contains(record, "first client") || strings.Contains(record, "Save Changes") || strings.Contains(record, `name="name"`) {
		t.Fatal("the read-only table's record page offers an edit")
	}
	// The API is the app's: admin.yaml is a panel setting.
	if rec := crudScopeRequest(t, mux, http.MethodPatch, "/api/clients/2", admin, map[string]any{"name": "api-written"}); rec.Code != http.StatusOK {
		t.Fatalf("PATCH /api/clients/2: %d %s", rec.Code, rec.Body.String())
	}
}

// columns: chooses what the pages show and the forms offer, search: what the
// list's search matches, and readonly: [..] the columns the panel never
// writes.
func TestAdminYAMLColumnsSearchAndReadOnlyColumns(t *testing.T) {
	app, mux, admin := adminHiddenFixture(t, adminConfigYAML)
	mustExec(t, app.DB, `INSERT INTO invoices (client_id, label) VALUES (77, 'other-label')`)
	list := adminPage(t, mux, admin, "/_admin/invoices")
	if !strings.Contains(list, ">Label<") || !strings.Contains(list, ">Client id<") || strings.Contains(list, ">Id<") {
		t.Fatal("the list page does not show exactly the columns admin.yaml names")
	}
	if strings.Index(list, ">Label<") > strings.Index(list, ">Client id<") {
		t.Fatal("the columns are not in the order admin.yaml gives")
	}
	// The create form offers the listed columns that are not read-only.
	if !strings.Contains(list, `name="label"`) || strings.Contains(list, `name="client_id"`) {
		t.Fatal("the create form does not offer exactly the listed, writable columns")
	}
	// Search matches the search: columns only: 77 is a client_id, not a label.
	if hit := adminPage(t, mux, admin, "/_admin/invoices?q=other-lab"); !strings.Contains(hit, "other-label") || strings.Contains(hit, "invoice-marker") {
		t.Fatal("search on a search: column does not find its row alone")
	}
	if miss := adminPage(t, mux, admin, "/_admin/invoices?q=77"); strings.Contains(miss, "other-label") {
		t.Fatal("search matched a column search: does not name")
	}
	record := adminPage(t, mux, admin, "/_admin/invoices/1")
	if !strings.Contains(record, `name="label"`) || strings.Contains(record, `name="client_id"`) || !strings.Contains(record, "Client id") {
		t.Fatal("the record page does not show client_id read-only beside an editable label")
	}

	stored := func(col string) string {
		t.Helper()
		var v string
		if err := app.DB.QueryRow("SELECT CAST(" + col + " AS TEXT) FROM invoices WHERE id = 1").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, body := range []map[string]any{{"client_id": 2, "label": "moved"}, {"CLIENT_ID": 2}} {
		rec := crudScopeRequest(t, mux, http.MethodPost, "/_admin/api/invoices/update/1", admin, body)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"error":"admin_column_read_only"`) || !strings.Contains(rec.Body.String(), `"docs":"auth.admin_panel_config"`) {
			t.Fatalf("update naming a read-only column %v: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	if rec := crudScopeRequest(t, mux, http.MethodPost, "/_admin/api/invoices/create", admin, map[string]any{"client_id": 2, "label": "panel-made"}); rec.Code != http.StatusForbidden {
		t.Fatalf("create naming a read-only column: %d %s", rec.Code, rec.Body.String())
	}
	if stored("client_id") != "1" || stored("label") != "invoice-marker" {
		t.Fatalf("a refused write changed the row: client_id %s, label %q", stored("client_id"), stored("label"))
	}
	var made int
	app.DB.QueryRow("SELECT COUNT(*) FROM invoices WHERE label = 'panel-made'").Scan(&made)
	if made != 0 {
		t.Fatal("a refused create made a row")
	}
	// The other columns are written as before.
	if rec := crudScopeRequest(t, mux, http.MethodPost, "/_admin/api/invoices/update/1", admin, map[string]any{"label": "relabelled"}); rec.Code != http.StatusOK || stored("label") != "relabelled" {
		t.Fatalf("update of a writable column: %d %s", rec.Code, rec.Body.String())
	}
}

// admin.yaml takes `readonly: true` and `readonly: [columns]`, and its
// lookups compare table and column names as SQLite does.
func TestAdminConfigReadsBothReadOnlyShapes(t *testing.T) {
	cfg := parseAdminConfig([]byte(adminConfigYAML))
	if cfg == nil || !cfg.TableReadOnly("clients") || cfg.TableReadOnly("invoices") {
		t.Fatalf("readonly: true: %+v", cfg)
	}
	if !cfg.IsReadonly("INVOICES", "Client_ID") || cfg.IsReadonly("invoices", "label") || cfg.IsReadonly("clients", "name") {
		t.Fatal("readonly: [client_id] is not read as a column list")
	}
	if got := cfg.VisibleColumns("Invoices"); len(got) != 2 || got[0] != "label" {
		t.Fatalf("columns: %v", got)
	}
	if got := cfg.SearchColumns("Invoices"); len(got) != 1 || got[0] != "label" {
		t.Fatalf("search: %v", got)
	}
	var bad AdminConfig
	if err := decodeConfigYAML([]byte("tables:\n  clients:\n    readonly: sometimes\n"), &bad); err == nil {
		t.Fatal("readonly: sometimes decoded")
	}
}

// A key admin.yaml does not read is refused at write time and by
// `benmore check`: it would do nothing while the file reads as if it did.
func TestAdminYAMLWriteGateRefusesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", adminHiddenSchema)
	for content, want := range map[string]string{
		"tables:\n  clients:\n    read_only: true\n":             `unknown key "read_only"`,
		"tables:\n  clients:\n    hide: true\n":                  `unknown key "hide"`,
		"table:\n  clients:\n    hidden: true\n":                 `unknown key "table"`,
		"tables:\n  clients:\n    readonly: sometimes\n":         "readonly",
		"tables:\n  clients: hidden\n":                           "clients",
		"tables:\n  clients:\n    columns: name\n":               "columns",
		"tables:\n  clients:\n    hidden: true\n  CLIENTS: {}\n": "more than once",
	} {
		msg := ValidateOnWriteIn(dir, "admin.yaml", content)
		if !strings.Contains(msg, want) || !strings.Contains(msg, "admin.yaml") {
			t.Errorf("admin.yaml %q: refusal %q does not name %s", content, msg, want)
		}
	}
	if msg := ValidateOnWriteIn(dir, "admin.yaml", adminConfigYAML); msg != "" {
		t.Fatalf("a valid admin.yaml is refused: %s", msg)
	}
	if msg := ValidateOnWriteIn(dir, "admin.yaml", "tables:\n  clients:\n    hidden: true\n    label: Customers\n"); msg != "" {
		t.Fatalf("hidden + label refused: %s", msg)
	}
	// `benmore check` reads the file too.
	writeTestFile(t, dir, "admin.yaml", "tables:\n  clients:\n    read_only: true\n")
	found := false
	for _, file := range walkAppFiles(dir) {
		found = found || file.relPath == "admin.yaml"
	}
	if !found {
		t.Fatal("benmore check does not read admin.yaml")
	}
}

// A queued job that carries a hidden table's row is not on the jobs pages.
func TestAdminPanelShowsNoJobsAboutAHiddenTable(t *testing.T) {
	app, mux, admin := adminHiddenFixture(t, "tables:\n  SECRETS:\n    hidden: true\n")
	app.mu.Lock()
	app.Flows = append(app.Flows, Flow{Name: "on_secret", Trigger: FlowTrigger{Type: "on_insert", Table: "Secrets"}}, Flow{Name: "on_invoice", Trigger: FlowTrigger{Type: "on_update", Table: "invoices"}})
	app.mu.Unlock()
	insert := func(kind, flow, payload string) string {
		t.Helper()
		res, err := app.DB.Exec(`INSERT INTO _benmore_jobs (job_type, flow_name, payload, status) VALUES (?, ?, ?, 'failed')`, kind, flow, payload)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return strconv.FormatInt(id, 10)
	}
	hidden := []string{
		insert("hook", "hook", `{"_hook":{"table":"secrets","webhook":"https://hooks.example/a"},"_row":{"id":1,"body":"job-secret-hook"}}`),
		insert("webhook_subscription", "webhook", `{"_webhook_subscription":{"table":"Secrets","event":"insert"},"_row":{"id":1,"body":"job-secret-webhook"}}`),
		insert("flow", "on_secret", `{"id":1,"body":"job-secret-event"}`),
	}
	shown := []string{
		insert("hook", "hook", `{"_hook":{"table":"invoices"},"_row":{"id":1,"label":"job-invoice-hook","api_secret":"job-hidden-column-value"}}`),
		insert("flow", "on_invoice", `{"id":1,"label":"job-invoice-event"}`),
		insert("flow", "nightly", `{"note":"job-plain-flow"}`),
		insert("cron", "sweep", ``),
	}
	list := adminPage(t, mux, admin, "/_admin/_benmore_jobs")
	link := func(id string) string { return `href="/_admin/_benmore_jobs/` + id + `"` }
	for _, id := range hidden {
		if strings.Contains(list, link(id)) {
			t.Errorf("the jobs list shows job %s, which carries a row of the hidden table", id)
		}
	}
	for _, id := range shown {
		if !strings.Contains(list, link(id)) {
			t.Errorf("the jobs list lost job %s", id)
		}
	}
	if !strings.Contains(list, strconv.Itoa(len(shown))+" records") {
		t.Errorf("the jobs page does not count the %d jobs it lists", len(shown))
	}
	// A job's payload is shown as the jobs API returns it, and the list's
	// search does not match what that leaves out.
	if page := adminPage(t, mux, admin, "/_admin/_benmore_jobs/"+shown[0]); !strings.Contains(page, "job-invoice-hook") || strings.Contains(page, "job-hidden-column-value") {
		t.Error("the job page shows a hidden column's value, or lost the payload")
	}
	for _, q := range []string{"job-hidden-column-value", "job-secret-hook", "job-invoice-hook"} {
		if page := adminPage(t, mux, admin, "/_admin/_benmore_jobs?q="+q); strings.Contains(page, `href="/_admin/_benmore_jobs/`) {
			t.Errorf("the jobs search matched payload text %q", q)
		}
	}
	if page := adminPage(t, mux, admin, "/_admin/_benmore_jobs?q=nightly"); !strings.Contains(page, link(shown[2])) || strings.Contains(page, link(shown[0])) {
		t.Error("the jobs search does not find a job by its flow name")
	}
	for _, id := range hidden {
		if rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/_benmore_jobs/"+id, admin, nil); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "job-secret") {
			t.Errorf("job %s about the hidden table has a page: %d", id, rec.Code)
		}
	}
	for _, id := range shown {
		if rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/_benmore_jobs/"+id, admin, nil); rec.Code != http.StatusOK {
			t.Errorf("job %s has no page: %d", id, rec.Code)
		}
	}
}
