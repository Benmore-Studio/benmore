//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The fixture is the actual synthetic owned report/schema/access/encryption source.
// Every database row, session and key below is generated locally.
func reportPacketApp(t *testing.T) *App {
	t.Helper()
	root := filepath.Join("testdata", "report-packet")
	dir := t.TempDir()
	for _, name := range []string{"app.yaml", "schema.prisma", "encrypted.yaml"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	if err != nil {
		t.Fatal(err)
	}
	models, err := ParsePrismaSchema(string(schema))
	if err != nil {
		t.Fatal(err)
	}
	ddl := EmitSQL(models)
	path := filepath.Join(dir, "data.db")
	RegisterDBEncryptionKey(path, testKeyBytes(0x43))
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(path)) })
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(path, dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, ddl)
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour,
		Tables: ParseCreateTables(ddl), Design: LoadAppConfigYAML(dir), Group: LoadGroupConfig(dir),
		Access: LoadAccess(dir), Encrypted: LoadEncryptedFieldsConfig(dir)}
	t.Cleanup(app.Shutdown)
	if app.Group == nil || app.Group.Key != "org_id" || app.Access == nil || app.Encrypted == nil {
		t.Fatal("actual source configuration did not load")
	}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureBlindColumns(db, app.Encrypted)
	if err := InstallEncryptionTriggers(db, app.Encrypted); err != nil {
		t.Fatal(err)
	}
	InstallBlindIndexTriggers(db, app.Encrypted)
	for i := range app.Tables {
		app.Tables[i].Columns, err = GetTableColumns(db, app.Tables[i].Name)
		if err != nil {
			t.Fatal(err)
		}
	}
	crudScopeMustExec(t, db, "INSERT INTO organizations(id,name,user_id) VALUES(1,'Synthetic north',0),(2,'Synthetic south',0)")
	crudScopeMustExec(t, db, "INSERT INTO case_records(id,org_id,user_id,title) VALUES(1,1,0,'Synthetic north case'),(2,2,0,'Synthetic south case')")
	legacy, err := os.ReadFile(filepath.Join(root, "legacy-evidence.html"))
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := os.ReadFile(filepath.Join(root, "my-evidence.html"))
	if err != nil {
		t.Fatal(err)
	}
	if msg := ValidateOnWriteIn(dir, "my-evidence.html", string(proposed)); msg != "" {
		t.Fatal(msg)
	}
	ssrLoadPages(t, app, map[string]string{"legacy-evidence.html": string(legacy), "my-evidence.html": string(proposed)})
	return app
}

func reportPacketActor(t *testing.T, app *App, name, role, group, actAs string) (string, int64) {
	t.Helper()
	sid := createCrudScopeSession(t, app, name+"@example.com", role, group, actAs)
	uid := GetSessionFromDB(app.DB, sid).UserID
	if group != "" {
		if _, err := app.DB.Exec("INSERT INTO members(org_id,user_id,member_role,active) VALUES(?,?,'reviewer',1)", group, uid); err != nil {
			t.Fatal(err)
		}
	}
	return sid, uid
}

func reportPacketDoc(t *testing.T, app *App, id, org, uid int64, title string, deleted any) {
	t.Helper()
	if _, err := app.DB.Exec("INSERT INTO case_documents(id,org_id,user_id,case_id,title,body,deleted_at) VALUES(?,?,?,?,?,?,?)", id, org, uid, org, title, "body-"+title, deleted); err != nil {
		t.Fatal(err)
	}
}

func reportPacketRead(t *testing.T, mux *http.ServeMux, route, sid string) (string, int, int) {
	t.Helper()
	w := ssrGet(mux, route, sid)
	if w.Code != 200 {
		t.Fatalf("%s status=%d body=%s", route, w.Code, w.Body.String())
	}
	body := w.Body.String()
	m := regexp.MustCompile(`data-testid="document-count">Documents: ([0-9]+)</p>`).FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatalf("count shape missing: %s", body)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return body, n, strings.Count(body, "<article>")
}

func TestReportSourcePacketOrdinaryTenantParity(t *testing.T) {
	app := reportPacketApp(t)
	owner, uid := reportPacketActor(t, app, "owner", "user", "1", "")
	peer, pid := reportPacketActor(t, app, "peer", "user", "1", "")
	other, oid := reportPacketActor(t, app, "other", "user", "2", "")
	empty, _ := reportPacketActor(t, app, "empty", "user", "1", "")
	reportPacketDoc(t, app, 20, 1, uid, "owner-second", nil)
	reportPacketDoc(t, app, 10, 1, uid, "owner-first", nil)
	reportPacketDoc(t, app, 30, 1, pid, "peer-only", nil)
	reportPacketDoc(t, app, 40, 2, uid, "same-owner-other-tenant", nil)
	reportPacketDoc(t, app, 50, 2, oid, "other-only", nil)
	reportPacketDoc(t, app, 60, 1, uid, "owner-deleted", "2026-01-01")
	mux := buildAppMux(app, false, "https://offline-report.example.invalid")
	for _, tc := range []struct {
		name, sid string
		count     int
	}{{"owner", owner, 2}, {"peer", peer, 1}, {"other", other, 1}, {"empty", empty, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			old, on, oa := reportPacketRead(t, mux, "/legacy-evidence", tc.sid)
			new, nn, na := reportPacketRead(t, mux, "/my-evidence", tc.sid)
			if on != tc.count || nn != tc.count || oa != tc.count || na != tc.count {
				t.Fatalf("legacy=%d/%d typed=%d/%d want=%d", on, oa, nn, na, tc.count)
			}
			if strings.Contains(new, "same-owner-other-tenant") || strings.Contains(new, "owner-deleted") {
				t.Fatal("foreign or deleted row escaped")
			}
			if tc.name == "owner" {
				if !strings.Contains(new, "body-owner-first") || !strings.Contains(new, "body-owner-second") || strings.Contains(new, "body-peer-only") {
					t.Fatal("encrypted owner/peer behavior changed")
				}
				if strings.Index(new, "<h2>owner-first</h2>") > strings.Index(new, "<h2>owner-second</h2>") {
					t.Fatal("ID order changed")
				}
			}
			if tc.count == 0 && (!strings.Contains(old, "No active evidence belongs to this account.") || !strings.Contains(new, "No active evidence belongs to this account.")) {
				t.Fatal("empty text changed")
			}
		})
	}
	// Page sources inherit the original authentication requirement.
	if w := ssrGet(mux, "/my-evidence", ""); w.Code == 200 {
		t.Fatal("signed-out report returned success")
	}
	FlushReadAudit(app)
	var audit int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_read_audit WHERE table_name='case_documents' AND query_type='query'").Scan(&audit); err != nil || audit != 4 {
		t.Fatalf("one native read audit entry per report: %d (%v)", audit, err)
	}
	t.Log("PASS: real source fixture preserves owner AND selected tenant, peer denial, soft deletion, decryption, ID ordering, zero count/list, authentication, and native read audit for ordinary selected-tenant users")
}

func TestReportSourcePacketCopiedCiphertextStaysLiteral(t *testing.T) {
	app := reportPacketApp(t)
	sid, uid := reportPacketActor(t, app, "literal", "user", "1", "")
	_, other := reportPacketActor(t, app, "cipher-owner", "user", "2", "")
	reportPacketDoc(t, app, 1, 2, other, "synthetic-foreign-marker", nil)
	var cipher string
	if err := app.DB.QueryRow("SELECT body FROM case_documents WHERE id=1").Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cipher, "enc:") {
		t.Fatal("fixture body is not encrypted")
	}
	reportPacketDoc(t, app, 2, 1, uid, cipher, nil)
	mux := buildAppMux(app, false, "https://offline-report.example.invalid")
	old, _, _ := reportPacketRead(t, mux, "/legacy-evidence", sid)
	new, _, _ := reportPacketRead(t, mux, "/my-evidence", sid)
	if !strings.Contains(old, "body-synthetic-foreign-marker") || strings.Contains(new, "body-synthetic-foreign-marker") || !strings.Contains(new, "enc:") {
		t.Fatal("expected source-aware literal ciphertext behavior was not observed")
	}
	t.Log("PASS: synthetic possessed ciphertext in ordinary title stays literal under typed source; actual encrypted body still decodes through source metadata")
}

func reportPacketDenied(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status || strings.Contains(w.Body.String(), "<article>") || strings.Contains(w.Body.String(), "CASEWORK / PRIVATE EVIDENCE") {
		t.Fatalf("denied report: status=%d want=%d body=%.500s", w.Code, status, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store, must-revalidate" {
		t.Fatal("denied report is cacheable")
	}
}

func TestReportSourcePacketTenantAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, role, group, actAs string
		want                     int
		title                    string
	}{
		{"admin", "admin", "1", "", 200, "north"}, {"groupless", "user", "", "", 403, ""},
		{"grouplessadmin", "admin", "", "", 403, ""}, {"stepped", "admin", "2", "1", 200, "north"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := reportPacketApp(t)
			sid, uid := reportPacketActor(t, app, tc.name, tc.role, tc.group, tc.actAs)
			reportPacketDoc(t, app, 1, 1, uid, "north", nil)
			reportPacketDoc(t, app, 2, 2, uid, "south", nil)
			mux := buildAppMux(app, false, "https://offline-report.example.invalid")
			for _, path := range []string{"/my-evidence", "/my-evidence?org_id=2&user_group_id=2&tenant_scope=2"} {
				req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(`{"org_id":2,"user_group_id":2}`))
				req.Header.Set("Authorization", "Bearer "+sid)
				req.Header.Set("X-Tenant-ID", "2")
				req.Header.Set("X-Group-ID", "2")
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)
				if tc.want != 200 {
					reportPacketDenied(t, w, tc.want)
					continue
				}
				if w.Code != 200 || strings.Count(w.Body.String(), "<article>") != 1 || !strings.Contains(w.Body.String(), "body-"+tc.title) || strings.Contains(w.Body.String(), "body-south") {
					t.Fatalf("trusted tenant scope changed: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestReportSourcePacketLimits(t *testing.T) {
	for _, limit := range []int{0, 1, 1000} {
		cap := limit
		if cap == 0 {
			cap = 200
		}
		for _, size := range []int{0, 1, cap, cap + 1} {
			t.Run(fmt.Sprintf("limit%d_rows%d", limit, size), func(t *testing.T) {
				app := reportPacketApp(t)
				sid, uid := reportPacketActor(t, app, "bounded", "user", "1", "")
				for id := 1; id <= size; id++ {
					reportPacketDoc(t, app, int64(id), 1, uid, fmt.Sprintf("visible-%04d", id), nil)
				}
				// Foreign and deleted rows must not spend this caller's output budget.
				reportPacketDoc(t, app, 2001, 2, uid, "foreign", nil)
				reportPacketDoc(t, app, 2002, 1, uid, "deleted", "2026-01-01")
				raw, err := os.ReadFile(filepath.Join("testdata", "report-packet", "my-evidence.html"))
				if err != nil {
					t.Fatal(err)
				}
				page := strings.Replace(string(raw), "    limit: 1000\n", "", 1)
				if limit > 0 {
					page = strings.Replace(page, "    overflow: error", fmt.Sprintf("    limit: %d\n    overflow: error", limit), 1)
				}
				ssrLoadPages(t, app, map[string]string{"my-evidence.html": page})
				mux := buildAppMux(app, false, "https://offline-report.example.invalid")
				if size > cap {
					w := ssrGet(mux, "/my-evidence", sid)
					reportPacketDenied(t, w, 422)
					if !strings.Contains(w.Body.String(), "report_source_limit_exceeded") || strings.Contains(w.Body.String(), "visible-") {
						t.Fatal("overflow response leaked rows or omitted stable error")
					}
					return
				}
				_, count, articles := reportPacketRead(t, mux, "/my-evidence", sid)
				if count != size || articles != size {
					t.Fatalf("count/list completeness: %d/%d want%d", count, articles, size)
				}
			})
		}
	}
}

func TestReportSourceTenantAggregatesAndNativeLimitUnchanged(t *testing.T) {
	app := reportPacketApp(t)
	sid, uid := reportPacketActor(t, app, "aggregate", "admin", "1", "")
	for id := int64(1); id <= 3; id++ {
		reportPacketDoc(t, app, id, 1, uid, fmt.Sprintf("group-%d", id), nil)
	}
	reportPacketDoc(t, app, 4, 2, uid, "foreign", nil)
	ssrLoadPages(t, app, map[string]string{
		"count.html":         reportFixturePage("    table: case_documents\n    tenant_scope: current\n    aggregates: [{fn: count, as: n}]\n    limit: 1\n    overflow: error", "scope: owner\n"),
		"groups.html":        reportFixturePage("    table: case_documents\n    tenant_scope: current\n    group_by: [title]\n    aggregates: [{fn: count, as: n}]\n    limit: 1\n    overflow: error", "scope: owner\n"),
		"contradiction.html": reportFixturePage("    table: case_documents\n    tenant_scope: current\n    where: {org_id: 2}", "scope: owner\n"),
		"literal.html":       reportFixturePage("    table: case_documents\n    tenant_scope: current\n    where: {org_id: ':user_group_id'}", "scope: owner\n"),
	})
	mux := buildAppMux(app, false, "https://offline-report.example.invalid")
	rows := reportFixtureRows(t, ssrGet(mux, "/count", sid))
	if len(rows) != 1 || rows[0]["n"] != float64(3) {
		t.Fatalf("count result is not tenant scoped: %#v", rows)
	}
	reportPacketDenied(t, ssrGet(mux, "/groups", sid), 422)
	for _, route := range []string{"/contradiction", "/literal?user_group_id=1"} {
		if rows := reportFixtureRows(t, ssrGet(mux, route, sid)); len(rows) != 0 {
			t.Fatalf("authored condition replaced or interpolated: %#v", rows)
		}
	}
	// Public native API keeps its existing admin behavior and truncating limit.
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{"table": "case_documents", "select": []string{"id"}, "limit": 1})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"rows":[{`) {
		t.Fatalf("native limit changed: %d %s", w.Code, w.Body.String())
	}
}

func TestReportSourceTenantMetadataAndAuthoring(t *testing.T) {
	valid := reportFixturePage("    table: case_documents\n    tenant_scope: current\n    overflow: error", "")
	for _, raw := range []string{
		strings.Replace(valid, "tenant_scope: current", "tenant_scope: user_group_id", 1),
		strings.Replace(valid, "overflow: error", "overflow: truncate", 1),
		strings.Replace(valid, "overflow: error", "overflow: error\n    limit: -1", 1),
		strings.Replace(valid, "overflow: error", "overflow: error\n    limit: 1001", 1),
		strings.Replace(valid, "tenant_scope: current", "tenant_scope: {param: org_id}", 1),
		strings.Replace(valid, "tenant_scope: current", "tenant_scope: null", 1),
		strings.Replace(valid, "tenant_scope: current", "tenant_scope: ''", 1),
		strings.Replace(valid, "overflow: error", "overflow: null", 1),
	} {
		if err := ValidateOnWrite("report.html", raw); err == "" {
			t.Errorf("bad report accepted: %s", raw)
		}
	}
	if err := ValidateOnWrite("report.html", valid); err != "" {
		t.Fatal(err)
	}
	app := reportPacketApp(t)
	sid, _ := reportPacketActor(t, app, "metadata", "admin", "1", "")
	ssrLoadPages(t, app, map[string]string{"bad.html": strings.Replace(valid, "case_documents", "reference_bulletins", 1)})
	mux := buildAppMux(app, false, "https://offline-report.example.invalid")
	reportPacketDenied(t, ssrGet(mux, "/bad", sid), 400)
	app.Group = nil
	reportPacketDenied(t, ssrGet(mux, "/my-evidence", sid), 400)
}

func TestReportSourceTenantValuesStayBound(t *testing.T) {
	app := reportPacketApp(t)
	tenant := "north' OR 1=1 --"
	session := &Session{UserID: 7, Role: "admin", GroupID: "other", ActingAsGroup: tenant}
	spec := &querySpec{Table: "case_documents", Select: []string{"id"}, Limit: 1000}
	text, args, err := buildQueryWithPolicy(app, spec, columnSet(app, spec.Table), session, queryReadPolicy{ownerOnly: true, currentTenant: true, rejectOverflow: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, tenant) || !strings.Contains(text, `"case_documents"."org_id" = ?`) || !strings.HasSuffix(text, " LIMIT 1001") {
		t.Fatalf("unsafe or unbounded query: %s", text)
	}
	if len(args) < 2 || args[0] != int64(7) || args[1] != tenant {
		t.Fatalf("server tenant not bound separately from owner: %#v", args)
	}
	// Public native builder must retain the cap and must not opt into report scope.
	text, _, err = buildQuery(app, spec, columnSet(app, spec.Table), &Session{UserID: 7, Role: "admin", GroupID: "1"})
	if err != nil || !strings.HasSuffix(text, " LIMIT 1000") || strings.Contains(text, " WHERE ") && !strings.Contains(text, "deleted_at IS NULL") {
		t.Fatalf("native builder changed: %s (%v)", text, err)
	}
}

func TestReportSourceMergedOptionsRejectInvalidEnums(t *testing.T) {
	for name, source := range map[string]string{
		"inline_null_tenant":      "    <<: {tenant_scope: null}",
		"inline_blank_tenant":     "    <<: {tenant_scope: ''}",
		"inline_unknown_tenant":   "    <<: {tenant_scope: request}",
		"inline_null_overflow":    "    <<: {overflow: null}",
		"inline_blank_overflow":   "    <<: {overflow: ''}",
		"inline_unknown_overflow": "    <<: {overflow: truncate}",
		"nested_merge":            "    <<: {<<: {tenant_scope: null}}",
		"merge_sequence":          "    <<: [{tenant_scope: null}, {overflow: error}]",
		"nested_alias":            "    where: {title: &blank ''}\n    <<: {<<: {tenant_scope: *blank}}",
		"null_alias":              "    where: {title: &absent null}\n    <<: {overflow: *absent}",
	} {
		t.Run(name, func(t *testing.T) {
			raw := reportFixturePage("    table: notes\n"+source, "")
			if err := ValidateOnWrite("report.html", raw); err == "" {
				t.Fatal("merged invalid option accepted")
			}
			if err := ValidateOnWriteIn(t.TempDir(), "report.html", raw); err == "" {
				t.Fatal("app-aware authoring accepted merged invalid option")
			}
		})
	}
	for _, option := range []string{"tenant_scope: null", "tenant_scope: ''", "tenant_scope: request", "overflow: null", "overflow: ''", "overflow: truncate"} {
		raw := "---\nengine: gotmpl\ndefaults: &opts {" + option + "}\nnested: &nested {<<: *opts}\nsources:\n  rows:\n    table: notes\n    <<: *nested\n---\n<p>{{len .sources.rows}}</p>"
		if err := ValidateOnWrite("report.html", raw); err == "" {
			t.Errorf("external merged option accepted: %s", option)
		}
	}
	// Valid inline defaults and YAML merge precedence remain supported; a
	// direct valid value may override an unused invalid inherited value.
	for _, source := range []string{
		"    <<: {tenant_scope: current, overflow: error}",
		"    <<: {tenant_scope: null}\n    tenant_scope: current\n    overflow: error",
		"    where: {title: &current current}\n    <<: {tenant_scope: *current, overflow: error}",
	} {
		if err := ValidateOnWrite("report.html", reportFixturePage("    table: notes\n"+source, "")); err != "" {
			t.Fatalf("valid merged options refused: %s", err)
		}
	}
}
