//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const appDataTestSecret = "app-data-channel-test-secret-0123456789abcdef"

// appDataTestBody encodes one channel request.
func appDataTestBody(t *testing.T, op string, actor appDataActor, args any) []byte {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(appDataRequest{Op: op, Actor: actor, Args: raw, RequestID: generateToken(8)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// appDataTestApp is an app whose database holds an app table and the
// framework tables the channel touches.
func appDataTestApp(t *testing.T) *App {
	t.Helper()
	app, done := newTestApp(t)
	t.Cleanup(done)
	EnsureAuditLogTable(app.DB)
	mustExec(t, app.DB, `CREATE TABLE notes(id INTEGER PRIMARY KEY, title TEXT, owner TEXT);
		INSERT INTO notes VALUES(1,'first','a'),(2,'second','b'),(3,'third','a');
		CREATE TABLE _benmore_sessions(id TEXT PRIMARY KEY, user_id INTEGER, expires_at TEXT);
		INSERT INTO _benmore_sessions VALUES('sha256:live-session',1,'2999-01-01');`)
	old := serverSecret
	serverSecret = appDataTestSecret
	t.Cleanup(func() { serverSecret = old })
	return app
}

var (
	appDataTestEditor = appDataActor{PlatformUserID: 7, Email: "editor@test.com", Role: "editor", Surface: "mcp"}
	appDataTestViewer = appDataActor{PlatformUserID: 8, Email: "viewer@test.com", Role: "viewer", Surface: "dashboard"}
)

// appDataPost sends body to the channel middleware as the router would.
func appDataPost(app *App, token string, body []byte, mutate func(*http.Request)) (int, appDataResponse, http.Header) {
	req := httptest.NewRequest(http.MethodPost, appDataRoute, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:40000"
	if token != "" {
		req.Header.Set(appDataTokenHeader, token)
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	appDataChannelMiddleware(next, app).ServeHTTP(rec, req)
	var resp appDataResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp, rec.Header()
}

func appDataTestToken(app *App, body []byte) string {
	return mintAppDataToken(app.Dir, time.Now().Add(30*time.Second), appDataTestSecret, appDataNonce16(), body)
}

func appDataNonce16() string {
	return generateToken(16)
}

func TestAppDataChannelAcceptsRouterTokenOnce(t *testing.T) {
	app := appDataTestApp(t)
	body := appDataTestBody(t, "count", appDataTestViewer, appDataCountArgs{})
	token := appDataTestToken(app, body)
	code, resp, header := appDataPost(app, token, body, nil)
	if code != http.StatusOK || !resp.OK || header.Get(appDataChannelHeader) != "1" {
		t.Fatalf("router call refused: %d %+v", code, resp)
	}
	var counts appDataCountResult
	if err := json.Unmarshal(resp.Result, &counts); err != nil || counts.Counts["notes"] != 3 {
		t.Fatalf("counts = %s (%v)", resp.Result, err)
	}
	// The same token (same body) is refused the second time.
	if code, resp, _ = appDataPost(app, token, body, nil); code != http.StatusForbidden || resp.Error != "forbidden" {
		t.Fatalf("replayed token: %d %+v", code, resp)
	}
}

func TestAppDataChannelRefusesBadTokens(t *testing.T) {
	app := appDataTestApp(t)
	body := appDataTestBody(t, "count", appDataTestEditor, appDataCountArgs{})
	other := appDataTestBody(t, "exec", appDataTestEditor, appDataExecArgs{SQL: "DELETE FROM notes"})
	now := time.Now()
	for name, token := range map[string]string{
		"missing":         "",
		"garbage":         "not-a-token",
		"other audience":  mintAppDataToken(app.Dir+"-dev", now.Add(30*time.Second), appDataTestSecret, appDataNonce16(), body),
		"other secret":    mintAppDataToken(app.Dir, now.Add(30*time.Second), "another-secret-0123456789abcdef-0123456789", appDataNonce16(), body),
		"expired":         mintAppDataToken(app.Dir, now.Add(-time.Second), appDataTestSecret, appDataNonce16(), body),
		"over the TTL":    mintAppDataToken(app.Dir, now.Add(2*appDataTokenTTL), appDataTestSecret, appDataNonce16(), body),
		"other body":      mintAppDataToken(app.Dir, now.Add(30*time.Second), appDataTestSecret, appDataNonce16(), other),
		"short nonce":     mintAppDataToken(app.Dir, now.Add(30*time.Second), appDataTestSecret, "abc", body),
		"connector token": mintAppMCPControlToken(app.Dir, now.Add(20*time.Second), appDataTestSecret, "owner@test.com", "status:0:0:0:0"),
	} {
		code, resp, header := appDataPost(app, token, body, nil)
		if code != http.StatusForbidden || resp.OK || header.Get(appDataChannelHeader) != "1" {
			t.Errorf("%s: %d %+v", name, code, resp)
		}
	}
	// A token minted for the exec body does not carry a different body.
	execToken := appDataTestToken(app, other)
	if code, _, _ := appDataPost(app, execToken, body, nil); code != http.StatusForbidden {
		t.Errorf("token reused for another body: %d", code)
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n); err != nil || n != 3 {
		t.Fatalf("a refused request changed data: %d %v", n, err)
	}
}

func TestAppDataChannelRefusesPublicAndProxiedRequests(t *testing.T) {
	app := appDataTestApp(t)
	for name, mutate := range map[string]func(*http.Request){
		"remote peer":     func(r *http.Request) { r.RemoteAddr = "203.0.113.9:5000" },
		"router proxied":  func(r *http.Request) { r.Header.Set("X-Benmore-App", "myapp") },
		"forwarded":       func(r *http.Request) { r.Header.Set("X-Forwarded-For", "203.0.113.9") },
		"forwarded host":  func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "myapp.example.test") },
		"cloudflare":      func(r *http.Request) { r.Header.Set("CF-Connecting-IP", "203.0.113.9") },
		"probe marked":    func(r *http.Request) { r.Header.Set("X-Internal-Probe", "1") },
		"wrong method":    func(r *http.Request) { r.Method = http.MethodGet },
		"other spelling":  func(r *http.Request) { r.URL.Path = "/API/_internal/Data" },
		"trailing suffix": func(r *http.Request) { r.URL.Path = appDataRoute + "/x" },
	} {
		body := appDataTestBody(t, "count", appDataTestEditor, appDataCountArgs{})
		code, resp, header := appDataPost(app, appDataTestToken(app, body), body, mutate)
		if code == http.StatusOK || resp.OK || code == http.StatusTeapot || header.Get(appDataChannelHeader) != "1" {
			t.Errorf("%s: %d %+v", name, code, resp)
		}
	}
	// Other paths go to the app as before.
	req := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
	rec := httptest.NewRecorder()
	appDataChannelMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }), app).ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("ordinary request intercepted: %d", rec.Code)
	}
	for _, p := range []string{appDataRoute, "/api/_internal/data/", "/API/_INTERNAL/DATA", "//api/_internal/data", "/api/./_internal/data", "/api/_internal/data/../data"} {
		if !isAppDataChannelPath(p) {
			t.Errorf("isAppDataChannelPath(%q) = false", p)
		}
	}
	for _, p := range []string{"/api/_internal/database", "/api/_internal/mcp/connector", "/api/data"} {
		if isAppDataChannelPath(p) {
			t.Errorf("isAppDataChannelPath(%q) = true", p)
		}
	}
}

func TestAppDataViewerCannotWriteOrReadRows(t *testing.T) {
	app := appDataTestApp(t)
	for _, tc := range []struct {
		op   string
		args any
	}{
		{"exec", appDataExecArgs{SQL: "DELETE FROM notes"}},
		{"query", appDataQueryArgs{SQL: "SELECT * FROM notes"}},
		{"table_rows", appDataTableRowsArgs{Table: "notes"}},
	} {
		body := appDataTestBody(t, tc.op, appDataTestViewer, tc.args)
		code, resp := appDataDispatch(context.Background(), app, body)
		if code != http.StatusForbidden || resp.Error != "forbidden" {
			t.Errorf("viewer %s: %d %+v", tc.op, code, resp)
		}
	}
	// A viewer reads the schema.
	body := appDataTestBody(t, "schema", appDataTestViewer, appDataSchemaArgs{Columns: true})
	if code, resp := appDataDispatch(context.Background(), app, body); code != http.StatusOK || !resp.OK {
		t.Fatalf("viewer schema: %d %+v", code, resp)
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n); err != nil || n != 3 {
		t.Fatalf("viewer changed data: %d %v", n, err)
	}
}

func TestAppDataRequestValidation(t *testing.T) {
	app := appDataTestApp(t)
	cases := map[string]string{
		"unknown op":       `{"op":"drop_everything","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"request_id":"x"}`,
		"unknown field":    `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"request_id":"x","sudo":true}`,
		"unknown arg":      `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"args":{"tables":"crud","x":1},"request_id":"x"}`,
		"bad role":         `{"op":"count","actor":{"email":"a@b.c","role":"admin","surface":"mcp"},"request_id":"x"}`,
		"bad surface":      `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"cli"},"request_id":"x"}`,
		"no email":         `{"op":"count","actor":{"email":"","role":"owner","surface":"mcp"},"request_id":"x"}`,
		"bad request id":   `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"request_id":"a b"}`,
		"trailing data":    `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"request_id":"x"} {}`,
		"bad table set":    `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"args":{"tables":"everything"},"request_id":"x"}`,
		"query over limit": `{"op":"query","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"args":{"sql":"SELECT 1","limit":5000},"request_id":"x"}`,
		"query bad gate":   `{"op":"query","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"args":{"sql":"SELECT 1","gate":"none"},"request_id":"x"}`,
	}
	for name, body := range cases {
		code, resp := appDataDispatch(context.Background(), app, []byte(body))
		if code == http.StatusOK || resp.OK {
			t.Errorf("%s accepted: %d %+v", name, code, resp)
		}
	}
}

func TestAppDataQueryKeepsGatesAndMasking(t *testing.T) {
	app := appDataTestApp(t)
	run := func(args appDataQueryArgs) (int, appDataResponse) {
		return appDataDispatch(context.Background(), app, appDataTestBody(t, "query", appDataTestEditor, args))
	}
	for _, sql := range []string{"DELETE FROM notes", "SELECT 1; DELETE FROM notes", "ATTACH 'x.db' AS x", "SELECT load_extension('x')", "PRAGMA writable_schema=1"} {
		for _, gate := range []string{"query_db", "console"} {
			if code, resp := run(appDataQueryArgs{SQL: sql, Gate: gate}); resp.OK || resp.Error != "rejected" {
				t.Errorf("%s gate accepted %q: %d %+v", gate, sql, code, resp)
			}
		}
	}
	_, resp := run(appDataQueryArgs{SQL: "SELECT id FROM notes ORDER BY id", Limit: 2})
	var rows appDataRowsResult
	if !resp.OK || json.Unmarshal(resp.Result, &rows) != nil || len(rows.Rows) != 2 || !rows.Truncated || len(rows.Columns) != 1 {
		t.Fatalf("limited read: %+v %s", resp, resp.Result)
	}
	// Session ids read as NULL, exactly as query_db always returned them.
	_, resp = run(appDataQueryArgs{SQL: "SELECT id, user_id FROM _benmore_sessions"})
	if !resp.OK || !strings.Contains(string(resp.Result), `"id":null`) || strings.Contains(string(resp.Result), "live-session") {
		t.Fatalf("session id not masked: %s", resp.Result)
	}
	// The console's gate and table view.
	_, resp = run(appDataQueryArgs{SQL: "SELECT CAST('blob' AS BLOB) AS b;", Gate: "console", BytesAsText: true})
	if !resp.OK || !strings.Contains(string(resp.Result), `"b":"blob"`) {
		t.Fatalf("console bytes: %+v %s", resp, resp.Result)
	}
	_, resp = run(appDataQueryArgs{SQL: "SELECT nope FROM notes"})
	if resp.OK || resp.Error != "query_failed" || !strings.Contains(resp.Message, "nope") {
		t.Fatalf("failed query: %+v", resp)
	}
}

func TestAppDataExecAuditsInItsTransaction(t *testing.T) {
	app := appDataTestApp(t)
	body := appDataTestBody(t, "exec", appDataTestEditor, appDataExecArgs{SQL: "UPDATE notes SET title = 'secret-value' WHERE owner = 'a'"})
	code, resp := appDataDispatch(context.Background(), app, body)
	if code != http.StatusOK || !resp.OK {
		t.Fatalf("editor exec: %d %+v", code, resp)
	}
	var res appDataExecResult
	if err := json.Unmarshal(resp.Result, &res); err != nil || res.RowsAffected != 2 {
		t.Fatalf("exec result %s (%v)", resp.Result, err)
	}
	rows, err := QueryRows(app.DB, "SELECT action, table_name, user_email, new_values FROM _benmore_audit_log")
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit rows: %v %v", rows, err)
	}
	row := rows[0]
	values, _ := row["new_values"].(string)
	if row["action"] != "data_sql_write" || row["table_name"] != "notes" || row["user_email"] != "editor@test.com" ||
		!strings.Contains(values, `"rows_affected":2`) || !strings.Contains(values, `"surface":"mcp"`) || !strings.Contains(values, `"verb":"UPDATE"`) {
		t.Fatalf("audit row: %v", row)
	}
	if strings.Contains(values, "secret-value") {
		t.Fatalf("audit row records the statement text: %v", values)
	}
	// Refused statements change nothing and record nothing.
	for _, sql := range []string{"DROP TABLE notes", "DELETE FROM notes; DELETE FROM _benmore_audit_log", "ATTACH 'x' AS y", "SELECT load_extension('x')"} {
		_, resp := appDataDispatch(context.Background(), app, appDataTestBody(t, "exec", appDataTestEditor, appDataExecArgs{SQL: sql}))
		if resp.OK || resp.Error != "rejected" {
			t.Errorf("exec accepted %q: %+v", sql, resp)
		}
	}
	// A failing statement rolls back with its audit row.
	_, resp = appDataDispatch(context.Background(), app, appDataTestBody(t, "exec", appDataTestEditor, appDataExecArgs{SQL: "INSERT INTO notes(id, title) VALUES (1, 'dup')"}))
	if resp.OK || resp.Error != "exec_failed" {
		t.Fatalf("duplicate insert: %+v", resp)
	}
	var audits int
	_ = app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log").Scan(&audits)
	if audits != 1 {
		t.Fatalf("audit rows after refusals = %d, want 1", audits)
	}
}

// The insert id SQLite reports belongs to the connection, so an UPDATE on a
// connection that inserted before reported that old id. And a WITH-prefixed
// write was audited with no table.
func TestAppDataExecInsertIDAndWithTarget(t *testing.T) {
	app := appDataTestApp(t)
	app.DB.SetMaxOpenConns(1) // one connection: the earlier insert's id is still on it
	exec := func(sql string) appDataExecResult {
		t.Helper()
		_, resp := appDataDispatch(context.Background(), app, appDataTestBody(t, "exec", appDataTestEditor, appDataExecArgs{SQL: sql}))
		var res appDataExecResult
		if !resp.OK || json.Unmarshal(resp.Result, &res) != nil {
			t.Fatalf("exec %q: %+v", sql, resp)
		}
		return res
	}
	inserted := exec("INSERT INTO notes(id, title, owner) VALUES (90, 'n', 'a')")
	if inserted.LastInsertID != 90 {
		t.Fatalf("insert reported last_insert_id %d, want 90", inserted.LastInsertID)
	}
	if updated := exec("UPDATE notes SET title = 't' WHERE owner = 'a'"); updated.LastInsertID != 0 || updated.RowsAffected == 0 {
		t.Fatalf("update reported %+v, want rows and no insert id", updated)
	}
	exec("WITH t AS (SELECT 'a' AS o) UPDATE notes SET title = 'w' WHERE owner IN (SELECT o FROM t)")
	var table string
	if err := app.DB.QueryRow("SELECT table_name FROM _benmore_audit_log ORDER BY id DESC LIMIT 1").Scan(&table); err != nil || table != "notes" {
		t.Fatalf("WITH write audited table %q (%v), want notes", table, err)
	}
}

func TestAppDataSchemaAndTableRows(t *testing.T) {
	app := appDataTestApp(t)
	_, resp := appDataDispatch(context.Background(), app, appDataTestBody(t, "schema", appDataTestViewer, appDataSchemaArgs{Tables: "all", Columns: true, Counts: true}))
	var schema appDataSchemaResult
	if !resp.OK || json.Unmarshal(resp.Result, &schema) != nil {
		t.Fatalf("schema: %+v", resp)
	}
	found := false
	for _, table := range schema.Tables {
		if table.Name == "notes" {
			found = true
			if table.Rows == nil || *table.Rows != 3 || len(table.Columns) != 3 || !table.Columns[0].PK {
				t.Fatalf("notes schema: %+v", table)
			}
		}
	}
	if !found {
		t.Fatalf("notes missing from %+v", schema.Tables)
	}
	_, resp = appDataDispatch(context.Background(), app, appDataTestBody(t, "table_rows", appDataTestEditor, appDataTableRowsArgs{
		Table: "notes", Columns: []string{"id", "title"}, Where: map[string]string{"owner": "a"}, OrderBy: "id", Desc: true, Limit: 1,
	}))
	var page appDataRowsResult
	if !resp.OK || json.Unmarshal(resp.Result, &page) != nil || len(page.Rows) != 1 || !page.Truncated {
		t.Fatalf("table rows: %+v %s", resp, resp.Result)
	}
	if id, _ := page.Rows[0]["id"].(float64); id != 3 {
		t.Fatalf("table rows order/filter: %v", page.Rows)
	}
	for name, args := range map[string]appDataTableRowsArgs{
		"unknown table":     {Table: "missing"},
		"injected table":    {Table: `notes" --`},
		"unknown column":    {Table: "notes", Columns: []string{"id; DROP TABLE notes"}},
		"unknown filter":    {Table: "notes", Where: map[string]string{"1=1 OR id": "1"}},
		"unknown order":     {Table: "notes", OrderBy: "id DESC; --"},
		"limit over cap":    {Table: "notes", Limit: appDataTableRowsMax + 1},
		"negative offset":   {Table: "notes", Offset: -1},
		"framework secrets": {Table: "_benmore_sessions", Where: map[string]string{"nope": "x"}},
	} {
		if _, resp := appDataDispatch(context.Background(), app, appDataTestBody(t, "table_rows", appDataTestEditor, args)); resp.OK {
			t.Errorf("%s accepted: %s", name, resp.Result)
		}
	}
	// Framework credential columns read as NULL through table_rows too.
	_, resp = appDataDispatch(context.Background(), app, appDataTestBody(t, "table_rows", appDataTestEditor, appDataTableRowsArgs{Table: "_benmore_sessions"}))
	if !resp.OK || strings.Contains(string(resp.Result), "live-session") {
		t.Fatalf("table_rows exposed a session id: %s", resp.Result)
	}
}

func TestAppDataRegistryShape(t *testing.T) {
	for _, name := range appDataOpNames() {
		op, _ := lookupAppDataOp(name)
		if op.Mutating && appDataRoles[op.MinRole] < appDataRoles["editor"] {
			t.Errorf("%s mutates with min role %s", name, op.MinRole)
		}
	}
	for _, want := range []string{"query", "exec", "schema", "count", "table_rows"} {
		if _, ok := lookupAppDataOp(want); !ok {
			t.Errorf("operation %s not registered", want)
		}
	}
}

// An older runtime answers a newer router's operation or argument with
// "unsupported" (nothing ran), so the router can fall back during a rollout.
func TestAppDataUnknownOperationOrArgumentIsUnsupported(t *testing.T) {
	app := appDataTestApp(t)
	for name, body := range map[string]string{
		"unknown op":    `{"op":"from_the_future","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"request_id":"x"}`,
		"unknown arg":   `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"args":{"tables":"crud","since_v9":true},"request_id":"x"}`,
		"unknown field": `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"request_id":"x","v9":1}`,
		// A role or surface added by a newer router.
		"unknown role":    `{"op":"count","actor":{"email":"a@b.c","role":"auditor","surface":"mcp"},"request_id":"x"}`,
		"unknown surface": `{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"cli"},"request_id":"x"}`,
	} {
		code, resp := appDataDispatch(context.Background(), app, []byte(body))
		if code != http.StatusNotImplemented || resp.Error != "unsupported" {
			t.Errorf("%s: %d %+v", name, code, resp)
		}
	}
	// A malformed value is still a bad request.
	code, resp := appDataDispatch(context.Background(), app, []byte(`{"op":"count","actor":{"email":"a@b.c","role":"owner","surface":"mcp"},"args":{"tables":7},"request_id":"x"}`))
	if code != http.StatusBadRequest || resp.Error != "bad_request" {
		t.Fatalf("malformed argument: %d %+v", code, resp)
	}
}

// Channel operations share a small per-app budget, so platform reads cannot
// take every connection the app's own traffic needs.
func TestAppDataOperationsAreBoundedPerApp(t *testing.T) {
	app := appDataTestApp(t)
	slots := appDataSlotsFor(app)
	for i := 0; i < cap(slots); i++ {
		slots <- struct{}{}
	}
	defer func() {
		for len(slots) > 0 {
			<-slots
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	code, resp := appDataDispatch(ctx, app, appDataTestBody(t, "count", appDataTestViewer, appDataCountArgs{}))
	if code != http.StatusServiceUnavailable || resp.Error != "busy" {
		t.Fatalf("over-budget call: %d %+v", code, resp)
	}
	<-slots
	if code, resp = appDataDispatch(context.Background(), app, appDataTestBody(t, "count", appDataTestViewer, appDataCountArgs{})); code != http.StatusOK {
		t.Fatalf("call with a free slot: %d %+v", code, resp)
	}
}

// Every answer to an accepted token carries a MAC over the nonce and the
// exact body; refusals before the token was accepted carry none.
func TestAppDataAnswersAreAuthenticated(t *testing.T) {
	app := appDataTestApp(t)
	body := appDataTestBody(t, "count", appDataTestViewer, appDataCountArgs{})
	nonce := appDataNonce16()
	token := mintAppDataToken(app.Dir, time.Now().Add(30*time.Second), appDataTestSecret, nonce, body)
	req := httptest.NewRequest(http.MethodPost, appDataRoute, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set(appDataTokenHeader, token)
	rec := httptest.NewRecorder()
	appDataChannelMiddleware(http.NotFoundHandler(), app).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get(appDataMACHeader) != appDataResponseMAC(appDataTestSecret, nonce, rec.Body.Bytes()) {
		t.Fatalf("answer MAC: %d %q", rec.Code, rec.Header().Get(appDataMACHeader))
	}
	if appDataResponseMAC(appDataTestSecret, nonce+"x", rec.Body.Bytes()) == rec.Header().Get(appDataMACHeader) {
		t.Fatal("MAC does not bind the nonce")
	}
	_, _, header := appDataPost(app, "", body, nil)
	if header.Get(appDataMACHeader) != "" {
		t.Fatal("a refusal before the token check carried a MAC")
	}
}
