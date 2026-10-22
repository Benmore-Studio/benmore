//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// serverErrorFixture runs real handlers behind the request log middleware so
// a test sees what the caller got, what the journal got and what the request
// log row holds.
type serverErrorFixture struct {
	t       *testing.T
	app     *App
	sid     string
	handler func(http.ResponseWriter, *http.Request)
	logged  http.Handler
}

func newServerErrorFixture(t *testing.T, dev bool) *serverErrorFixture {
	t.Helper()
	app := newGateApp(t,
		"CREATE TABLE widgets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT)",
		"CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT)")
	app.DevMode = dev
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	uid, sid := gateUser(t, app, "owner@example.com")
	mustExec(t, app.DB, "INSERT INTO widgets (user_id, name) VALUES ("+strconv.FormatInt(uid, 10)+", 'one')")
	f := &serverErrorFixture{t: t, app: app, sid: sid}
	f.logged = requestLogMiddleware(app, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.handler(w, r) }))
	return f
}

// breakStorage makes the list, count and read queries on widgets fail after
// the column cache was filled, and every audit insert fail, as a broken
// deploy would.
func (f *serverErrorFixture) breakStorage() {
	mustExec(f.t, f.app.DB, "DROP TABLE widgets")
	mustExec(f.t, f.app.DB, "CREATE TRIGGER audit_broken BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT, 'audit trigger refused the row'); END")
}

func (f *serverErrorFixture) call(handler func(http.ResponseWriter, *http.Request), method, path, body string) (*httptest.ResponseRecorder, string) {
	f.t.Helper()
	f.handler = handler
	r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.sid)
	w := httptest.NewRecorder()
	out := captureLog(f.t, func() { f.logged.ServeHTTP(w, r) })
	return w, out
}

type requestLogRow struct {
	path, errDetail, requestID string
	status                     int
}

// rows flushes the request log writer and returns every row in order.
func (f *serverErrorFixture) rows() []requestLogRow {
	f.t.Helper()
	close(f.app.Stop)
	f.app.workerWG.Wait()
	rs, err := f.app.DB.Query("SELECT path, status, COALESCE(error,''), COALESCE(request_id,'') FROM _benmore_request_log ORDER BY id")
	if err != nil {
		f.t.Fatal(err)
	}
	defer rs.Close()
	var out []requestLogRow
	for rs.Next() {
		var row requestLogRow
		if err := rs.Scan(&row.path, &row.status, &row.errDetail, &row.requestID); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, row)
	}
	return out
}

var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// A server error from a built-in data route (list, count, read, batch,
// /api/_transaction) and from a flow is kept server-side: the request log row
// carries the full detail and the request id, and one journal line has both.
// Outside dev mode the caller gets the route's generic text and the request
// id, never SQLite's text; dev mode keeps the full text. Before, the list and
// count routes sent the raw SQLite error to every caller and nothing was
// recorded, so a failure could not be diagnosed afterwards.
func TestServerErrorsAreRecordedAndProductionAnswersAreGeneric(t *testing.T) {
	for _, dev := range []bool{false, true} {
		name := "production"
		if dev {
			name = "dev"
		}
		t.Run(name, func(t *testing.T) {
			f := newServerErrorFixture(t, dev)
			f.breakStorage()
			flow := &Flow{Name: "broken-flow", Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/broken-flow"},
				Steps: []FlowStep{{Name: "lookup", Type: "sql", SQL: `SELECT name FROM missing_flow_table`}}}

			type call struct {
				name, method, path, body string
				handler                  func(http.ResponseWriter, *http.Request)
				status                   int
				json                     bool   // the answer is a JSON error object
				public                   string // generic text a production caller gets
				detail                   string // what only the server side (and dev mode) may hold
				where                    string // the label of the request log row and journal line
			}
			calls := []call{
				{name: "list", method: "GET", path: "/api/widgets", status: 500, public: "list failed", detail: "no such table: widgets", where: "[widgets list]",
					handler: func(w http.ResponseWriter, r *http.Request) { handleList(w, r, f.app, "widgets") }},
				{name: "count", method: "GET", path: "/api/widgets?count=true", status: 500, public: "count failed", detail: "no such table: widgets", where: "[widgets count]",
					handler: func(w http.ResponseWriter, r *http.Request) { handleList(w, r, f.app, "widgets") }},
				{name: "batch create", method: "POST", path: "/api/notes/batch", body: `[{"body":"a"}]`, status: 500,
					public: "Batch insert failed: audit write failed", detail: "audit trigger refused the row", where: "[notes batch create]",
					handler: func(w http.ResponseWriter, r *http.Request) { handleBatchCreate(w, r, f.app, "notes") }},
				{name: "transaction", method: "POST", path: "/api/_transaction", body: `{"operations":[{"table":"notes","action":"insert","data":{"body":"tx"}}]}`, status: 500, json: true,
					public: "audit write failed", detail: "audit trigger refused the row", where: "[_transaction insert notes]",
					handler: func(w http.ResponseWriter, r *http.Request) { handleTransaction(w, r, f.app) }},
				{name: "flow", method: "POST", path: "/api/broken-flow", status: 500,
					public: "Internal error", detail: "no such table: missing_flow_table", where: "[flow broken-flow]",
					handler: func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(f.app, flow, w, r) }},
			}
			ids := map[string]string{}
			for _, c := range calls {
				w, journal := f.call(c.handler, c.method, c.path, c.body)
				body := w.Body.String()
				if w.Code != c.status {
					t.Fatalf("%s: status %d, want %d: %s", c.name, w.Code, c.status, body)
				}
				id := w.Header().Get(requestIDHeader)
				if !requestIDPattern.MatchString(id) {
					t.Fatalf("%s: X-Request-Id %q is not a request id", c.name, id)
				}
				ids[c.name] = id
				if c.json {
					var got map[string]any
					if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
						t.Fatalf("%s: JSON shape lost: %v %s", c.name, err, body)
					}
					if got["request_id"] != id {
						t.Fatalf("%s: request_id %v, want %s", c.name, got["request_id"], id)
					}
					msg, _ := got["error"].(string)
					if !strings.HasPrefix(msg, c.public) {
						t.Fatalf("%s: error key %q lost the route's text %q", c.name, msg, c.public)
					}
				}
				if dev {
					if !strings.Contains(body, c.detail) {
						t.Fatalf("%s: dev mode must keep the full error text %q: %s", c.name, c.detail, body)
					}
				} else {
					if strings.Contains(body, c.detail) || strings.Contains(body, "SQL") || strings.Contains(body, "no such") {
						t.Fatalf("%s: production answer carries the server-side detail: %s", c.name, body)
					}
					if !c.json && !strings.Contains(body, c.public+" (request id: "+id+")") {
						t.Fatalf("%s: production answer %q lacks the generic text and request id", c.name, body)
					}
				}
				if !strings.Contains(journal, id) || !strings.Contains(journal, c.detail) {
					t.Fatalf("%s: journal has no line with the request id and detail:\n%s", c.name, journal)
				}
				if c.name != "flow" && !strings.Contains(journal, "SERVER ERROR "+c.where+" "+c.method+" "+strings.SplitN(c.path, "?", 2)[0]+" (request "+id+"): ") {
					t.Fatalf("%s: SERVER ERROR line missing or misshapen:\n%s", c.name, journal)
				}
			}

			// The failed flow's answer also names the failing step and its
			// request id in the flow_no_response diagnostic.
			rows := f.rows()
			if len(rows) != len(calls) {
				t.Fatalf("request log has %d rows, want %d: %+v", len(rows), len(calls), rows)
			}
			for i, c := range calls {
				row := rows[i]
				if row.status != c.status || row.requestID != ids[c.name] {
					t.Fatalf("%s: logged status %d id %q, want %d %q", c.name, row.status, row.requestID, c.status, ids[c.name])
				}
				if !strings.HasPrefix(row.errDetail, c.where+" ") || !strings.Contains(row.errDetail, c.detail) {
					t.Fatalf("%s: request log error %q lacks %s and %q", c.name, row.errDetail, c.where, c.detail)
				}
				if strings.ContainsAny(row.errDetail, "\n\r") {
					t.Fatalf("%s: request log error is not one line: %q", c.name, row.errDetail)
				}
			}
			if flowRow := rows[len(rows)-1]; !strings.Contains(flowRow.errDetail, `failed_step="lookup"`) || !strings.Contains(flowRow.errDetail, "hint=") {
				t.Fatalf("failed flow row lacks the failing step and hint: %q", flowRow.errDetail)
			}
		})
	}
}

// A single-record read whose query fails still answers the 404 it always has
// (a 4xx is unchanged), but the failure is recorded with a request id instead
// of disappearing.
func TestReadQueryFailureIsRecordedAndStill404(t *testing.T) {
	f := newServerErrorFixture(t, false)
	f.breakStorage()
	w, journal := f.call(func(w http.ResponseWriter, r *http.Request) { handleRead(w, r, f.app, "widgets") }, "GET", "/api/widgets/1", "")
	if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != "Not found" {
		t.Fatalf("read answer changed: %d %q", w.Code, w.Body.String())
	}
	id := w.Header().Get(requestIDHeader)
	if !requestIDPattern.MatchString(id) || !strings.Contains(journal, "SERVER ERROR [widgets read] GET /api/widgets/1 (request "+id+"): no such table: widgets") {
		t.Fatalf("read failure not in the journal (id %q):\n%s", id, journal)
	}
	rows := f.rows()
	if len(rows) != 1 || rows[0].status != http.StatusNotFound || rows[0].requestID != id || !strings.Contains(rows[0].errDetail, "no such table: widgets") {
		t.Fatalf("read failure not in the request log: %+v", rows)
	}
}

// A respond step whose template does not resolve answers its documented
// template_unresolved envelope, now with the request id, and the halt is in
// the request log.
func TestFlowTemplateUnresolvedIsRecorded(t *testing.T) {
	f := newServerErrorFixture(t, false)
	flow := &Flow{Name: "unresolved", Trigger: FlowTrigger{Type: "http", Method: http.MethodGet, Path: "/api/unresolved"},
		Steps: []FlowStep{{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "{{steps.nope.outputs}}"}}}}
	w, _ := f.call(func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(f.app, flow, w, r) }, "GET", "/api/unresolved", "")
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 500 || got["error"] != "template_unresolved" {
		t.Fatalf("template_unresolved envelope changed: %d %s", w.Code, w.Body.String())
	}
	id := w.Header().Get(requestIDHeader)
	if got["request_id"] != id || !requestIDPattern.MatchString(id) {
		t.Fatalf("envelope request_id %v, header %q", got["request_id"], id)
	}
	rows := f.rows()
	if len(rows) != 1 || rows[0].requestID != id || !strings.Contains(rows[0].errDetail, "template_unresolved: steps.nope.outputs") {
		t.Fatalf("template_unresolved not in the request log: %+v", rows)
	}
}

// A handler panic unwinds past the request log middleware; the request still
// gets its log line (status 500, the panic as its error) and the recovery page
// quotes the request id.
func TestPanicIsRecordedInRequestLog(t *testing.T) {
	f := newServerErrorFixture(t, false)
	handler := recoverMiddleware(f.logged)
	f.handler = func(http.ResponseWriter, *http.Request) { panic("handler exploded") }
	w := httptest.NewRecorder()
	captureLog(t, func() { handler.ServeHTTP(w, httptest.NewRequest("GET", "https://app.example.com/boom", nil)) })
	id := w.Header().Get(requestIDHeader)
	if w.Code != 500 || !requestIDPattern.MatchString(id) || !strings.Contains(w.Body.String(), "Request id: "+id) {
		t.Fatalf("panic answer: %d id %q %s", w.Code, id, w.Body.String())
	}
	rows := f.rows()
	if len(rows) != 1 || rows[0].status != 500 || rows[0].requestID != id || rows[0].errDetail != "panic: handler exploded" {
		t.Fatalf("panic not in the request log: %+v", rows)
	}
}

// What an error text may carry is cut to one bounded line and stripped of
// credential-shaped text before it reaches the request log or the journal.
func TestServerErrorTextIsOneBoundedRedactedLine(t *testing.T) {
	cases := map[string]string{
		`Get "https://api.example.com/v1/items?api_key=abc123&x=1": dial tcp: timeout`:              "https://api.example.com/v1/items?[redacted]",
		"upstream said: Authorization: Bearer eyJhbGciOi.abcdefghijk.lmnopqrstuv was refused":       "Authorization: [redacted]",
		"retry with Bearer abcdefghijklmnop":                                                        "Bearer [redacted]",
		"postgres://admin:hunter2@db.internal/app unreachable":                                      "postgres://[redacted]@db.internal",
		"token=bmr_" + strings.Repeat("ab12", 16) + " rejected":                                     "token=[redacted]",
		"session " + strings.Repeat("0f", 32) + " not found":                                        "session [redacted] not found",
		`converting driver.Value type string ("$2a$12$` + strings.Repeat("A", 53) + `") to a int64`: "[redacted]",
		"stripe: sk_live_" + strings.Repeat("Z", 24) + " invalid":                                   "stripe: [redacted] invalid",
		`config {"client_secret": "s3cr3t-value", "name": "x"}`:                                     `"client_secret": [redacted]`,
		"column value enc:v2:QUJDREVGR0hJSktMTU5PUA== could not be read":                            "column value [redacted] could not be read",
		"UNIQUE constraint failed: notes.slug":                                                      "UNIQUE constraint failed: notes.slug",
		"no such column: password_hash":                                                             "no such column: password_hash",
	}
	for in, want := range cases {
		got := serverErrorText(in)
		if !strings.Contains(got, want) {
			t.Errorf("serverErrorText(%q) = %q, want it to contain %q", in, got, want)
		}
		for _, secret := range []string{"abc123", "hunter2", "s3cr3t-value", "eyJhbGciOi", strings.Repeat("ab12", 16), strings.Repeat("0f", 32)} {
			if strings.Contains(got, secret) {
				t.Errorf("serverErrorText(%q) kept %q: %q", in, secret, got)
			}
		}
	}
	long := serverErrorText("line one\nline two\r\n" + strings.Repeat("x", 5000))
	if strings.ContainsAny(long, "\n\r") || len(long) > serverErrorDetailMax {
		t.Fatalf("detail not one bounded line: %d bytes %q", len(long), long[:40])
	}
}

// A list whose caller went away mid-query is recorded in its request log row
// but writes no journal line: an abandoned request is not a server fault, and
// clients that abort fetches would otherwise flood the journal.
func TestCancelledRequestIsNotAJournalError(t *testing.T) {
	f := newServerErrorFixture(t, false)
	f.handler = func(w http.ResponseWriter, r *http.Request) { handleList(w, r, f.app, "widgets") }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("GET", "https://app.example.com/api/widgets", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+f.sid)
	w := httptest.NewRecorder()
	journal := captureLog(t, func() { f.logged.ServeHTTP(w, r) })
	if strings.Contains(journal, "SERVER ERROR") {
		t.Fatalf("a cancelled request wrote a journal error:\n%s", journal)
	}
	rows := f.rows()
	if len(rows) != 1 || !strings.Contains(rows[0].errDetail, "context canceled") {
		t.Fatalf("cancelled request not in its request log row: %+v", rows)
	}
}
