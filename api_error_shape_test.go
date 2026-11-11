//go:build !cli

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// apiErrorShapeApp: services readable by every signed-in user but writable
// only by staff, secrets with no rule (admin-only), bookings on the tenant
// key, notes owner-scoped.
func apiErrorShapeApp(t *testing.T) *App {
	t.Helper()
	app := newGateApp(t,
		"CREATE TABLE services (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)",
		"CREATE TABLE secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)",
		"CREATE TABLE members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, email TEXT)",
		"CREATE TABLE bookings (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, notes TEXT)",
		"CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT)",
		"INSERT INTO services (name) VALUES ('cut')",
	)
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "email", Bootstrap: &GroupBootstrapConfig{}}
	app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{
		"services": {OpRead: "everyone", OpWrite: "role:staff", OpUpdate: "role:staff", OpDelete: "role:staff"},
		"bookings": {"all": "group"},
	}}
	return app
}

func decodeJSONAnswer(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("answer %d is %q, not JSON: %q", w.Code, ct, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("answer %d is not one JSON object: %v %q", w.Code, err, w.Body.String())
	}
	return body
}

// Round 2 B15: a client POSTing to a staff-only table answered 404 "no API
// route matches this path" although GET on the same route worked. A write
// refused on a table the caller may read now answers 403 saying it is an
// access rule. A table the caller may not read still answers the very bytes
// an unmatched path does, so the change is no existence oracle; that shared
// message now names both causes.
func TestCRUDDenialSaysWhatItIsWithoutAnExistenceOracle(t *testing.T) {
	app := apiErrorShapeApp(t)
	_, sid := gateUser(t, app, "client@example.com")

	if w := gateCall(app, handleList, "services", "GET", "/api/services", "application/json", "", sid); w.Code != http.StatusOK {
		t.Fatalf("readable table list %d %s", w.Code, w.Body.String())
	}
	for _, c := range []struct {
		handler      func(http.ResponseWriter, *http.Request, *App, string)
		method, path string
		action       string
	}{
		{handleCreate, "POST", "/api/services", "create rows in services"},
		{handleUpdate, "PATCH", "/api/services/1", "change rows in services"},
		{handleDelete, "DELETE", "/api/services/1", "delete rows from services"},
	} {
		w := gateCall(app, c.handler, "services", c.method, c.path, "application/json", `{"name":"x"}`, sid)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s on a readable staff-only table: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
		body := decodeJSONAnswer(t, w)
		msg, _ := body["message"].(string)
		if body["error"] != "forbidden" || !strings.Contains(msg, c.action) || !strings.Contains(msg, "access") {
			t.Fatalf("%s %s denial body %v", c.method, c.path, body)
		}
		if strings.Contains(w.Body.String(), "staff") {
			t.Fatalf("denial names the role that would allow it: %s", w.Body.String())
		}
	}
	if got := gateScalar(t, app, "SELECT name FROM services WHERE id = 1"); got != "cut" {
		t.Fatalf("refused write changed the row: %q", got)
	}

	// A table the caller cannot read answers exactly what an unmatched /api
	// path answers, for reads and writes alike.
	unmatched := httptest.NewRecorder()
	notFoundHandler(app)(unmatched, httptest.NewRequest("POST", "https://app.example.com/api/no_such_table", strings.NewReader("{}")))
	if unmatched.Code != http.StatusNotFound || unmatched.Body.String() != unmatchedAPINotFoundBody {
		t.Fatalf("unmatched path answer %d %q", unmatched.Code, unmatched.Body.String())
	}
	if msg, _ := decodeJSONAnswer(t, unmatched)["message"].(string); !strings.Contains(msg, "access rules") {
		t.Fatalf("unmatched message does not name the access-rule cause: %q", msg)
	}
	for _, c := range []struct {
		handler      func(http.ResponseWriter, *http.Request, *App, string)
		method, path string
	}{
		{handleList, "GET", "/api/secrets"},
		{handleCreate, "POST", "/api/secrets"},
		{handleUpdate, "PATCH", "/api/secrets/1"},
		{handleDelete, "DELETE", "/api/secrets/1"},
	} {
		w := gateCall(app, c.handler, "secrets", c.method, c.path, "application/json", `{"name":"x"}`, sid)
		if w.Code != unmatched.Code || w.Body.String() != unmatched.Body.String() {
			t.Fatalf("%s %s on an unreadable table differs from an unmatched path: %d %q", c.method, c.path, w.Code, w.Body.String())
		}
	}

	// A tenant-less caller on a tenant-keyed table lists an empty page and is
	// told why its write was refused.
	if w := gateCall(app, handleList, "bookings", "GET", "/api/bookings", "application/json", "", sid); w.Code != http.StatusOK {
		t.Fatalf("tenant-less list %d %s", w.Code, w.Body.String())
	}
	w := gateCall(app, handleCreate, "bookings", "POST", "/api/bookings", "application/json", `{"notes":"x"}`, sid)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant-less create %d %s", w.Code, w.Body.String())
	}
	if hint, _ := decodeJSONAnswer(t, w)["hint"].(string); !strings.Contains(hint, "tenant") || !strings.Contains(hint, "/api/_groups/create") {
		t.Fatalf("tenant-less create hint %q", hint)
	}
}

// Round 2 B15: /api error bodies were JSON on some routes, text on others
// (a single-row 404, a flow input refusal, an auto-CRUD list failure) and
// both on a failed flow. They are JSON now; a page route keeps its text.
func TestAPIErrorBodiesAreJSON(t *testing.T) {
	app := apiErrorShapeApp(t)
	_, sid := gateUser(t, app, "reader@example.com")

	w := gateCall(app, handleRead, "notes", "GET", "/api/notes/999", "application/json", "", sid)
	if body := decodeJSONAnswer(t, w); w.Code != http.StatusNotFound || body["error"] != "Not found" {
		t.Fatalf("missing row %d %v", w.Code, body)
	}
	w = gateCall(app, handleUpdate, "notes", "PATCH", "/api/notes/abc", "application/json", `{"body":"x"}`, "no-such-session")
	if w.Code < 400 {
		t.Fatalf("bad update %d", w.Code)
	}
	decodeJSONAnswer(t, w)

	flow := &Flow{Name: "quote", Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/quote",
		Inputs: map[string]FlowInput{"hours": {Type: "number", Required: true}}},
		Steps: []FlowStep{{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}}}}
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/quote", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	_ = executeFlowHTTP(app, flow, w, r)
	if body := decodeJSONAnswer(t, w); w.Code != http.StatusUnprocessableEntity || body["error"] != `flow input "hours" is required` {
		t.Fatalf("flow input refusal %d %v", w.Code, body)
	}

	for path, wantJSON := range map[string]bool{"/api/widgets": true, "/reports": false} {
		w := httptest.NewRecorder()
		captureLog(t, func() {
			serverError(w, httptest.NewRequest("GET", "https://app.example.com"+path, nil), app, "probe", errors.New("no such table: widgets"), "list failed")
		})
		id := w.Header().Get(requestIDHeader)
		if wantJSON {
			body := decodeJSONAnswer(t, w)
			if w.Code != 500 || body["error"] != "list failed" || body["request_id"] != id {
				t.Fatalf("%s server error %d %v", path, w.Code, body)
			}
		} else if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") || !strings.Contains(w.Body.String(), "list failed (request id: "+id+")") {
			t.Fatalf("%s server error changed: %q %q", path, ct, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "no such table") {
			t.Fatalf("%s server error leaked the detail: %s", path, w.Body.String())
		}
	}
}
