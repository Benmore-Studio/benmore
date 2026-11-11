//go:build !cli

package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The scheduled-task, approval and saved-view writes called validateCSRF
// directly, so a Bearer client (CLI, native app, server) got 403 "invalid
// CSRF token" on every one of them, although the documented rule (and every
// other app API write) exempts Bearer requests. These tests pin both halves:
// a Bearer-only request needs no token, and any request that carries the
// session cookie still does, whatever Authorization header rides along.

type internalCSRFFixture struct {
	app            *App
	mux            *http.ServeMux
	aliceID, bobID int64
	aliceSession   string
	bobSession     string
	aliceAPIToken  string
}

func newInternalCSRFFixture(t *testing.T) *internalCSRFFixture {
	t.Helper()
	old := approvalRequestLimiter
	approvalRequestLimiter = NewRateLimiter(approvalRequestBurst, approvalRequestWindow)
	t.Cleanup(func() { approvalRequestLimiter = old })

	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour}
	t.Cleanup(app.Shutdown)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsureNotificationsTable(app.DB)
	EnsureSchedulingTables(app.DB)
	EnsureSavedViewsTable(app.DB)

	f := &internalCSRFFixture{app: app}
	for _, u := range []struct {
		name string
		id   *int64
		tok  *string
	}{{"alice", &f.aliceID, &f.aliceSession}, {"bob", &f.bobID, &f.bobSession}} {
		email := u.name + "@example.com"
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, 'user', 1)", u.name, email)
		if err != nil {
			t.Fatal(err)
		}
		*u.id, _ = res.LastInsertId()
		*u.tok = CreateSession(app.DB, *u.id, email, "", time.Hour)
	}
	f.aliceAPIToken = "bmr_" + strings.Repeat("a", 40)
	if _, err := app.DB.Exec("INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'cli', ?, '*')", f.aliceID, hashToken(f.aliceAPIToken)); err != nil {
		t.Fatal(err)
	}

	f.mux = http.NewServeMux()
	registerSchedulingAPI(f.mux, app)
	registerQueryAPI(f.mux, app)
	return f
}

// call sends one request; prep sets the credential headers.
func (f *internalCSRFFixture) call(t *testing.T, method, path string, body any, prep func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	prep(req)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func bearerOnly(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func responseID(t *testing.T, rec *httptest.ResponseRecorder) int64 {
	t.Helper()
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.ID == 0 {
		t.Fatalf("response has no id: %d %s", rec.Code, rec.Body.String())
	}
	return out.ID
}

func (f *internalCSRFFixture) scalar(t *testing.T, q string, args ...any) string {
	t.Helper()
	var v sql.NullString
	if err := f.app.DB.QueryRow(q, args...).Scan(&v); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	return v.String
}

// state is every row the six endpoints can write, so a refused request can
// be shown to have changed nothing.
func (f *internalCSRFFixture) state(t *testing.T) string {
	t.Helper()
	return strings.Join([]string{
		f.scalar(t, "SELECT group_concat(id||':'||user_id||':'||status, ',') FROM (SELECT * FROM _benmore_scheduled_tasks ORDER BY id)"),
		f.scalar(t, "SELECT group_concat(id||':'||requested_by||':'||status, ',') FROM (SELECT * FROM _benmore_approvals ORDER BY id)"),
		f.scalar(t, "SELECT group_concat(id||':'||user_id||':'||name, ',') FROM (SELECT * FROM _benmore_saved_views ORDER BY id)"),
	}, " | ")
}

func TestInternalAPIBearerWritesSkipCSRF(t *testing.T) {
	f := newInternalCSRFFixture(t)
	for _, cred := range []struct{ name, token string }{
		{"session token", f.aliceSession},
		{"persistent API token", f.aliceAPIToken},
	} {
		t.Run(cred.name, func(t *testing.T) {
			as := bearerOnly(cred.token)

			rec := f.call(t, http.MethodPost, "/api/_scheduled", map[string]any{"kind": "reminder", "title": "call back", "run_at": "1h"}, as)
			if rec.Code != http.StatusOK {
				t.Fatalf("Bearer POST /api/_scheduled: %d %s", rec.Code, rec.Body.String())
			}
			task := responseID(t, rec)
			if got := f.scalar(t, "SELECT user_id||':'||status||':'||title FROM _benmore_scheduled_tasks WHERE id = ?", task); got != fmt.Sprintf("%d:pending:call back", f.aliceID) {
				t.Fatalf("scheduled task row = %q", got)
			}
			if rec := f.call(t, http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", task), nil, as); rec.Code != http.StatusOK {
				t.Fatalf("Bearer DELETE /api/_scheduled: %d %s", rec.Code, rec.Body.String())
			}
			if got := f.scalar(t, "SELECT status FROM _benmore_scheduled_tasks WHERE id = ?", task); got != "cancelled" {
				t.Fatalf("Bearer DELETE left the task %q", got)
			}

			rec = f.call(t, http.MethodPost, "/api/_approvals", map[string]any{
				"table": "expense", "row_id": cred.name, "approver_email": "bob@example.com", "title": "Approve " + cred.name,
			}, as)
			if rec.Code != http.StatusOK {
				t.Fatalf("Bearer POST /api/_approvals: %d %s", rec.Code, rec.Body.String())
			}
			approval := responseID(t, rec)
			if got := f.scalar(t, "SELECT requested_by||':'||approver_id||':'||status FROM _benmore_approvals WHERE id = ?", approval); got != fmt.Sprintf("%d:%d:pending", f.aliceID, f.bobID) {
				t.Fatalf("approval row = %q", got)
			}
			if rec := f.call(t, http.MethodPost, fmt.Sprintf("/api/_approvals/%d/decide", approval), map[string]any{"decision": "approved"}, bearerOnly(f.bobSession)); rec.Code != http.StatusOK {
				t.Fatalf("Bearer POST /api/_approvals/{id}/decide: %d %s", rec.Code, rec.Body.String())
			}
			if got := f.scalar(t, "SELECT status FROM _benmore_approvals WHERE id = ?", approval); got != "approved" {
				t.Fatalf("Bearer decide left the approval %q", got)
			}

			rec = f.call(t, http.MethodPost, "/api/_query/views", map[string]any{"name": "open " + cred.name, "spec": map[string]any{"table": "expense"}}, as)
			if rec.Code != http.StatusOK {
				t.Fatalf("Bearer POST /api/_query/views: %d %s", rec.Code, rec.Body.String())
			}
			view := responseID(t, rec)
			if got := f.scalar(t, "SELECT user_id||':'||name FROM _benmore_saved_views WHERE id = ?", view); got != fmt.Sprintf("%d:open %s", f.aliceID, cred.name) {
				t.Fatalf("saved view row = %q", got)
			}
			if rec := f.call(t, http.MethodDelete, fmt.Sprintf("/api/_query/views/%d", view), nil, as); rec.Code != http.StatusOK {
				t.Fatalf("Bearer DELETE /api/_query/views: %d %s", rec.Code, rec.Body.String())
			}
			if got := f.scalar(t, "SELECT COUNT(*) FROM _benmore_saved_views WHERE id = ?", view); got != "0" {
				t.Fatalf("Bearer DELETE left the saved view (count %s)", got)
			}
		})
	}
}

func TestInternalAPICookieWritesStillNeedCSRF(t *testing.T) {
	f := newInternalCSRFFixture(t)
	// Rows the DELETE and decide requests would change if they got through.
	res, err := f.app.DB.Exec("INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, run_at) VALUES (?, 'reminder', 'keep', ?)", f.aliceID, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	task, _ := res.LastInsertId()
	res, err = f.app.DB.Exec("INSERT INTO _benmore_saved_views (user_id, name, spec) VALUES (?, 'keep', '{}')", f.aliceID)
	if err != nil {
		t.Fatal(err)
	}
	view, _ := res.LastInsertId()
	res, err = f.app.DB.Exec("INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_id, approver_email, title) VALUES ('expense', '1', ?, 'bob@example.com', ?, 'alice@example.com', 'keep')", f.bobID, f.aliceID)
	if err != nil {
		t.Fatal(err)
	}
	approval, _ := res.LastInsertId()

	endpoints := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/_scheduled", map[string]any{"kind": "reminder", "title": "forged", "run_at": "1h"}},
		{http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", task), nil},
		{http.MethodPost, "/api/_approvals", map[string]any{"table": "expense", "row_id": "9", "approver_email": "bob@example.com", "title": "forged"}},
		{http.MethodPost, fmt.Sprintf("/api/_approvals/%d/decide", approval), map[string]any{"decision": "approved"}},
		{http.MethodPost, "/api/_query/views", map[string]any{"name": "forged", "spec": map[string]any{}}},
		{http.MethodDelete, fmt.Sprintf("/api/_query/views/%d", view), nil},
	}
	cookieHTTP := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: f.aliceSession})
	}
	cookieHTTPS := func(r *http.Request) {
		r.TLS = &tls.ConnectionState{}
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: f.aliceSession})
	}
	refused := []struct {
		name string
		prep func(*http.Request)
	}{
		{"cookie, no token", cookieHTTP},
		{"cookie + junk Bearer", func(r *http.Request) {
			cookieHTTP(r)
			r.Header.Set("Authorization", "Bearer junk")
		}},
		{"cookie + another account's valid Bearer", func(r *http.Request) {
			cookieHTTP(r)
			r.Header.Set("Authorization", "Bearer "+f.bobSession)
		}},
		{"__Host- cookie over HTTPS + junk Bearer", func(r *http.Request) {
			cookieHTTPS(r)
			r.Header.Set("Authorization", "Bearer junk")
		}},
		{"cookie + junk Bearer + token of another session", func(r *http.Request) {
			cookieHTTP(r)
			r.Header.Set("Authorization", "Bearer junk")
			r.Header.Set("X-CSRF-Token", authMintCSRFToken(f.bobSession))
		}},
	}
	before := f.state(t)
	for _, ep := range endpoints {
		for _, c := range refused {
			rec := f.call(t, ep.method, ep.path, ep.body, c.prep)
			if rec.Code != http.StatusForbidden || !strings.Contains(strings.ToLower(rec.Body.String()), "csrf") {
				t.Errorf("%s %s with %s: %d %s, want 403 invalid CSRF token", ep.method, ep.path, c.name, rec.Code, rec.Body.String())
			}
			if after := f.state(t); after != before {
				t.Fatalf("%s %s with %s changed rows without a CSRF token:\nbefore %s\nafter  %s", ep.method, ep.path, c.name, before, after)
			}
		}
		// Over HTTPS the unprefixed cookie is no session cookie, for the
		// CSRF exemption and for identity alike: the request is judged by its
		// junk Bearer alone and is nobody.
		rec := f.call(t, ep.method, ep.path, ep.body, func(r *http.Request) {
			r.TLS = &tls.ConnectionState{}
			r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: f.aliceSession})
			r.Header.Set("Authorization", "Bearer junk")
		})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with an ignored cookie + junk Bearer: %d %s, want 401", ep.method, ep.path, rec.Code, rec.Body.String())
		}
		if after := f.state(t); after != before {
			t.Fatalf("%s %s with an ignored cookie changed rows", ep.method, ep.path)
		}
	}

	// The cookie session with its own token still works, junk Bearer or not,
	// and acts as the cookie's account.
	withToken := func(r *http.Request) {
		cookieHTTP(r)
		r.Header.Set("Authorization", "Bearer junk")
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(f.aliceSession))
	}
	rec := f.call(t, http.MethodPost, "/api/_scheduled", map[string]any{"kind": "reminder", "title": "mine", "run_at": "1h"}, withToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie + CSRF token: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.scalar(t, "SELECT user_id FROM _benmore_scheduled_tasks WHERE id = ?", responseID(t, rec)); got != fmt.Sprint(f.aliceID) {
		t.Fatalf("cookie + CSRF token wrote the task as user %s, want the cookie's account %d", got, f.aliceID)
	}
	if rec := f.call(t, http.MethodPost, fmt.Sprintf("/api/_approvals/%d/decide", approval), map[string]any{"decision": "rejected"}, withToken); rec.Code != http.StatusOK {
		t.Fatalf("cookie + CSRF token decide: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.call(t, http.MethodDelete, fmt.Sprintf("/api/_query/views/%d", view), nil, withToken); rec.Code != http.StatusOK {
		t.Fatalf("cookie + CSRF token delete view: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.scalar(t, "SELECT COUNT(*) FROM _benmore_saved_views WHERE id = ?", view); got != "0" {
		t.Fatalf("cookie + CSRF token did not delete the view")
	}
}
