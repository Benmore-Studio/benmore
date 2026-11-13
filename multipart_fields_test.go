//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// multipartAs builds a multipart request with the given credential: a Bearer
// session, or the session cookie with its CSRF token in the X-CSRF-Token
// header or in the `_csrf` field of the body.
func multipartAs(t *testing.T, cred, method, path, sid string, fields map[string]string, parts ...uploadPart) *http.Request {
	t.Helper()
	sent := map[string]string{}
	for k, v := range fields {
		sent[k] = v
	}
	switch cred {
	case "bearer":
		return uploadRequest(t, method, path, sid, sent, parts...)
	case "cookie, token in header":
		r := uploadRequest(t, method, path, "", sent, parts...)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
		return r
	case "cookie, token in body":
		sent[csrfTokenName] = authMintCSRFToken(sid)
		r := uploadRequest(t, method, path, "", sent, parts...)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		return r
	}
	t.Fatalf("unknown credential %q", cred)
	return nil
}

var multipartCredentials = []string{"bearer", "cookie, token in header", "cookie, token in body"}

// A multipart PATCH applied its text fields with a session cookie (the CSRF
// check had parsed the form) and read none of them with a Bearer credential.
// Every credential gets the same reading: the text fields are applied through
// the update pipeline, a protected column is stripped and named, and a file
// part is never stored and is named in X-Ignored-Fields.
func TestMultipartPatchReadsTheSameWithEveryCredential(t *testing.T) {
	for _, cred := range multipartCredentials {
		t.Run(cred, func(t *testing.T) {
			app := newGateApp(t, docsTable)
			uid, sid := gateUser(t, app, "owner@example.com")
			mustExecArgs(t, app.DB, "INSERT INTO docs (id, user_id, title, attachment) VALUES (1, ?, 'first', 'kept')", uid)

			w := httptest.NewRecorder()
			handleUpdate(w, multipartAs(t, cred, "PATCH", "/api/docs/1", sid,
				map[string]string{"title": "renamed", "user_id": "999"},
				uploadPart{"attachment", "scan.png", pngBytes}), app, "docs")
			if w.Code != http.StatusOK {
				t.Fatalf("multipart PATCH: %d %s, want 200", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT title || '|' || attachment || '|' || (user_id = ?) FROM docs WHERE id = 1", uid); got != "renamed|kept|1" {
				t.Errorf("row = %q, want the title changed, the file column and the owner untouched", got)
			}
			if got := w.Header().Get("X-Stripped-Fields"); got != "user_id" {
				t.Errorf("X-Stripped-Fields = %q, want user_id", got)
			}
			if got := w.Header().Get(ignoredFieldsHeader); got != "attachment" {
				t.Errorf("%s = %q, want the file part attachment", ignoredFieldsHeader, got)
			}
			if left := everyStoredUpload(t, app); len(left) != 0 {
				t.Errorf("the PATCH stored %v", left)
			}

			// A body with a file part only names no field to write: the
			// answer says what an update does with a multipart body.
			w = httptest.NewRecorder()
			handleUpdate(w, multipartAs(t, cred, "PATCH", "/api/docs/1", sid, nil, uploadPart{"attachment", "scan.png", pngBytes}), app, "docs")
			body := answerJSON(t, w)
			hint, _ := body["hint"].(string)
			if w.Code != http.StatusBadRequest || body["error"] != "No fields to update" || body["docs"] != "uploads.multipart_bodies" {
				t.Fatalf("file-only multipart PATCH: %d %s, want 400 No fields to update with docs", w.Code, w.Body.String())
			}
			for _, want := range []string{"multipart", "file part", "/api/_upload"} {
				if !strings.Contains(hint, want) {
					t.Errorf("hint %q does not mention %s", hint, want)
				}
			}
			if got := gateScalar(t, app, "SELECT title || '|' || attachment FROM docs WHERE id = 1"); got != "renamed|kept" {
				t.Errorf("row after the refused PATCH: %q", got)
			}
		})
	}
}

// The optimistic-concurrency field travels in a multipart body like any
// other text field, for every credential.
func TestMultipartPatchHonoursExpectedUpdatedAt(t *testing.T) {
	for _, cred := range multipartCredentials {
		t.Run(cred, func(t *testing.T) {
			app := newGateApp(t, "CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, updated_at TEXT)")
			uid, sid := gateUser(t, app, "owner@example.com")
			mustExecArgs(t, app.DB, "INSERT INTO docs (id, user_id, title, updated_at) VALUES (1, ?, 'first', '2026-01-01 00:00:00')", uid)
			w := httptest.NewRecorder()
			handleUpdate(w, multipartAs(t, cred, "PATCH", "/api/docs/1", sid,
				map[string]string{"title": "stale", "_expected_updated_at": "2025-01-01 00:00:00"}), app, "docs")
			if w.Code != http.StatusConflict {
				t.Fatalf("stale multipart PATCH: %d %s, want 409", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT title FROM docs WHERE id = 1"); got != "first" {
				t.Errorf("title = %q after a refused update", got)
			}
		})
	}
}

// A multipart body cut by the body cap answers 413 with the limit and one
// that does not parse answers 400, whatever the credential; neither writes.
func TestMultipartPatchBodyErrors(t *testing.T) {
	for _, cred := range multipartCredentials {
		t.Run(cred, func(t *testing.T) {
			app := newGateApp(t, docsTable)
			uid, sid := gateUser(t, app, "owner@example.com")
			mustExecArgs(t, app.DB, "INSERT INTO docs (id, user_id, title, attachment) VALUES (1, ?, 'first', '')", uid)

			r := multipartAs(t, cred, "PATCH", "/api/docs/1", sid, map[string]string{"title": "renamed"},
				uploadPart{"attachment", "big.bin", strings.Repeat("x", 64<<10)})
			w := httptest.NewRecorder()
			r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
			handleUpdate(w, r, app, "docs")
			if body := answerJSON(t, w); w.Code != http.StatusRequestEntityTooLarge || body["limit_bytes"] != float64(4<<10) {
				t.Errorf("capped multipart PATCH: %d %s, want 413 with the limit", w.Code, w.Body.String())
			}

			r = multipartAs(t, cred, "PATCH", "/api/docs/1", sid, map[string]string{"title": "renamed"})
			r.Header.Set("Content-Type", "multipart/form-data") // no boundary
			w = httptest.NewRecorder()
			handleUpdate(w, r, app, "docs")
			if body := answerJSON(t, w); w.Code != http.StatusBadRequest || body["error"] != "malformed multipart body" {
				t.Errorf("multipart PATCH with no boundary: %d %s, want 400 malformed multipart body", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT title FROM docs WHERE id = 1"); got != "first" {
				t.Errorf("title = %q after two refused updates", got)
			}
		})
	}
}

// The text fields of one body are held to the form limit, and a file part's
// bytes are read past without being kept.
func TestReadMultipartTextFields(t *testing.T) {
	r := uploadRequest(t, "PATCH", "/api/docs/1?title=from-query", "", map[string]string{"title": "from-body", "note": "n"},
		uploadPart{"attachment", "scan.png", pngBytes}, uploadPart{"second", "b.png", pngBytes})
	files, err := readMultipartTextFields(r)
	if err != nil || len(files) != 2 {
		t.Fatalf("files = %v, err = %v, want the two file parts", files, err)
	}
	if got := r.Form["title"]; len(got) != 2 || got[0] != "from-query" || got[1] != "from-body" {
		t.Errorf("Form[title] = %v, want the query's value first, as a parsed form orders them", got)
	}
	if r.PostForm.Get("title") != "from-body" || r.PostForm.Get("note") != "n" || r.FormValue("attachment") != "" {
		t.Errorf("PostForm = %v", r.PostForm)
	}
	// A second call (or a later r.FormValue) reads nothing again.
	if again, err := readMultipartTextFields(r); err != nil || len(again) != 0 || len(r.Form["title"]) != 2 {
		t.Errorf("second read: files %v err %v form %v", again, err, r.Form)
	}

	big := uploadRequest(t, "PATCH", "/api/docs/1", "", map[string]string{"title": strings.Repeat("x", int(netHTTPMaxFormBytes)+1)})
	_, err = readMultipartTextFields(big)
	if limit, tooLarge := requestBodyTooLarge(err); !tooLarge || limit != netHTTPMaxFormBytes {
		t.Errorf("text fields over the form limit: err = %v, want too large at %d", err, netHTTPMaxFormBytes)
	}
}

// POST /api/_groups/create ran its CSRF check before it read the body, so
// it had the same split: a multipart body named the organization with a
// cookie and was an empty body with a Bearer credential.
func TestGroupBootstrapReadsMultipartWithEveryCredential(t *testing.T) {
	for _, cred := range multipartCredentials {
		t.Run(cred, func(t *testing.T) {
			app, uid, cleanup := newBootstrapTestApp(t, "email")
			defer cleanup()
			sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
			w := httptest.NewRecorder()
			handleGroupBootstrap(w, multipartAs(t, cred, "POST", "/api/_groups/create", sid, map[string]string{"name": "Acme"}), app)
			if w.Code != http.StatusOK && w.Code != http.StatusCreated {
				t.Fatalf("multipart bootstrap: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT name FROM companies"); got != "Acme" {
				t.Errorf("organization name = %q, want Acme", got)
			}
		})
	}
}

// A flow reads nothing from a multipart body (parse.summary). On a PUT or
// PATCH flow a cookie request's `run: parse` step did read its text fields,
// and its `_csrf` field was accepted as the CSRF token, because the CSRF
// check parsed the body; a POST flow and a Bearer request read neither.
// Every method and credential now agree: no field is read, and a cookie
// request sends its CSRF token in the X-CSRF-Token header.
func TestFlowReadsNoMultipartFieldWithAnyCredential(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		app := newGateApp(t)
		_, sid := gateUser(t, app, "owner@example.com")
		src := "on:\n  request:\n    method: " + method + `
    path: /api/echo
    auth: required
jobs:
  echo:
    steps:
      - id: evt
        run: parse
      - run: respond
        with:
          json:
            title: "${{ steps.evt.outputs.title || 'unread' }}"
            q: "${{ steps.evt.outputs.q }}"
`
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		flows := LoadFlowsGHA(dir)
		if len(flows) != 1 {
			t.Fatalf("loaded %d flows, want 1", len(flows))
		}
		app.mu.Lock()
		app.Flows = flows
		app.mu.Unlock()
		for _, cred := range multipartCredentials {
			t.Run(method+" "+cred, func(t *testing.T) {
				w := httptest.NewRecorder()
				r := multipartAs(t, cred, method, "/api/echo?q=from-query", sid, map[string]string{"title": "from-multipart"})
				if err := executeFlowHTTP(app, &flows[0], w, r); err != nil {
					t.Fatalf("run: %v", err)
				}
				if cred == "cookie, token in body" {
					// The token is a field of the body the flow does not read.
					if w.Code != http.StatusForbidden {
						t.Fatalf("cookie request with the token only in a multipart field: %d %s, want 403", w.Code, w.Body.String())
					}
					return
				}
				body := answerJSON(t, w)
				if w.Code != http.StatusOK || body["title"] != "unread" || body["q"] != "from-query" {
					t.Fatalf("%d %s, want 200 with the multipart field unread and the query field read", w.Code, w.Body.String())
				}
			})
		}
	}
}
