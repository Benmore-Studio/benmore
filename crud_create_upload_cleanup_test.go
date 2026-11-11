//go:build !cli

package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// multipartCreate posts one text field and one file to handleCreate.
func multipartCreate(t *testing.T, app *App, table, sid string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("title", "scan"); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("attachment", "scan.png")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("\x89PNG\r\n\x1a\nnot really an image"))
	mw.Close()
	return gateCall(app, handleCreate, table, "POST", "/api/"+table, mw.FormDataContentType(), body.String(), sid)
}

func storedUploadFiles(t *testing.T, app *App, folder string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(app.Dir, "uploads", folder))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// A multipart create stores its files before the before-hooks run. When a
// hook refuses the row, the stored bytes (and, for a private folder, the
// ownership row) must not outlive the refusal.
func TestRefusedMultipartCreateRemovesStoredFiles(t *testing.T) {
	for _, table := range []string{"docs", "private"} {
		t.Run(table, func(t *testing.T) {
			app := newGateApp(t, "CREATE TABLE "+quoteIdent(table)+" (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, attachment TEXT)")
			if err := EnsureUploadOwnersTable(app.DB); err != nil {
				t.Fatal(err)
			}
			_, sid := gateUser(t, app, "owner@example.com")

			// Control: an accepted create keeps its file.
			if w := multipartCreate(t, app, table, sid); w.Code != http.StatusOK && w.Code != http.StatusCreated {
				t.Fatalf("accepted create: %d %s", w.Code, w.Body.String())
			}
			kept := storedUploadFiles(t, app, table)
			if len(kept) != 1 {
				t.Fatalf("accepted create stored %d files, want 1", len(kept))
			}
			owners := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_upload_owners")
			if want := map[string]string{"docs": "0", "private": "1"}[table]; owners != want {
				t.Fatalf("accepted create recorded %s ownership rows, want %s", owners, want)
			}

			app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{
				table: {{SQL: "SELECT 'scans are closed' AS error"}},
			}}
			w := multipartCreate(t, app, table, sid)
			if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "scans are closed") {
				t.Fatalf("hook did not refuse the create: %d %s", w.Code, w.Body.String())
			}
			if got := storedUploadFiles(t, app, table); len(got) != 1 || got[0] != kept[0] {
				t.Fatalf("refused create left files behind: %v (kept %v)", got, kept)
			}
			if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_upload_owners"); got != owners {
				t.Fatalf("refused create left an ownership row: %s rows, want %s", got, owners)
			}
		})
	}
}

// On the hosted platform a tenant deletes through the router's broker. A
// refused create's public file lives under the caller's own public prefix,
// which the broker now deletes; another prefix, a private-looking path off
// uploads/private, and any non-canonical spelling are refused before S3.
func TestPresignBrokerDeletesOwnPublicUploads(t *testing.T) {
	var gotPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotPaths = append(gotPaths, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	s3 := &S3Storage{Endpoint: server.URL, Bucket: "bucket"}
	run := func(path string) (*presignResp, error) {
		req := presignReq{Operation: "delete", Prefix: "other-app", Path: path}
		scope, err := presignCallerScope(req, "current-app", false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return executePresignBrokerRequest(req, scope, s3)
	}

	for path, key := range map[string]string{
		"uploads/docs/a.png":       "public/current-app/uploads/docs/a.png",
		"/uploads/docs/b.png":      "public/current-app/uploads/docs/b.png",
		"uploads/private/c.pdf":    "private/current-app/uploads/private/c.pdf",
		"/uploads/private/d/e.pdf": "private/current-app/uploads/private/d/e.pdf",
	} {
		gotPaths = nil
		resp, err := run(path)
		if err != nil || resp.Key != key || len(gotPaths) != 1 || gotPaths[0] != "/bucket/"+key {
			t.Errorf("delete %q: resp=%+v err=%v s3=%v, want key %q", path, resp, err, gotPaths, key)
		}
	}

	for _, path := range []string{
		"", " uploads/docs/a.png", "uploads/docs/a.png ", "static/app.js", "docs/a.png", "uploads",
		"uploads/", "uploads//a.png", "uploads/./a.png", "uploads/../private/x.pdf", "uploads/docs/../../x",
		"../uploads/a.png", "//uploads/a.png", "uploads/docs/%2e%2e/x", "uploads/docs/a.png?x=1",
		"uploads/docs/a.png#f", "uploads\\docs\\a.png", "uploads/docs/a\x00.png",
		"uploads/docs/private/x.pdf", "public/other-app/uploads/docs/a.png",
	} {
		gotPaths = nil
		if resp, err := run(path); err == nil || len(gotPaths) != 0 {
			t.Errorf("delete %q was not refused: resp=%+v err=%v s3=%v", path, resp, err, gotPaths)
		}
	}
}
