//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// compliance: hipaa stores every upload on the private tier. A Go test because
// the YAML runner cannot send multipart bodies.
func TestHIPAAUploadsArePrivate(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	app.Design = &DesignConfig{Compliance: complianceHIPAA}
	user := createCrudScopeSession(t, app, "nurse@example.com", "user", "", "")

	// /api/_upload with no kind defaults to private.
	p := uploadedPath(t, uploadAs(t, mux, user, "", "scan.pdf", []byte("%PDF-1.4 chart")))
	if !strings.HasPrefix(p, "/uploads/private/") {
		t.Fatalf("default upload stored at %q, want the private tier", p)
	}
	// An explicit public kind is refused; private still works.
	if rec := uploadAs(t, mux, user, "avatars", "a.png", []byte("\x89PNG\r\n")); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "hipaa") {
		t.Fatalf("public kind under hipaa: %d %s", rec.Code, rec.Body.String())
	}
	if p := uploadedPath(t, uploadAs(t, mux, user, "private", "b.pdf", []byte("%PDF-1.4 b"))); !strings.HasPrefix(p, "/uploads/private/") {
		t.Fatalf("kind=private stored at %q", p)
	}

	// /api/_files and a multipart auto-CRUD create land under uploads/private/.
	for _, c := range []struct{ path, field string }{{"/api/_files", "file"}, {"/api/docs", "file_url"}} {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile(c.field, "x.pdf")
		fw.Write([]byte("%PDF-1.4 x"))
		mw.Close()
		req := httptest.NewRequest(http.MethodPost, c.path, &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+user)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("%s: %d %s", c.path, rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		got, _ := out["url"].(string)
		if c.field == "file_url" {
			got, _ = out["file_url"].(string)
		}
		if !strings.HasPrefix(got, "/uploads/private/") {
			t.Fatalf("%s stored at %q, want the private tier (%s)", c.path, got, rec.Body.String())
		}
		// The bytes are not served without a signature.
		get := httptest.NewRecorder()
		mux.ServeHTTP(get, httptest.NewRequest(http.MethodGet, got, nil))
		if get.Code == http.StatusOK {
			t.Fatalf("%s served unsigned", got)
		}
	}

	// Outside hipaa the folders stay as they were.
	app.Design = &DesignConfig{}
	if p := uploadedPath(t, uploadAs(t, mux, user, "avatars", "a.png", []byte("\x89PNG\r\n"))); !strings.HasPrefix(p, "/uploads/avatars/") {
		t.Fatalf("non-hipaa public kind stored at %q", p)
	}
}

func TestHIPAAUploadKindWriteGate(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "compliance: hipaa\n")
	refused := []string{
		"await bm.upload(file, { kind: 'avatars' });",
		"fd.append('kind', 'public'); await fetch('/api/_upload', {method: 'POST', body: fd});",
		`<form action="/api/_files" method="post"><input type="hidden" name="kind" value="photos"></form>`,
	}
	for _, src := range refused {
		if msg := ValidateOnWriteIn(dir, "static/app.tsx", src); !strings.Contains(msg, "hipaa") {
			t.Fatalf("public kind not refused in %q: %s", src, msg)
		}
	}
	for _, src := range []string{
		"await bm.upload(file);", "await bm.upload(file, { kind: 'private' });", "ws.send({ kind: 'chat' });",
		// No-semicolon style: the upload call ends before a later kind: literal.
		"const url = await bm.upload(file)\ntoast({ kind: 'success', text: 'Saved' })\n",
		// A FormData field named kind that is not sent to an upload route.
		"const fd = new FormData(); fd.append('kind', 'bug'); await fetch('/api/feedback-flow', {method:'POST', body: fd})",
	} {
		if msg := ValidateOnWriteIn(dir, "static/app.tsx", src); strings.Contains(msg, "hipaa") {
			t.Fatalf("refused %q: %s", src, msg)
		}
	}
	other := t.TempDir()
	writeTestFile(t, other, "app.yaml", "site_name: x\n")
	if msg := ValidateOnWriteIn(other, "static/app.tsx", refused[0]); strings.Contains(msg, "hipaa") {
		t.Fatalf("non-hipaa app refused: %s", msg)
	}
}
