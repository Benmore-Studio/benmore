//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type countingRoundTripper struct{ calls int }

func (t *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, fmt.Errorf("unexpected network request")
}

func TestDeleteUploadParserValidatorRuntimeInterpolation(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	wantPath := filepath.Join(app.Dir, "uploads", "private", "report.pdf")
	if err := os.MkdirAll(filepath.Dir(wantPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wantPath, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	yaml := `on:
  request: { method: POST, path: /api/delete, auth: required }
jobs:
  delete:
    steps:
      - id: remove
        run: delete_upload
        with:
          path: "${{ steps.lookup.outputs.path }}"
`
	if msg := validateFlowsYAML(yaml); msg != "" {
		t.Fatalf("validator rejected delete_upload: %s", msg)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "flows.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(app.Dir)
	if len(flows) != 1 || len(flows[0].Steps) != 1 {
		t.Fatalf("parsed flows = %#v", flows)
	}
	step := flows[0].Steps[0]
	if step.Type != "delete_upload" || step.DeleteUpload != "{{lookup.path}}" {
		t.Fatalf("parsed step = %#v", step)
	}
	ctx := &FlowContext{
		App: app,
		Data: map[string]any{
			"lookup": map[string]any{"path": "/uploads/private/report.pdf"},
		},
		Params: map[string]string{},
	}
	if err := executeStep(ctx, &step); err != nil {
		t.Fatalf("execute delete_upload: %v", err)
	}
	if _, err := os.Stat(wantPath); !os.IsNotExist(err) {
		t.Fatalf("private upload still exists: %v", err)
	}
}

func TestDeletePrivateUploadLocalIsStrictAndIdempotent(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	file := filepath.Join(app.Dir, "uploads", "private", "keep.txt")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{
		"uploads/public/keep.txt",
		"uploads/private/",
		"uploads/private/../keep.txt",
		"uploads/private/%2e%2e/keep.txt",
		"uploads/private\\keep.txt",
		"uploads/private/keep.txt?download=1",
		"uploads/private/keep.txt#fragment",
		"https://files.example/uploads/private/keep.txt",
		"private/keep.txt",
	} {
		if err := deletePrivateUpload(app, raw); err == nil {
			t.Errorf("deletePrivateUpload(%q) unexpectedly succeeded", raw)
		}
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("rejected reference touched file: %v", err)
	}

	for i := 0; i < 2; i++ {
		if err := deletePrivateUpload(app, "/uploads/private/keep.txt"); err != nil {
			t.Fatalf("idempotent delete %d: %v", i+1, err)
		}
	}
}

func TestDeletePrivateUploadRejectsSymlinkedParent(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateDir := filepath.Join(app.Dir, "uploads", "private")
	if err := os.MkdirAll(privateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(privateDir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := deletePrivateUpload(app, "uploads/private/linked/victim.txt"); err == nil {
		t.Fatal("delete through symlinked parent unexpectedly succeeded")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("delete escaped app directory: %v", err)
	}
}

func TestPrivateUploadReferenceMatchesConfiguredBackend(t *testing.T) {
	app := &App{Dir: filepath.Join(t.TempDir(), "current-app")}
	cdn := &CDNStorage{Prefix: "current-app", CDNDomain: "cdn.example"}
	s3 := &S3Storage{Endpoint: "https://objects.example", Bucket: "bucket"}

	tests := []struct {
		name    string
		backend StorageBackend
		raw     string
		want    string
	}{
		{"cdn same app", cdn, "https://cdn.example/private/current-app/uploads/private/a.pdf", "uploads/private/a.pdf"},
		{"cdn cross app", cdn, "https://cdn.example/private/other/uploads/private/a.pdf", ""},
		{"cdn public", cdn, "https://cdn.example/public/current-app/uploads/private/a.pdf", ""},
		{"cdn query", cdn, "https://cdn.example/private/current-app/uploads/private/a.pdf?x=1", ""},
		{"cdn wrong scheme", cdn, "http://cdn.example/private/current-app/uploads/private/a.pdf", ""},
		{"s3 exact", s3, "https://objects.example/bucket/uploads/private/a.pdf", "uploads/private/a.pdf"},
		{"s3 wrong bucket", s3, "https://objects.example/other/uploads/private/a.pdf", ""},
		{"s3 public", s3, "https://objects.example/bucket/uploads/public/a.pdf", ""},
		{"s3 query", s3, "https://objects.example/bucket/uploads/private/a.pdf?x=1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := privateUploadPath(app, tt.backend, tt.raw)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("privateUploadPath unexpectedly accepted %q as %q", tt.raw, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("privateUploadPath = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestS3DeleteStatusContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var status int
		if _, err := fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/bucket/"), "%d", &status); err != nil {
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(strings.Repeat("failure", 1024)))
	}))
	defer server.Close()
	s3 := &S3Storage{Endpoint: server.URL, Bucket: "bucket"}
	for _, status := range []int{http.StatusNoContent, http.StatusNotFound} {
		if err := s3.Delete(fmt.Sprint(status)); err != nil {
			t.Errorf("Delete status %d: %v", status, err)
		}
	}
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		if err := s3.Delete(fmt.Sprint(status)); err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
			t.Errorf("Delete status %d error = %v", status, err)
		}
	}
}

func TestPresignBrokerDeleteClampsPrefixAndPropagatesFailure(t *testing.T) {
	statuses := []int{http.StatusNoContent, http.StatusForbidden}
	for _, status := range statuses {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var gotPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(status)
			}))
			defer server.Close()
			s3 := &S3Storage{Endpoint: server.URL, Bucket: "bucket"}
			resp, err := executePresignBrokerRequest(presignReq{
				Operation: "delete",
				Prefix:    "other-app",
				Path:      "uploads/private/a.pdf",
			}, "current-app", false, s3)
			if status == http.StatusNoContent {
				if err != nil {
					t.Fatalf("broker delete: %v", err)
				}
				if resp.Key != "private/current-app/uploads/private/a.pdf" || gotPath != "/bucket/private/current-app/uploads/private/a.pdf" {
					t.Fatalf("broker escaped peer prefix: resp=%#v path=%q", resp, gotPath)
				}
			} else if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("broker failure = %v", err)
			}
		})
	}
}

func TestCDNDeleteWithoutKeyRequiresBroker(t *testing.T) {
	t.Setenv("BENMORE_PRESIGN_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	transport := &countingRoundTripper{}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	cdn := &CDNStorage{
		s3:        &S3Storage{Bucket: "bucket", Region: "us-east-1"},
		Prefix:    "current-app",
		CDNDomain: "cdn.example",
	}
	err := cdn.Delete("uploads/private/a.pdf")
	if err == nil || !strings.Contains(err.Error(), "broker unavailable") {
		t.Fatalf("Delete error = %v, want broker unavailable", err)
	}
	if transport.calls != 0 {
		t.Fatalf("Delete made %d direct S3 request(s) without credentials", transport.calls)
	}
}

func TestDeleteUploadFailureStopsFlowAndRollsBackSQL(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE events (id INTEGER PRIMARY KEY, name TEXT)`)
	target := filepath.Join(app.Dir, "uploads", "private", "next.txt")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("must remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	app.Flows = []Flow{{
		Name:        "atomic_delete",
		Transaction: true,
		Steps: []FlowStep{
			{Type: "sql", SQL: `INSERT INTO events (name) VALUES ('before')`},
			{Type: "delete_upload", DeleteUpload: "uploads/public/rejected.txt"},
			{Type: "sql", SQL: `INSERT INTO missing_after_delete (name) VALUES ('must not run')`},
			{Type: "delete_upload", DeleteUpload: "uploads/private/next.txt"},
		},
	}}
	err := executeFlowJob(app, "atomic_delete", map[string]any{})
	if err == nil {
		t.Fatal("executeFlowJob unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "only uploads/private") {
		t.Fatalf("flow continued past delete failure: %v", err)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed delete committed %d SQL rows", count)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("step after failed delete ran: %v", err)
	}
}
