//go:build !cli

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAsyncBroadcastPreservesValidatedTenantSession(t *testing.T) {
	app, _, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	EnsureJobsTable(app.DB)
	uid := workflowTestUser(t, app, "auditor@example.com")
	addMember(t, app, "A", uid, "member")
	sid := CreateSession(app.DB, uid, "auditor@example.com", "A", time.Hour)
	flow := Flow{Name: "notify", Auth: "required", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/notify"}, Steps: []FlowStep{
		{Name: "message", Type: "broadcast", Broadcast: &FlowBroadcast{Room: "lobby", Payload: map[string]any{"kind": "changed"}, HasPayload: true}},
	}}
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "/api/notify", strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sid)
		return r
	}
	if err := executeFlowHTTP(app, &flow, httptest.NewRecorder(), request()); err != nil {
		t.Fatalf("sync control: %v", err)
	}
	flow.Async = true
	app.Flows = []Flow{flow}
	w := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &app.Flows[0], w, request()); err != nil || w.Code != 202 {
		t.Fatalf("enqueue: %d %v", w.Code, err)
	}
	if !processNextJob(app) {
		t.Fatal("job not claimed")
	}
	var status, failure string
	if err := app.DB.QueryRow("SELECT status,COALESCE(error,'') FROM _benmore_jobs").Scan(&status, &failure); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || failure != "" {
		t.Fatalf("unexpected result: %s %s", status, failure)
	}
}

func TestEnqueueRejectsInvalidRunAt(t *testing.T) {
	app := newJobsTestApp(t)
	ctx := &FlowContext{App: app, Data: map[string]any{"due": "tomorrow-invalid"}, Params: map[string]string{"due": "tomorrow-invalid"}, RequestKeys: map[string]bool{"due": true}}
	step := &FlowStep{Name: "queued", Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "worker", RunAt: "{{due}}"}}
	if err := executeStep(ctx, step); err == nil {
		t.Fatal("invalid schedule accepted")
	}
	var dueNow int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE run_at <= datetime('now')").Scan(&dueNow); err != nil {
		t.Fatal(err)
	}
	if dueNow != 0 {
		t.Fatalf("due jobs=%d", dueNow)
	}
}

type freshAuditRuntimeTransport func(*http.Request) (*http.Response, error)

func (f freshAuditRuntimeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPaginationCountsHTTPPages(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	calls := 0
	client := &http.Client{Transport: freshAuditRuntimeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"items":[1,2,3],"next":"second"}`
		if calls == 2 {
			body = `{"items":[4,5,6],"next":""}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	step := &FlowStep{Name: "pages", Type: "api", API: &FlowAPICall{URL: "https://8.8.8.8/audit", Paginate: &FlowAPIPaginate{CursorField: "$.next"}}}
	if err := execStepAPIWithClient(ctx, step, client); err != nil {
		t.Fatal(err)
	}
	out := ctx.Data["pages"].(map[string]any)
	if calls != 2 || out["pages_fetched"] != 2 {
		t.Fatalf("calls=%d output=%v", calls, out)
	}
}

func TestFlowCannotReadRuntimeSigningKey(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	const fixture = "audit-fixture-runtime-signing-key-no-real-secret"
	if err := os.MkdirAll(filepath.Join(app.Dir, ".benmore"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, ".benmore", "env"), []byte("BENMORE_SERVER_SECRET="+fixture+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	vars, err := readAppEnvFromSource(app.Dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	storeAppEnv(app.Dir, vars)
	flow := Flow{Name: "environment_boundary", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/fixture"}, Steps: []FlowStep{{Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"value": "{{env.BENMORE_SERVER_SECRET}}"}}}}}
	w := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flow, w, httptest.NewRequest("GET", "/fixture", nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), fixture) {
		t.Fatalf("runtime signing key was exposed; status=%d", w.Code)
	}
}

func TestSignedInPasswordChangeRejectsProofAfterReset(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "audit@example.com", "Before!Password123", 1)
	sid := CreateSession(app.DB, uid, "audit@example.com", "", time.Hour)
	staleSession := GetSessionFromDB(app.DB, sid)
	if staleSession == nil {
		t.Fatal("session fixture missing")
	}
	// Exact logical interleaving of settings.go: proof, bcrypt work, write.
	proof, locked := currentPasswordProof(app, uid, "Before!Password123")
	if proof == "" || locked {
		t.Fatal("initial proof failed")
	}
	replacement, err := generateBcryptHash([]byte("Concurrent!Password123"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("INSERT INTO _benmore_password_resets(token,email,expires_at,type) VALUES (?,?,?,'reset')", hashResetToken("local-fixture-reset"), "audit@example.com", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"token": {"local-fixture-reset"}, "password": {"Recovered!Password123"}, "confirm": {"Recovered!Password123"}}
	r := httptest.NewRequest("POST", app.Paths.ResetPassword, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleResetPassword(w, r, app)
	if !strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatalf("reset failed: %d %s", w.Code, w.Header().Get("Location"))
	}
	if GetSessionFromDB(app.DB, sid) != nil {
		t.Fatal("reset control failed to revoke original session")
	}
	if _, err := changeSignedInPasswordWith(app, staleSession, proof, string(replacement), false); err == nil {
		t.Fatal("stale write accepted")
	}
	var stored string
	if err := app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id=?", uid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == string(replacement) {
		t.Fatal("unexpected final credential")
	}
}
