//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A lock's expires_at is one timestamp, so acquire, renew, the status
// endpoint and the 409 another editor gets must all spell it the same way
// (RFC3339 UTC). Acquire used to answer SQLite text ("2026-11-05 04:04:21")
// while the other two answered RFC3339. The lock lasts lockTTL (30 s) and a
// held lock answers 409, as api(at:"locks") now says.
func TestLockExpiresAtIsRFC3339Everywhere(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	holder := createCrudScopeSession(t, app, "holder@example.com", "user", "org-b", "")
	other := createCrudScopeSession(t, app, "other@example.com", "user", "org-b", "")

	decode := func(t *testing.T, body []byte) map[string]any {
		t.Helper()
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		return out
	}
	rfc3339 := func(t *testing.T, label string, v any) time.Time {
		t.Helper()
		s, _ := v.(string)
		at, err := time.Parse(time.RFC3339, s)
		if err != nil || !strings.HasSuffix(s, "Z") {
			t.Fatalf("%s expires_at = %q, want RFC3339 UTC: %v", label, s, err)
		}
		return at
	}

	before := time.Now().UTC().Truncate(time.Second)
	acquire := crudScopeRequest(t, mux, http.MethodPost, "/api/records/2/lock", holder, nil)
	if acquire.Code != http.StatusOK {
		t.Fatalf("acquire = %d %s", acquire.Code, acquire.Body.String())
	}
	acquired := decode(t, acquire.Body.Bytes())
	expires := rfc3339(t, "acquire", acquired["expires_at"])
	if ttl := expires.Sub(before); ttl < lockTTL-2*time.Second || ttl > lockTTL+2*time.Second {
		t.Fatalf("lock lasts %s, want about %s", ttl, lockTTL)
	}

	status := crudScopeRequest(t, mux, http.MethodGet, "/api/records/2/lock", other, nil)
	stated := decode(t, status.Body.Bytes())
	if status.Code != http.StatusOK || stated["locked"] != true || stated["expires_at"] != acquired["expires_at"] {
		t.Fatalf("status = %d %s, want expires_at %v", status.Code, status.Body.String(), acquired["expires_at"])
	}
	rfc3339(t, "status locked_at", stated["locked_at"])

	conflict := crudScopeRequest(t, mux, http.MethodPost, "/api/records/2/lock", other, nil)
	refused := decode(t, conflict.Body.Bytes())
	if conflict.Code != http.StatusConflict || refused["expires_at"] != acquired["expires_at"] || refused["locked_by"] != "holder@example.com" {
		t.Fatalf("second editor's acquire = %d %s, want 409 with the holder's expires_at %v", conflict.Code, conflict.Body.String(), acquired["expires_at"])
	}

	// A held lock refuses another editor's PATCH with the same 409.
	patch := crudScopeRequest(t, mux, http.MethodPatch, "/api/records/2", other, map[string]any{"title": "theirs"})
	if patch.Code != http.StatusConflict || !strings.Contains(patch.Body.String(), "record is locked by another user") {
		t.Fatalf("PATCH on a locked row = %d %s, want 409", patch.Code, patch.Body.String())
	}

	renew := crudScopeRequest(t, mux, http.MethodPost, "/api/records/2/lock", holder, nil)
	if renew.Code != http.StatusOK {
		t.Fatalf("renew = %d %s", renew.Code, renew.Body.String())
	}
	renewed := rfc3339(t, "renew", decode(t, renew.Body.Bytes())["expires_at"])
	if renewed.Before(expires) {
		t.Fatalf("renew moved expiry back: %s < %s", renewed, expires)
	}
	// The stored value stays SQLite text, which the expiry sweeps compare.
	var stored string
	if err := app.DB.QueryRow("SELECT CAST(expires_at AS TEXT) FROM _benmore_locks WHERE table_name='records' AND row_id='2'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != renewed.Format("2006-01-02 15:04:05") {
		t.Fatalf("stored expires_at = %q, want SQLite UTC text for %s", stored, renewed)
	}
}
