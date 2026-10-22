//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type permissionExpiryState struct {
	ID         int64
	Permission string
	GrantedBy  sql.NullInt64
	ExpiresAt  sql.NullString
	GrantedAt  sql.NullString
}

func readPermissionExpiryState(t *testing.T, app *App, row string) permissionExpiryState {
	t.Helper()
	var state permissionExpiryState
	// DATETIME scanning can convert malformed stored text to null. Inspect the
	// raw bytes separately from the native permission-list representation.
	err := app.DB.QueryRow(`SELECT id,permission,granted_by,CAST(expires_at AS TEXT),CAST(granted_at AS TEXT) FROM _benmore_permissions WHERE resource_type='notes' AND resource_id=? AND grant_type='user'`, row).Scan(&state.ID, &state.Permission, &state.GrantedBy, &state.ExpiresAt, &state.GrantedAt)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func shareExpiryAuditCount(t *testing.T, app *App) int {
	t.Helper()
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_audit_log WHERE action='share' AND table_name='notes'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestShareExpiryRejectsMalformedBeforeMutation(t *testing.T) {
	for _, value := range []string{"definitely-not-a-timestamp", " ", "2099-13-01", "10000-01-01T00:00:00Z", "2099-01-01T00:00:00+25:00"} {
		t.Run(value, func(t *testing.T) {
			app, mux, owner, reader := permissionRevokeFixture(t)
			var parsed sql.NullString
			if err := app.DB.QueryRow(`SELECT datetime(?)`, value).Scan(&parsed); err != nil || parsed.Valid {
				t.Fatalf("invalid-value parser control: %v %v", parsed, err)
			}
			body := map[string]any{"email": "reader+files/test@example.test", "permission": "admin", "expires_at": value}
			beforeAudit := shareExpiryAuditCount(t, app)
			r := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/share", owner, body)
			if r.Code != http.StatusBadRequest {
				t.Errorf("malformed new share: status=%d body=%s", r.Code, r.Body.String())
			}
			var count int
			if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_permissions`).Scan(&count); err != nil || count != 0 {
				t.Errorf("malformed new share wrote grant: count=%d err=%v", count, err)
			}
			if got := shareExpiryAuditCount(t, app); got != beforeAudit {
				t.Errorf("malformed new share wrote audit: %d -> %d", beforeAudit, got)
			}
			assertStatus(t, mux, http.MethodGet, "/api/notes/1", reader, nil, http.StatusNotFound)

			// An invalid upsert must not revoke/replace a working grant. Keep an
			// independent historical malformed row to prove no implicit migration.
			assertStatus(t, mux, http.MethodPost, "/api/notes/1/share", owner, map[string]any{"email": body["email"], "permission": "view", "expires_at": "2099-01-01 00:00:00"}, http.StatusOK)
			crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_permissions(resource_type,resource_id,grant_type,grantee_id,permission,expires_at) VALUES ('notes','2','user','reader+files/test@example.test','view','legacy-invalid')`)
			before, legacy := readPermissionExpiryState(t, app, "1"), readPermissionExpiryState(t, app, "2")
			beforeAudit = shareExpiryAuditCount(t, app)
			r = crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/share", owner, body)
			if r.Code != http.StatusBadRequest {
				t.Errorf("malformed upsert: status=%d body=%s", r.Code, r.Body.String())
			}
			if got := readPermissionExpiryState(t, app, "1"); got != before {
				t.Errorf("malformed upsert changed grant: before=%+v after=%+v", before, got)
			}
			if got := readPermissionExpiryState(t, app, "2"); got != legacy {
				t.Errorf("historical malformed grant changed: before=%+v after=%+v", legacy, got)
			}
			if got := shareExpiryAuditCount(t, app); got != beforeAudit {
				t.Errorf("malformed upsert wrote audit: %d -> %d", beforeAudit, got)
			}
			assertStatus(t, mux, http.MethodGet, "/api/notes/1", reader, nil, http.StatusOK)
			assertStatus(t, mux, http.MethodGet, "/api/notes/2", reader, nil, http.StatusNotFound)
		})
	}
}

func TestShareExpiryPreservesAcceptedFormats(t *testing.T) {
	cases := []struct {
		name, value string
		omit        bool
		readStatus  int
	}{
		{"rfc3339_future", "2099-01-01T00:00:00Z", false, 200},
		{"offset_future", "2099-01-01T00:00:00+02:30", false, 200},
		{"rfc3339_past", "2000-01-01T00:00:00Z", false, 404},
		{"offset_past", "2000-01-01T00:00:00-03:30", false, 404},
		{"sqlite_future", "2099-01-01 00:00:00", false, 200},
		{"sqlite_date_only", "2099-01-01", false, 200},
		{"empty_no_expiry", "", false, 200},
		{"omitted_no_expiry", "", true, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, mux, owner, reader := permissionRevokeFixture(t)
			body := map[string]any{"email": "reader+files/test@example.test", "permission": "view"}
			if !tc.omit {
				body["expires_at"] = tc.value
			}
			assertStatus(t, mux, http.MethodPost, "/api/notes/1/share", owner, body, http.StatusOK)
			stored := readPermissionExpiryState(t, app, "1")
			if stored.ExpiresAt.Valid != (tc.value != "") || stored.ExpiresAt.String != tc.value {
				t.Fatalf("expiry representation changed: %+v want %q", stored.ExpiresAt, tc.value)
			}
			if got := shareExpiryAuditCount(t, app); got != 1 {
				t.Fatalf("successful share audit count=%d", got)
			}
			assertStatus(t, mux, http.MethodGet, "/api/notes/1", reader, nil, tc.readStatus)
		})
	}
}

func TestShareExpiryRetainsAuthorityPrecedence(t *testing.T) {
	app, mux, owner, reader := permissionRevokeFixture(t)
	EnsureAPITokensTable(app.DB)
	readOnly := auditToken(t, app, owner, "notes:read")
	body := map[string]any{"email": "reader+files/test@example.test", "permission": "view", "expires_at": "malformed"}
	for _, tc := range []struct {
		name, token string
		status      int
	}{{"signed_out", "", 401}, {"nonowner", reader, 403}, {"read_only_owner", readOnly, 403}} {
		t.Run(tc.name, func(t *testing.T) {
			assertStatus(t, mux, http.MethodPost, "/api/notes/1/share", tc.token, body, tc.status)
		})
	}
	req := httptest.NewRequest(http.MethodPost, "/api/notes/1/share", strings.NewReader(`{"email":"reader+files/test@example.test","permission":"view","expires_at":"malformed"}`))
	req.AddCookie(&http.Cookie{Name: "_benmore_session", Value: owner})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF must still win: %d %s", rec.Code, rec.Body.String())
	}
	if got := shareExpiryAuditCount(t, app); got != 0 {
		t.Fatalf("denied calls wrote share audits: %d", got)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_permissions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("denied calls wrote grants: count=%d err=%v", count, err)
	}
}
