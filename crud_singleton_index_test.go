//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// The no-id PATCH contract requires a global one-row-per-user invariant.
// Partial indexes and composite expression indexes allow multiple rows for one
// user, so accepting them would silently select and overwrite an arbitrary row.
func TestSingletonUpdateRequiresGlobalUserIDUniqueness(t *testing.T) {
	for _, tc := range []struct {
		name        string
		index       string
		multiple    bool
		isSingleton bool
	}{
		{name: "partial", index: `CREATE UNIQUE INDEX profiles_active ON profiles (user_id) WHERE active = 1`, multiple: true},
		{name: "composite_expression", index: `CREATE UNIQUE INDEX profiles_category ON profiles (user_id, lower(category))`, multiple: true},
		{name: "expression_before_user_id", index: `CREATE UNIQUE INDEX profiles_category ON profiles (lower(category), user_id)`, multiple: true},
		{name: "expression_only", index: `CREATE UNIQUE INDEX profiles_expression ON profiles (abs(user_id))`},
		{name: "plain_unique", index: `CREATE UNIQUE INDEX profiles_user ON profiles (user_id)`, isSingleton: true},
		{name: "descending_quoted_index", index: `CREATE UNIQUE INDEX "profiles' user index" ON profiles (user_id DESC)`, isSingleton: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newGateApp(t,
				`CREATE TABLE profiles (id INTEGER PRIMARY KEY, user_id INTEGER, active INTEGER, category TEXT, body TEXT)`,
				tc.index,
			)
			EnsureWebhooksTable(app.DB)
			uid, sid := gateUser(t, app, "owner@example.com")
			if _, err := app.DB.Exec(`INSERT INTO profiles (id, user_id, active, category, body) VALUES (1, ?, 0, 'home', 'original')`, uid); err != nil {
				t.Fatal(err)
			}
			if tc.multiple {
				if _, err := app.DB.Exec(`INSERT INTO profiles (id, user_id, active, category, body) VALUES (2, ?, 0, 'work', 'original')`, uid); err != nil {
					t.Fatalf("fixture must permit multiple rows per user: %v", err)
				}
			}
			if got := tableHasUniqueUserID(app.DB, "profiles"); got != tc.isSingleton {
				t.Errorf("singleton detected = %t, want %t", got, tc.isSingleton)
			}
			w := gateCall(app, handleSingletonUpdate, "profiles", http.MethodPatch, "/api/profiles", "application/json", `{"body":"changed"}`, sid)
			wantStatus, wantChanged := http.StatusBadRequest, "0"
			if tc.isSingleton {
				wantStatus, wantChanged = http.StatusOK, "1"
			}
			if w.Code != wantStatus {
				t.Errorf("singleton PATCH = %d %s, want %d", w.Code, w.Body.String(), wantStatus)
			}
			if got := gateScalar(t, app, `SELECT COUNT(*) FROM profiles WHERE body = 'changed'`); got != wantChanged {
				t.Errorf("singleton PATCH changed %s rows, want %s", got, wantChanged)
			}
		})
	}
}
