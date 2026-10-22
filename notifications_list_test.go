//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// bm.notifications.list({limit, offset, unread}) sent those names, but the
// server only read page/per_page and ignored unread, so every call got the
// default first page of everything. Both spellings work now.
func TestNotificationsListHonorsSDKParameters(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "inbox@example.com", "user", "", "")
	var userID int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'inbox@example.com'").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if _, err := CreateNotification(app.DB, userID, "n"+string(rune('0'+i)), "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(t, app.DB, "UPDATE _benmore_notifications SET read = 1 WHERE title IN ('n1', 'n2')")
	mux := http.NewServeMux()
	RegisterNotificationRoutes(mux, app)
	list := func(query string) (titles []string, total int64) {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/_notifications"+query, nil)
		req.Header.Set("Authorization", "Bearer "+sid)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		var body struct {
			Notifications []map[string]any `json:"notifications"`
			Total         int64            `json:"total"`
		}
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &body) != nil {
			t.Fatalf("%s: %d %s", query, rr.Code, rr.Body.String())
		}
		for _, n := range body.Notifications {
			titles = append(titles, n["title"].(string))
		}
		return titles, body.Total
	}
	if got, total := list("?unread=1"); strings.Join(got, ",") != "n5,n4,n3" || total != 3 {
		t.Errorf("unread=1: %v (total %d), want n5,n4,n3 (3)", got, total)
	}
	if got, _ := list("?limit=2&offset=1"); strings.Join(got, ",") != "n4,n3" {
		t.Errorf("limit=2&offset=1: %v, want n4,n3", got)
	}
	if got, _ := list("?page=2&per_page=2"); strings.Join(got, ",") != "n3,n2" {
		t.Errorf("page=2&per_page=2: %v, want n3,n2", got)
	}
}

// Change events carry no row data, so onNew can't hand the callback ev.row;
// it fetches what is new instead, with the parameters the server reads.
func TestNotificationsSDKDoesNotReadEventRows(t *testing.T) {
	src, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(src), "export const notifications = {")
	end := strings.Index(string(src)[start:], "\n};\n")
	block := string(src)[start : start+end]
	if strings.Contains(block, "ev.row") {
		t.Error("bm.notifications still reads ev.row, which change events never carry")
	}
	if !strings.Contains(block, "api.get(`/api/_notifications?") {
		t.Error("bm.notifications.onNew no longer fetches new notifications")
	}
}
