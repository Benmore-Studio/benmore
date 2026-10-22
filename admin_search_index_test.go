//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The admin search index wrote each user's email into a JavaScript string
// with html.EscapeString, which leaves backslashes alone, so a stored value
// ending in a backslash changed how the rest of the inline script parsed.
// The index is now JSON, a valid script literal for any stored value.
func TestAdminSearchIndexEncodesUsersAsJSON(t *testing.T) {
	app, mux, admin, cleanup := adminPanelApp(t)
	defer cleanup()
	odd := `odd\` + " " + `"</script>@example.com`
	mustExec(t, app.DB, `INSERT INTO _benmore_users (username, email, role, verified) VALUES ('odd', '`+strings.ReplaceAll(odd, "'", "''")+`', 'user', 1)`)
	rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin", admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/_admin: %d", rec.Code)
	}
	m := regexp.MustCompile(`var users=(\[.*?\]);\n`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("search index not found")
	}
	if strings.Contains(m[1], "</script") {
		t.Fatalf("index can end the script element: %s", m[1])
	}
	var users []struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal([]byte(m[1]), &users); err != nil {
		t.Fatalf("search index is not a JSON literal: %v: %s", err, m[1])
	}
	found := false
	for _, u := range users {
		found = found || u.Email == odd
	}
	if !found {
		t.Fatalf("stored email not carried verbatim: %+v", users)
	}
	// The values are raw now, so the results list escapes what it renders.
	for _, want := range []string{"'+esc(item.title)+'", "'+esc(item.sub)+'", "'+esc(item.url)+'"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("search results render %s unescaped", want)
		}
	}
}
