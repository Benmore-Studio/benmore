//go:build !cli && !windows

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

const appMCPOAuthHTTPOrigin = "https://fixture.example"

type appMCPOAuthHTTPFixture struct {
	app     *App
	mux     *http.ServeMux
	session *Session
	sid     string
	values  url.Values
}

func newAppMCPOAuthHTTPFixture(t *testing.T) *appMCPOAuthHTTPFixture {
	t.Helper()
	app, session, values, _, _ := appMCPOAuthFixture(t)
	// Session.ID is the stored hash. The browser cookie must carry the raw sid.
	sid := CreateSession(app.DB, session.UserID, session.Email, "17", time.Hour)
	session = GetSessionFromDB(app.DB, sid)
	app.Design = &DesignConfig{Auth: map[string]string{"enabled": "true"}}
	if !NeedsAuth(app) {
		t.Fatal("OAuth route registration requires auth")
	}
	app.Paths = DiscoverAuthPaths(nil)
	mux := buildAppMux(app, false, appMCPOAuthHTTPOrigin)
	return &appMCPOAuthHTTPFixture{app: app, mux: mux, session: session, sid: sid, values: values}
}

func (f *appMCPOAuthHTTPFixture) request(t *testing.T, method, path string, form url.Values, origin, host string) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, appMCPOAuthHTTPOrigin+path, body)
	if host != "" {
		r.Host = host
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.AddCookie(sessionCookie(f.sid, false, time.Hour))
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func appMCPOAuthHTTPHidden(t *testing.T, body string) url.Values {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	fields := make(url.Values)
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "input" {
			var name, value, kind string
			for _, attr := range node.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "value":
					value = attr.Val
				case "type":
					kind = attr.Val
				}
			}
			if name != "" && kind == "hidden" {
				fields.Add(name, value)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	return fields
}

func appMCPOAuthHTTPCount(t *testing.T, app *App, table string) int {
	t.Helper()
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func appMCPOAuthHTTPConsent(t *testing.T, f *appMCPOAuthHTTPFixture) url.Values {
	t.Helper()
	values := cloneMCPOAuthValues(f.values)
	values.Set("workspace", "17")
	w := f.request(t, http.MethodGet, "/oauth/authorize?"+values.Encode(), nil, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("authorize workspace: %d %s", w.Code, w.Body.String())
	}
	fields := appMCPOAuthHTTPHidden(t, w.Body.String())
	if fields.Get("connector_nonce") == "" || fields.Get("consent") == "" {
		t.Fatal("consent page omitted nonce-bound form")
	}
	return fields
}

func TestAppMCPOAuthHTTPWorkspaceChooserAndConsent(t *testing.T) {
	f := newAppMCPOAuthHTTPFixture(t)
	w := f.request(t, http.MethodGet, "/oauth/authorize?"+f.values.Encode(), nil, "", "")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `<select id="workspace"`) || !strings.Contains(body, `value="17"`) || !strings.Contains(body, `value="29"`) {
		t.Fatalf("workspace chooser: %d %s", w.Code, body)
	}
	if strings.Contains(body, "connector_nonce") || strings.Contains(body, "name=\"consent\"") || appMCPOAuthHTTPCount(t, f.app, "_benmore_mcp_authorizations") != 0 || appMCPOAuthHTTPCount(t, f.app, "_benmore_oauth_codes") != 0 {
		t.Fatal("workspace chooser minted consent or a code")
	}

	selected := cloneMCPOAuthValues(f.values)
	selected.Set("workspace", "17")
	w = f.request(t, http.MethodGet, "/oauth/authorize?"+selected.Encode(), nil, "", "")
	body = w.Body.String()
	fields := appMCPOAuthHTTPHidden(t, body)
	if !strings.Contains(body, "notes:read in workspace 17") || !strings.Contains(body, "client.example") || fields.Get("workspace") != "17" || fields.Get("connector_nonce") == "" || fields.Get("consent") == "" {
		t.Fatalf("consent did not disclose the scoped grant: %s", body)
	}
}

func TestAppMCPOAuthHTTPApproveExchangeRefreshAndRevoke(t *testing.T) {
	f := newAppMCPOAuthHTTPFixture(t)
	form := appMCPOAuthHTTPConsent(t, f)
	form.Set("decision", "approve")
	w := f.request(t, http.MethodPost, "/oauth/authorize", form, appMCPOAuthHTTPOrigin, "")
	if w.Code != http.StatusFound {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	callback, err := url.Parse(w.Header().Get("Location"))
	if err != nil || callback.Query().Get("state") != f.values.Get("state") || !strings.HasPrefix(callback.Query().Get("code"), "bmcc_") {
		t.Fatalf("bad authorization redirect: %q %v", w.Header().Get("Location"), err)
	}
	exchange := url.Values{"grant_type": {"authorization_code"}, "client_id": f.values["client_id"], "resource": f.values["resource"], "code": {callback.Query().Get("code")}, "redirect_uri": f.values["redirect_uri"], "code_verifier": {strings.Repeat("v", 43)}}
	w = f.request(t, http.MethodPost, "/oauth/token", exchange, "", "")
	var first struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || w.Code != http.StatusOK || !strings.HasPrefix(first.AccessToken, "bmca_") || !strings.HasPrefix(first.RefreshToken, "bmcr_") || first.Scope != "notes:read" {
		t.Fatalf("code exchange: %d %+v %v %s", w.Code, first, err, w.Body.String())
	}
	grant, actor, err := resolveAppMCPAccess(f.app, first.AccessToken, grantFixtureResource, time.Now())
	if err != nil || grant.Tenant != "17" || grant.Scopes != "notes:read" || actor.UserID != f.session.UserID {
		t.Fatalf("access was not pinned and narrow: %+v %+v %v", grant, actor, err)
	}
	var fixedExpiry int64
	if err := f.app.DB.QueryRow("SELECT expires_at FROM _benmore_mcp_grants WHERE id=?", grant.ID).Scan(&fixedExpiry); err != nil {
		t.Fatal(err)
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": f.values["client_id"], "resource": f.values["resource"], "refresh_token": {first.RefreshToken}, "scope": {"notes:read"}}
	invalidScope := cloneMCPOAuthValues(refresh)
	invalidScope.Set("scope", "notes:write")
	if bad := f.request(t, http.MethodPost, "/oauth/token", invalidScope, "", ""); bad.Code < 400 {
		t.Fatal("refresh widened scope")
	}
	w = f.request(t, http.MethodPost, "/oauth/token", refresh, "", "")
	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rotated); err != nil || w.Code != http.StatusOK || rotated.RefreshToken == first.RefreshToken || rotated.Scope != "notes:read" {
		t.Fatalf("refresh rotation: %d %+v %v %s", w.Code, rotated, err, w.Body.String())
	}
	var afterExpiry int64
	if err := f.app.DB.QueryRow("SELECT expires_at FROM _benmore_mcp_grants WHERE id=?", grant.ID).Scan(&afterExpiry); err != nil || afterExpiry != fixedExpiry {
		t.Fatalf("refresh extended grant lifetime: %d -> %d (%v)", fixedExpiry, afterExpiry, err)
	}
	revoke := url.Values{"client_id": f.values["client_id"], "resource": f.values["resource"], "token": {rotated.AccessToken}}
	wrongClient := cloneMCPOAuthValues(revoke)
	wrongClient.Set("client_id", "other-client")
	if wrong := f.request(t, http.MethodPost, "/oauth/revoke", wrongClient, "", ""); wrong.Code != 200 {
		t.Fatal("wrong-client token disclosure")
	}
	if _, _, err := resolveAppMCPAccess(f.app, rotated.AccessToken, grantFixtureResource, time.Now()); err != nil {
		t.Fatal("wrong client revoked grant")
	}

	w = f.request(t, http.MethodPost, "/oauth/revoke", revoke, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if _, _, err := resolveAppMCPAccess(f.app, rotated.AccessToken, grantFixtureResource, time.Now()); err == nil {
		t.Fatal("revoked access remained usable")
	}
	if repeated := f.request(t, http.MethodPost, "/oauth/revoke", revoke, "", ""); repeated.Code != 200 {
		t.Fatal("revocation not idempotent")
	}
	refresh.Set("refresh_token", rotated.RefreshToken)
	if denied := f.request(t, http.MethodPost, "/oauth/token", refresh, "", ""); denied.Code < 400 {
		t.Fatal("revoked successor refresh remained usable")
	}

}

func TestAppMCPOAuthHTTPMetadataRegistrationAndResourceDenials(t *testing.T) {
	f := newAppMCPOAuthHTTPFixture(t)
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/api/_mcp"} {
		w := f.request(t, http.MethodGet, path, nil, "", "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), appMCPOAuthHTTPOrigin) || !strings.Contains(w.Body.String(), "notes:read") {
			t.Errorf("metadata %s: %d %s", path, w.Code, w.Body.String())
		}
		var document struct {
			Issuer, Resource string
			Scopes           []string `json:"scopes_supported"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Scopes) != 1 || document.Scopes[0] != "notes:read" {
			t.Fatalf("metadata widened scopes: %+v", document)
		}
		if path == "/.well-known/oauth-authorization-server" {
			if document.Issuer != appMCPOAuthHTTPOrigin {
				t.Fatalf("wrong pinned issuer: %q", document.Issuer)
			}
		} else if document.Resource != grantFixtureResource {
			t.Fatalf("wrong pinned resource: %q", document.Resource)
		}
	}
	if unknown := f.request(t, http.MethodGet, "/.well-known/oauth-protected-resource/not-the-connector", nil, "", ""); unknown.Code != 404 {
		t.Fatal("invented resource metadata served")
	}
	w := f.request(t, http.MethodGet, "/.well-known/oauth-protected-resource/api/_mcp", nil, "", "attacker.example")
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "attacker.example") {
		t.Fatalf("hostile Host reflected in metadata: %d %s", w.Code, w.Body.String())
	}
	for name, resource := range map[string]string{"empty": "", "unknown": "https://fixture.example/api/_mcp/other"} {
		values := cloneMCPOAuthValues(f.values)
		values.Set("resource", resource)
		w := f.request(t, http.MethodGet, "/oauth/authorize?"+values.Encode(), nil, "", "")
		if w.Code < 400 || strings.Contains(w.Body.String(), "name=\"consent\"") {
			t.Errorf("%s resource authorize: %d %s", name, w.Code, w.Body.String())
		}
	}
	for _, redirect := range []string{"file://localhost/callback", "ftp://localhost/callback", "http://10.0.0.1/callback"} {
		payload, _ := json.Marshal(map[string]any{"client_name": "HTTP test", "redirect_uris": []string{redirect}})
		r := httptest.NewRequest(http.MethodPost, appMCPOAuthHTTPOrigin+"/oauth/register", strings.NewReader(string(payload)))
		r.Host = "fixture.example"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Errorf("unsafe redirect %q registered: %d %s", redirect, w.Code, w.Body.String())
		}
	}
	payload, _ := json.Marshal(map[string]any{"client_name": "HTTP default scope", "redirect_uris": []string{mcpOAuthFixtureRedirect}})
	r := httptest.NewRequest(http.MethodPost, appMCPOAuthHTTPOrigin+"/oauth/register", strings.NewReader(string(payload)))
	r.Host = "fixture.example"
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	var registered struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &registered); err != nil || w.Code != http.StatusCreated || registered.Scope != "notes:read" {
		t.Fatalf("registration default scope: %d %+v %v %s", w.Code, registered, err, w.Body.String())
	}
	// claude.ai registers with a scope of its own; unknown scopes are dropped,
	// never refused (a 400 here is the "Couldn't register" connector error).
	for requested, want := range map[string]string{"claudeai": "notes:read", "notes:read claudeai": "notes:read", "notes:write": "notes:read"} {
		payload, _ := json.Marshal(map[string]any{"client_name": "Claude", "redirect_uris": []string{mcpOAuthFixtureRedirect}, "scope": requested})
		r := httptest.NewRequest(http.MethodPost, appMCPOAuthHTTPOrigin+"/oauth/register", strings.NewReader(string(payload)))
		r.Host = "fixture.example"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		registered.Scope = ""
		if err := json.Unmarshal(w.Body.Bytes(), &registered); err != nil || w.Code != http.StatusCreated || registered.Scope != want {
			t.Errorf("registration scope %q: %d %+v %s", requested, w.Code, registered, w.Body.String())
		}
	}
	if got := appMCPOAuthHTTPCount(t, f.app, "_benmore_oauth_codes"); got != 0 {
		t.Fatalf("invalid resource requests minted %d legacy codes", got)
	}
}

func TestAppMCPOAuthHTTPRejectsTamperingAndConsumesDenial(t *testing.T) {
	f := newAppMCPOAuthHTTPFixture(t)
	cases := []struct {
		name   string
		mutate func(url.Values) (string, string)
	}{
		{name: "crosssite origin", mutate: func(url.Values) (string, string) { return "https://attacker.example", "" }},
		{name: "changed workspace", mutate: func(v url.Values) (string, string) { v.Set("workspace", "29"); return appMCPOAuthHTTPOrigin, "" }},
		{name: "duplicate resource", mutate: func(v url.Values) (string, string) {
			v.Add("resource", grantFixtureResource)
			return appMCPOAuthHTTPOrigin, ""
		}},
		{name: "duplicate form value", mutate: func(v url.Values) (string, string) { v.Add("decision", "deny"); return appMCPOAuthHTTPOrigin, "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := appMCPOAuthHTTPConsent(t, f)
			form.Set("decision", "approve")
			origin, host := tc.mutate(form)
			w := f.request(t, http.MethodPost, "/oauth/authorize", form, origin, host)
			if w.Code < 400 || w.Header().Get("Location") != "" {
				t.Fatalf("tampering accepted: %d %s", w.Code, w.Header().Get("Location"))
			}
		})
	}
	form := appMCPOAuthHTTPConsent(t, f)
	form.Set("decision", "approve")
	w := f.request(t, http.MethodPost, "/oauth/authorize?state=attacker", form, appMCPOAuthHTTPOrigin, "")
	if w.Code < 400 {
		t.Fatalf("query tampering accepted: %d %s", w.Code, w.Header().Get("Location"))
	}
	form = appMCPOAuthHTTPConsent(t, f)
	form.Set("decision", "deny")
	w = f.request(t, http.MethodPost, "/oauth/authorize", form, appMCPOAuthHTTPOrigin, "")
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "error=access_denied") {
		t.Fatalf("denial response: %d %s", w.Code, w.Header().Get("Location"))
	}
	form.Set("decision", "approve")
	w = f.request(t, http.MethodPost, "/oauth/authorize", form, appMCPOAuthHTTPOrigin, "")
	if w.Code < 400 || appMCPOAuthHTTPCount(t, f.app, "_benmore_oauth_codes") != 0 {
		t.Fatalf("denied nonce replay minted a code: %d %s", w.Code, w.Header().Get("Location"))
	}
	var used int
	if err := f.app.DB.QueryRow("SELECT used FROM _benmore_mcp_authorizations WHERE kind='consent' ORDER BY rowid DESC LIMIT 1").Scan(&used); err != nil || used != 1 {
		t.Fatalf("denial did not consume its nonce: used=%d err=%v", used, err)
	}
}

func TestAppMCPOAuthHTTPRevocationDoesNotAcknowledgeDatabaseFaults(t *testing.T) {
	for _, table := range []string{"_benmore_mcp_credentials", "_benmore_mcp_grants"} {
		t.Run(table, func(t *testing.T) {
			f := newAppMCPOAuthHTTPFixture(t)
			pair := fixtureGrant(t, f.app, f.session.UserID, time.Now())
			form := url.Values{"client_id": {"client-fixture"}, "resource": {grantFixtureResource}, "token": {pair.AccessToken}}
			auditExec(t, f.app.DB, "ALTER TABLE "+table+" RENAME TO temporarily_unavailable")
			response := f.request(t, http.MethodPost, "/oauth/revoke", form, "", "")
			auditExec(t, f.app.DB, "ALTER TABLE temporarily_unavailable RENAME TO "+table)
			if response.Code != 500 {
				t.Fatalf("database fault falsely acknowledged: %d", response.Code)
			}
			if _, _, err := resolveAppMCPAccess(f.app, pair.AccessToken, grantFixtureResource, time.Now()); err != nil {
				t.Fatalf("fault fixture did not preserve live grant: %v", err)
			}
			if response = f.request(t, http.MethodPost, "/oauth/revoke", form, "", ""); response.Code != 200 {
				t.Fatalf("recovered revocation: %d", response.Code)
			}
			if _, _, err := resolveAppMCPAccess(f.app, pair.AccessToken, grantFixtureResource, time.Now()); err == nil {
				t.Fatal("recovered revocation left access usable")
			}
		})
	}
}

func TestAppMCPOAuthHTTPRefreshNarrowsPersistedFamily(t *testing.T) {
	f := newAppMCPOAuthHTTPFixture(t)
	writeTestFile(t, f.app.Dir, "mcp.yaml", strings.Replace(appMCPManifestFixture(), "permissions: [notes:read]", "permissions: [notes:read, notes:inspect]", 1))
	reviewAppMCPFixture(t, f.app.Dir)
	config, err := loadRuntimeConfig(f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	f.app.MCP = config.mcp
	f.app.Roles.Roles["editor"] = RoleDef{Scopes: "notes:read notes:inspect"}
	pair, err := createAppMCPGrant(f.app, f.session.UserID, "17", "client-fixture", grantFixtureResource, "notes:read notes:inspect", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {pair.RefreshToken}, "client_id": {"client-fixture"}, "resource": {grantFixtureResource}, "scope": {"notes:read"}}
	response := f.request(t, http.MethodPost, "/oauth/token", form, "", "")
	var result struct {
		Scope       string
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != 200 || result.Scope != "notes:read" {
		t.Fatalf("scope reduction failed: status%d scope%q err%v", response.Code, result.Scope, err)
	}
	grant, actor, err := resolveAppMCPAccess(f.app, result.AccessToken, grantFixtureResource, time.Now())
	if err != nil || grant.Scopes != "notes:read" || actor.Scopes != "notes:read" {
		t.Fatalf("persisted family did not narrow: %v", err)
	}
}
