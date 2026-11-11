//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The enrollment otpauth URI was built with fmt.Sprintf, so a site_name with
// `&`, `:` or `?` broke it: "Shifts & Staff: R1105" made a standard parser
// read the issuer as "Shifts ", and a `?` pushed the secret out of the query.
// Every part is now percent-encoded and the issuer parameter carries the exact
// name.
func TestMFASetupOtpauthURIEncodesSiteName(t *testing.T) {
	const siteName = "Shifts & Staff: R1105? #1 100% +more"
	app := recoveryHardeningApp(t)
	app.Design.SEO["site_name"] = siteName
	app.Design.Auth["require_mfa_for_roles"] = "user"
	const email = "mgr+ops@example.test"
	recoveryUser(t, app, email, "Original!Password1", 1)
	mux := http.NewServeMux()
	RegisterMFARoutes(mux, app)

	grant := mfaRecoveryLogin(t, app, email, "Original!Password1")
	w := mfaRecoveryCall(mux, grant, "setup", "{}")
	var setup struct {
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauth_uri"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &setup) != nil || setup.Secret == "" {
		t.Fatalf("setup = %d %s", w.Code, w.Body.String())
	}

	u, err := url.Parse(setup.OtpauthURI)
	if err != nil {
		t.Fatalf("otpauth_uri does not parse: %v (%q)", err, setup.OtpauthURI)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Fragment != "" {
		t.Fatalf("otpauth_uri scheme/host/fragment = %q %q %q (%q)", u.Scheme, u.Host, u.Fragment, setup.OtpauthURI)
	}
	q := u.Query()
	if q.Get("secret") != setup.Secret {
		t.Errorf("secret parameter = %q, want the enrollment secret %q (%q)", q.Get("secret"), setup.Secret, setup.OtpauthURI)
	}
	if q.Get("issuer") != siteName {
		t.Errorf("issuer parameter = %q, want %q (%q)", q.Get("issuer"), siteName, setup.OtpauthURI)
	}
	if q.Get("digits") != "6" || q.Get("period") != "30" || len(q) != 4 {
		t.Errorf("query = %v, want exactly secret, issuer, digits=6, period=30", q)
	}
	// Label: "<issuer>:<account>" with no colon inside either part.
	label := strings.TrimPrefix(u.Path, "/")
	labelIssuer, account, ok := strings.Cut(label, ":")
	if !ok || strings.Contains(account, ":") {
		t.Fatalf("label %q is not issuer:account", label)
	}
	if labelIssuer != "Shifts & Staff R1105? #1 100% +more" || account != email {
		t.Errorf("label = %q / %q, want the site name without colons and the account email", labelIssuer, account)
	}
	if strings.Contains(setup.OtpauthURI, " ") {
		t.Errorf("otpauth_uri holds a raw space: %q", setup.OtpauthURI)
	}
}

// A plain name keeps the familiar shape authenticators expect.
func TestTOTPKeyURIPlainName(t *testing.T) {
	got := totpKeyURI("App", "member@example.test", "SECRETB32")
	want := "otpauth://totp/App:member%40example.test?secret=SECRETB32&issuer=App&digits=6&period=30"
	if got != want {
		t.Fatalf("totpKeyURI = %q, want %q", got, want)
	}
}
