//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The auth: key check scanned lines with a two-space-indent regex, so a
// four-space indent, a flow mapping or a comment after `auth:` skipped it and
// `require_verifed: true` (verification OFF) passed the gate.
func TestAppYAMLAuthKeysCheckedWhateverTheLayout(t *testing.T) {
	for name, content := range map[string]string{
		"four-space":   "site_name: x\nauth:\n    identifier: email\n    require_verifed: true\n",
		"flow mapping": "site_name: x\nauth: { require_verifed: true }\n",
		"comment":      "site_name: x\nauth:   # sign-in settings\n  require_verifed: true\n",
		"trailing sp":  "site_name: x\nauth: \n  require_verifed: true\n",
	} {
		if msg := validateAppYAML(content); !strings.Contains(msg, "auth.require_verifed") {
			t.Errorf("%s: misspelled auth key accepted: %q", name, msg)
		}
	}
	if msg := validateAppYAML("site_name: x\ncsp:\n    scrpt_src: https://a.example\n"); !strings.Contains(msg, "csp.scrpt_src") {
		t.Errorf("four-space csp typo accepted: %q", msg)
	}
	if msg := validateAppYAML("site_name: x\n\"acess\":\n  notes: admin\n"); !strings.Contains(msg, "acess") {
		t.Errorf("quoted top-level typo accepted: %q", msg)
	}
}

// Every auth key the runtime reads must pass the gate: read_audit and
// edge_scopes are documented (api(at:"audit"), edges) yet were refused.
func TestAppYAMLAcceptsEveryRuntimeAuthKey(t *testing.T) {
	re := regexp.MustCompile(`\.Auth\["([a-z_]+)"\]`)
	files, _ := filepath.Glob("*.go")
	read := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			read[m[1]] = true
		}
	}
	if len(read) < 10 {
		t.Fatalf("found only %d runtime auth keys; the scan no longer matches the source", len(read))
	}
	for key := range read {
		if !knownAuthKeys[key] {
			t.Errorf("runtime reads auth.%s but the write gate refuses it", key)
		}
		value := "true"
		if key == "signup_rate_limit" {
			value = "30/10m" // has its own value grammar, checked at write time
		}
		if msg := validateAppYAML("site_name: x\nauth:\n  " + key + ": \"" + value + "\"\n"); strings.Contains(msg, "auth."+key) {
			t.Errorf("auth.%s refused: %s", key, msg)
		}
	}
	for key := range deadAuthKeys {
		if read[key] {
			t.Errorf("auth.%s is read by the runtime; it is not dead", key)
		}
		if msg := validateAppYAML("site_name: x\nauth:\n  " + key + ": true\n"); !strings.Contains(msg, "dead-auth-key") {
			t.Errorf("dead auth.%s accepted: %q", key, msg)
		}
	}
}

// access op keys other than read/write/update/delete/all are never read, so
// the op kept its broader fallback while the file read as restricted.
func TestAppYAMLRefusesUnreadAccessOps(t *testing.T) {
	for _, op := range []string{"create", "list", "raed", "edit", "remove"} {
		content := "site_name: x\naccess:\n  notes:\n    read: everyone\n    " + op + ": admin\n"
		if msg := validateAppYAML(content); !strings.Contains(msg, "not an access operation") {
			t.Errorf("access op %q accepted: %q", op, msg)
		}
	}
	good := "site_name: x\naccess:\n  default:\n    read: admin\n    all: admin\n  notes:\n    read: anon\n    write: self\n    update: self\n    delete: admin\n  comments: everyone\n"
	if msg := validateAppYAML(good); msg != "" {
		t.Errorf("valid access block refused: %s", msg)
	}
}

// Auth flags were compared to "true" only; YAML 1.2 hands yes/on/1 over as
// strings, so `require_verified: yes` left unverified accounts signed in.
func TestAuthFlagSpellingsCanonicalized(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("site_name: x\nauth:\n  require_verified: yes\n  otp: on\n  verify_email: \"1\"\n  read_audit_sync: no\n  oauth_only: false\n  signup: off\n  password_reset: no\n  api_tokens: 0\n  redirect: /home\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadAppConfigYAML(dir)
	if cfg == nil {
		t.Fatal("app.yaml did not load")
	}
	want := map[string]string{"require_verified": "true", "otp": "true", "verify_email": "true", "read_audit_sync": "false", "oauth_only": "false", "signup": "false", "password_reset": "false", "api_tokens": "false", "redirect": "/home"}
	for k, v := range want {
		if cfg.Auth[k] != v {
			t.Errorf("auth.%s = %q, want %q", k, cfg.Auth[k], v)
		}
	}
	if msg := validateAppYAML("site_name: x\nauth:\n  require_verified: always\n"); !strings.Contains(msg, "not a boolean") {
		t.Errorf("non-boolean require_verified accepted: %q", msg)
	}
	if msg := validateAppYAML("site_name: x\nauth:\n  require_verified: yes\n  otp: true\n"); msg != "" {
		t.Errorf("boolean spellings refused: %s", msg)
	}
}

// Feature switches: only "false" used to turn a string value off, so
// `ws_anonymous: no` opened /ws and /sse/events to anonymous clients.
func TestFeatureSwitchFalsySpellings(t *testing.T) {
	off := func(v any) bool {
		fc := parseFeaturesConfig(map[string]any{"ws_anonymous": v, "admin": v})
		return fc.WSAnonymous != nil && !*fc.WSAnonymous && !fc.IsEnabled("admin")
	}
	for _, v := range []any{"no", "off", "0", "No", false} {
		if !off(v) {
			t.Errorf("features value %v did not switch the feature off", v)
		}
	}
	if fc := parseFeaturesConfig(map[string]any{"ws_anonymous": "public"}); *fc.WSAnonymous {
		t.Error("an unrecognized ws_anonymous value opened the anonymous gate")
	}
	if fc := parseFeaturesConfig(map[string]any{"ws_anonymous": "yes"}); !*fc.WSAnonymous {
		t.Error("ws_anonymous: yes did not enable it")
	}
	if fc := parseFeaturesConfig(map[string]any{"docs": "auth"}); !fc.IsEnabled("docs") || !fc.DocsRequireAuth() {
		t.Error("docs: auth must stay enabled and require sign-in")
	}
	if msg := validateAppYAML("site_name: x\nfeatures:\n  docs: private\n"); msg == "" {
		t.Error("features.docs: private (read as public) accepted")
	}
	if msg := validateAppYAML("site_name: x\nfeatures:\n  ws_anonymus: true\n"); !strings.Contains(msg, "features.ws_anonymus") {
		t.Errorf("misspelled feature accepted: %q", msg)
	}
	if msg := validateAppYAML("site_name: x\nfeatures:\n  docs: auth\n  admin: false\n  ws_anonymous: no\n"); msg != "" {
		t.Errorf("valid features refused: %s", msg)
	}
	if msg := validateAppYAML("site_name: x\nfeatures:\n  account_settings: false\n"); msg != "" {
		t.Errorf("features.account_settings refused: %s", msg)
	}
	if msg := validateAppYAML("site_name: x\nfeatures:\n  account_settings: maybe\n"); msg == "" {
		t.Error("non-boolean features.account_settings accepted")
	}
	if parseFeaturesConfig(map[string]any{"account_settings": false}).IsEnabled("account_settings") {
		t.Error("features.account_settings: false did not disable account self-service")
	}
	if !(&FeaturesConfig{}).IsEnabled("account_settings") {
		t.Error("account self-service default changed")
	}
}

func TestAppYAMLGroupKeysChecked(t *testing.T) {
	base := "site_name: x\ngroups:\n  table: members\n  key: org_id\n  user_field: email\n"
	if msg := validateAppYAML(base + "  role_feild: role\n"); !strings.Contains(msg, "groups.role_feild") {
		t.Errorf("groups typo accepted: %q", msg)
	}
	if msg := validateAppYAML(base + "  bootstrap:\n    org_tabel: orgs\n"); !strings.Contains(msg, "groups.bootstrap.org_tabel") {
		t.Errorf("groups.bootstrap typo accepted: %q", msg)
	}
	if msg := validateAppYAML(base + "  role_field: role\n  active_field: active\n  bootstrap:\n    org_table: orgs\n    founding_role: owner\n"); msg != "" {
		t.Errorf("valid groups refused: %s", msg)
	}
}

// The inline app.yaml encrypted: section is documented and read by the
// runtime but was refused as an unknown key; an item written in the
// encrypted.yaml vocabulary lost its unmask roles (every reader saw
// plaintext), so it is refused at write and at load.
func TestAppYAMLInlineEncryptedShape(t *testing.T) {
	good := "site_name: x\nencrypted:\n  notes: [body]\n  patients:\n    - column: ssn\n      roles: [admin]\n"
	if msg := validateAppYAML(good); msg != "" {
		t.Fatalf("documented inline encrypted: refused: %s", msg)
	}
	enc := parseEncryptedFieldsConfig(nil, []byte(good))
	if enc == nil || len(enc.Fields["patients"]) != 1 || len(enc.Fields["patients"][0].Roles) != 1 {
		t.Fatalf("inline encrypted: did not parse: %+v", enc)
	}
	for name, bad := range map[string]string{
		"unmask_roles":   "site_name: x\nencrypted:\n  patients:\n    - column: ssn\n      unmask_roles: [admin]\n",
		"tables tree":    "site_name: x\nencrypted:\n  tables:\n    patients:\n      fields: [ssn]\n",
		"scalar table":   "site_name: x\nencrypted:\n  patients: ssn\n",
		"missing column": "site_name: x\nencrypted:\n  patients:\n    - roles: [admin]\n",
	} {
		if msg := validateAppYAML(bad); msg == "" {
			t.Errorf("%s: malformed inline encrypted: accepted", name)
		}
		if _, _, err := parseAppConfigDocument([]byte(bad)); err == nil {
			t.Errorf("%s: loader accepted malformed inline encrypted:", name)
		}
	}
}
