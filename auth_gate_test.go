package main

import "testing"

// TestEmailAllowedForApp locks the multi-domain + exception-allowlist
// gate for multi-domain signup/login restrictions.
func TestEmailAllowedForApp(t *testing.T) {
	mk := func(domain, allow string) *App {
		return &App{Design: &DesignConfig{Auth: map[string]string{
			"domain":       domain,
			"allow_emails": allow,
		}}}
	}

	cases := []struct {
		name  string
		app   *App
		email string
		want  bool
	}{
		{"no restriction → all allowed", mk("", ""), "anyone@gmail.com", true},
		{"nil app → allowed", nil, "x@y.com", true},
		{"single domain match", mk("example.org", ""), "founder@example.org", true},
		{"single domain miss", mk("example.org", ""), "evil@gmail.com", false},
		{"multi-domain first", mk("example.com,example.org", ""), "a@example.com", true},
		{"multi-domain second", mk("example.com,example.org", ""), "a@example.org", true},
		{"multi-domain miss", mk("example.com,example.org", ""), "a@other.net", false},
		{"allowlist bypass", mk("example.com,example.org", "founder@example.com"), "founder@example.com", true},
		{"allowlist second entry", mk("example.com", "a@gmail.com,bob@example.com"), "bob@example.com", true},
		{"not in allowlist + wrong domain", mk("example.com", "a@gmail.com"), "b@gmail.com", false},
		{"case-insensitive domain", mk("Example.COM", ""), "Founder@EXAMPLE.com", true},
		{"case-insensitive allowlist", mk("example.com", "Founder@Gmail.com"), "founder@gmail.com", true},
		{"@-prefixed domain config tolerated", mk("@example.org", ""), "x@example.org", true},
		{"substring-domain not fooled", mk("example.com", ""), "x@notexample.com", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := emailAllowedForApp(c.app, c.email)
			if got != c.want {
				t.Fatalf("emailAllowedForApp(%q) = %v (reason %q), want %v", c.email, got, reason, c.want)
			}
			if !got && reason == "" {
				t.Fatalf("denied %q but returned empty reason", c.email)
			}
		})
	}
}
