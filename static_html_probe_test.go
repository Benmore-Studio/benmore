//go:build !cli

package main

import "testing"

// TestIsScannerProbe locks the SPA-fallback guard: scanner probes (dotfiles,
// CMS markers, sensitive extensions) must hard-404, while real client routes
// — including dotted route params — must still fall through to the SPA.
func TestIsScannerProbe(t *testing.T) {
	probes := []string{
		"shop/.env", "web/.env", "var/www/.env", "root/.aws/credentials",
		"root/.netrc", "root/.git-credentials", "s3/.aws/config", ".git/config",
		"wp-content/mysql.sql", "wp-includes/wlwmanifest.xml", "xmlrpc.php",
		"test.php", "public/phpinfo.php", "terraform.tfstate", "terraform.tfvars",
		"wp_mail_smtp.ini", "settings.py", "stripe.env", "secrets.yaml",
		"src/config/stripe.ts", "cgi-bin/test.cgi",
	}
	for _, p := range probes {
		if !isScannerProbe(p) {
			t.Errorf("expected probe to be blocked (404): %q", p)
		}
	}

	legit := []string{
		"contacts", "shop/widgets", "dashboard", "blog/2026-04-launch",
		"profile/john.smith", "orders/INV.2026", "feed",
		".well-known/security.txt", "", "settings",
	}
	for _, p := range legit {
		if isScannerProbe(p) {
			t.Errorf("legit route wrongly blocked: %q", p)
		}
	}
}
