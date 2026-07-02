//go:build !cli

package main

import "testing"

// appMediaPrefix must key media by the LOGICAL app - a dev instance (<sub>-dev)
// shares prod's <sub> CDN prefix. Otherwise a file stored under <sub> (incl.
// prod data copied into dev via refresh-dev) signs to a <sub>-dev key that
// doesn't exist and CloudFront 403s.
func TestAppMediaPrefix_SharedAcrossEnv(t *testing.T) {
	prod := appMediaPrefix(&App{Dir: "/srv/apps/myapp-a1b2c3"})
	dev := appMediaPrefix(&App{Dir: "/srv/apps/myapp-a1b2c3-dev"})
	if prod != "myapp-a1b2c3" {
		t.Errorf("prod prefix = %q, want myapp-a1b2c3", prod)
	}
	if dev != prod {
		t.Errorf("dev prefix = %q, must equal prod prefix %q (media is shared per logical app)", dev, prod)
	}
	// trailing slash on Dir is tolerated
	if got := appMediaPrefix(&App{Dir: "/srv/apps/otherapp-x7y8z9-dev/"}); got != "otherapp-x7y8z9" {
		t.Errorf("dev (trailing slash) prefix = %q, want otherapp-x7y8z9", got)
	}
	if got := appMediaPrefix(nil); got != "_unknown" {
		t.Errorf("nil app = %q, want _unknown", got)
	}
}
