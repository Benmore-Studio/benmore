//go:build !cli

package main

import (
	"reflect"
	"testing"
)

// Each instance owns its own media prefix: prod <sub>, the dev instance
// <sub>-dev. They used to share <sub>, so a dev instance's delete_upload and
// serve_file acted on production's objects. A dev instance still reads the
// shared prefix (its pre-split uploads and the production references
// refresh-dev copies into it); prod never reads dev's.
func TestAppMediaPrefix_PerInstance(t *testing.T) {
	prod := &App{Dir: "/srv/apps/myapp-a1b2c3"}
	dev := &App{Dir: "/srv/apps/myapp-a1b2c3-dev"}
	if got := appMediaPrefix(prod); got != "myapp-a1b2c3" {
		t.Errorf("prod prefix = %q, want myapp-a1b2c3", got)
	}
	if got := appMediaPrefix(dev); got != "myapp-a1b2c3-dev" {
		t.Errorf("dev prefix = %q, want myapp-a1b2c3-dev (its own namespace)", got)
	}
	if got := appMediaReadPrefixes(dev); !reflect.DeepEqual(got, []string{"myapp-a1b2c3-dev", "myapp-a1b2c3"}) {
		t.Errorf("dev read prefixes = %q, want its own then the shared one", got)
	}
	if got := appMediaReadPrefixes(prod); !reflect.DeepEqual(got, []string{"myapp-a1b2c3"}) {
		t.Errorf("prod read prefixes = %q, want only its own", got)
	}
	// trailing slash on Dir is tolerated
	if got := appMediaPrefix(&App{Dir: "/srv/apps/otherapp-x7y8z9-dev/"}); got != "otherapp-x7y8z9-dev" {
		t.Errorf("dev (trailing slash) prefix = %q, want otherapp-x7y8z9-dev", got)
	}
	if got := appMediaPrefix(nil); got != "_unknown" {
		t.Errorf("nil app = %q, want _unknown", got)
	}
	if got := appMediaReadPrefixes(nil); !reflect.DeepEqual(got, []string{"_unknown"}) {
		t.Errorf("nil app read prefixes = %q", got)
	}
}
