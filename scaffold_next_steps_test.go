//go:build !cli

package main

import (
	"regexp"
	"strings"
	"testing"
)

// What `benmore new` prints as the next step names only what this edition
// runs. The framework edition printed `open http://localhost:8080` beside a
// scaffolded AGENTS.md that says there is no localhost development mode.
func TestNewNextStepsNameOnlyWhatThisEditionRuns(t *testing.T) {
	const dir = "/srv/apps/my app"
	out := scaffoldNextSteps(dir)
	if !strings.HasPrefix(out, "Created "+dir+"\n") {
		t.Errorf("does not start by naming the directory:\n%s", out)
	}
	for _, banned := range []string{"localhost", "127.0.0.1", "http://", "https://"} {
		if strings.Contains(out, banned) {
			t.Errorf("names a local address (%q):\n%s", banned, out)
		}
	}
	// Every command it names is one this edition's `help all` lists.
	named := regexp.MustCompile("benmore ([a-z][a-z-]*)").FindAllStringSubmatch(out, -1)
	if len(named) == 0 {
		t.Fatalf("names no command:\n%s", out)
	}
	for _, m := range named {
		if commandUsage(m[1]) == "" {
			t.Errorf("names `benmore %s`, which this edition (%s) does not list in help all:\n%s", m[1], editionName, out)
		}
	}
	want, absent := []string{"benmore deploy"}, []string{"benmore serve"}
	if editionName == "framework" {
		want = []string{`benmore serve "` + dir + `" --port 8080`, `benmore test "` + dir + `"`, "self-hosted", "AGENTS.md"}
		absent = []string{"benmore deploy", "benmore open", "benmore push"}
	}
	for _, s := range want {
		if !strings.Contains(out, s) {
			t.Errorf("%s edition: lacks %q:\n%s", editionName, s, out)
		}
	}
	for _, s := range absent {
		if strings.Contains(out, s) {
			t.Errorf("%s edition: names %q, which this edition's new app does not use:\n%s", editionName, s, out)
		}
	}
}
