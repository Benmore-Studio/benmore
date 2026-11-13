//go:build !cli && !windows

package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// oneLine reads a reference or guide file with its line breaks and runs of
// spaces folded, so a sentence can be looked for wherever the file wraps it.
func oneLine(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(data)), " ")
}

// The connector guide said `${{ user.role }}` and `${{ user.is_admin }}` bind
// "in prepare and apply SQL only", the reference key says any phase, and the
// compiler accepts them in the SQL bindings of all three phases. Both texts
// state what the compiler does; the actor's email stays apply-only.
func TestConnectorTextsStateWhereTheActorRoleBinds(t *testing.T) {
	tables := map[string]bool{"tasks": true, "activities": true, "members": true}
	const readbackSQL = "WHERE t.id=:id AND t.project_id=:project_id AND t.org_id=:tenant\n          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}'}"
	bound := func(ref string) string {
		source := strings.Replace(commandTaskFlowFixture, readbackSQL,
			"WHERE t.id=:id AND t.project_id=:project_id AND t.org_id=:tenant AND :who IS NOT NULL\n          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}', who: '"+ref+"'}", 1)
		if source == commandTaskFlowFixture {
			t.Fatal("the task command fixture's readback SQL changed shape")
		}
		return source
	}
	for _, ref := range []string{"${{ user.role }}", "${{ user.is_admin }}"} {
		if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(bound(ref)), tables); err != nil {
			t.Errorf("%s bound in readback SQL is refused: %v", ref, err)
		}
		for _, phase := range []string{"prepare", "apply", "readback"} {
			if _, err := compileCommandPhaseSQLRef(ref, phase, nil, nil); err != nil {
				t.Errorf("%s in %s SQL is refused: %v", ref, phase, err)
			}
		}
	}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(bound("${{ user.email }}")), tables); err == nil {
		t.Error("${{ user.email }} bound in readback SQL is accepted; the texts say apply only")
	}

	const anyPhase = "in the SQL bindings of any phase (prepare, apply, readback)"
	for _, path := range []string{"docs/agent/connector.md", "docs/reference/connector/connector_command_sql.json"} {
		text := oneLine(t, path)
		if !strings.Contains(text, anyPhase) {
			t.Errorf("%s does not say the actor's role binds %s", path, anyPhase)
		}
		if strings.Contains(text, "in prepare and apply SQL only") {
			t.Errorf("%s still says the actor's role binds in prepare and apply SQL only", path)
		}
	}
}

// A table with a `blind_index:` encrypted field cannot be enrolled for
// approved writes. The key about trigger order listed "a blind index" among
// the fields an enrolled table may have, and the guide's troubleshooting row
// named a blind-index field as a cause on an enrolled table.
func TestConnectorTextsSayABlindIndexTableIsNotEnrolled(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, commandTaskFlowFixture, "", func(_ *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "encrypted.yaml", "tables:\n  activities:\n    fields:\n      - event\n    blind_index:\n      - event\n")
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	_, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation)
	if err == nil {
		_, err = enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation)
	}
	const refusal = "blind-index trigger closure for activities.event is not yet admitted"
	if err == nil || !strings.Contains(err.Error(), refusal) {
		t.Fatalf("enrolling a table with a blind index: %v, want %q", err, refusal)
	}

	order := oneLine(t, "docs/reference/connector/revision_trigger_order.txt")
	if strings.Contains(order, "computed field or a blind index") {
		t.Error("connector.revision_trigger_order lists a blind index among the fields of an enrolled table")
	}
	if !strings.Contains(order, "A table with a `blind_index:` field is not enrolled") || !strings.Contains(order, "blind-index trigger closure for <table>.<column> is not yet admitted") {
		t.Error("connector.revision_trigger_order does not say a table with a blind_index: field is refused, with the refusal's text")
	}
	if guide := oneLine(t, "docs/agent/connector.md"); strings.Contains(guide, "(an encrypted, computed or blind-index field)") {
		t.Error("the connector guide names a blind-index field on an enrolled table")
	}
}
