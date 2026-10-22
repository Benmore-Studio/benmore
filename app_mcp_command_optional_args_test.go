//go:build !cli && !windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// optionalArgsFlow is the task command with three optional, nullable arguments
// (string, number, boolean). The apply SQL records what SQLite actually received.
var optionalArgsFlow = func() string {
	s := commandTaskFlowFixture
	for old, replacement := range map[string]string{
		"      project_id: {type: integer, minimum: 1, maximum: 9007199254740991}\n  preview_schema:": "      project_id: {type: integer, minimum: 1, maximum: 9007199254740991}\n      note: {type: string, maxLength: 64, nullable: true}\n      priority: {type: [number, \"null\"], minimum: 0, maximum: 100}\n      flag: {type: boolean, nullable: true}\n  preview_schema:",

		"project_id: '${{ params.arguments.project_id }}'}\n            preview:": "project_id: '${{ params.arguments.project_id }}', note: '${{ params.arguments.note }}', priority: '${{ params.arguments.priority }}', flag: '${{ params.arguments.flag }}'}\n            preview:",

		"completed_at = datetime('now') WHERE": "completed_at = typeof(:note) || '/' || typeof(:prio) || '/' || typeof(:flag) || '/' || COALESCE(CAST(:flag AS TEXT), '-') WHERE",

		"params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', actor: '${{ user.id }}', tenant: '${{ user.group_id }}'}\n      - id: add_activity": "params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', actor: '${{ user.id }}', tenant: '${{ user.group_id }}', note: '${{ params.note }}', prio: '${{ params.priority }}', flag: '${{ params.flag }}'}\n      - id: add_activity",
	} {
		if !strings.Contains(s, old) {
			panic("optional args fixture drifted from commandTaskFlowFixture: " + old)
		}
		s = strings.Replace(s, old, replacement, 1)
	}
	return s
}()

func newOptionalArgsFixture(t *testing.T) (*App, string) {
	t.Helper()
	app, sessionID, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, optionalArgsFlow, "", func(m *AppMCPManifest, _ string) {
		args := m.Tools[0].InputSchema.Properties["arguments"]
		args.Properties["note"] = &AppMCPSchema{Type: "string", MaxLength: intPointer(64), Nullable: true}
		args.Properties["priority"] = &AppMCPSchema{Type: "number", Minimum: floatPointer(0), Maximum: floatPointer(100), Nullable: true}
		args.Properties["flag"] = &AppMCPSchema{Type: "boolean", Nullable: true}
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	return app, sessionID
}

func runOptionalArgsCommand(t *testing.T, app *App, sessionID string, arguments map[string]any) (*appMCPCommandPrepared, map[string]any, error) {
	t.Helper()
	var prepared *appMCPCommandPrepared
	var readback map[string]any
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		var err error
		if prepared, err = cap.prepare(map[string]any{"arguments": arguments}); err != nil {
			return false, err
		}
		_, readback, err = cap.apply(prepared)
		return err == nil, err
	})
	return prepared, readback, err
}

func TestAppMCPCommandOptionalArgumentsOmittedBindNull(t *testing.T) {
	app, sessionID := newOptionalArgsFixture(t)
	prepared, readback, err := runOptionalArgsCommand(t, app, sessionID, map[string]any{"id": 1, "project_id": 7})
	if err != nil {
		t.Fatalf("command with omitted optional arguments failed: %v", err)
	}
	// Missing is canonicalized to an explicit null in the sealed prepared arguments.
	for _, name := range []string{"note", "priority", "flag"} {
		if value, present := prepared.Arguments[name]; !present || value != nil {
			t.Fatalf("omitted %s must be sealed as explicit null, got present=%v value=%v", name, present, value)
		}
	}
	if readback["completed_at"] != "null/null/null/-" {
		t.Fatalf("omitted optionals did not bind SQL NULL: %v", readback["completed_at"])
	}
}

func TestAppMCPCommandOptionalArgumentsNullEqualsOmitted(t *testing.T) {
	app, sessionID := newOptionalArgsFixture(t)
	prepared, readback, err := runOptionalArgsCommand(t, app, sessionID, map[string]any{"id": 1, "project_id": 7, "note": nil, "priority": nil, "flag": nil})
	if err != nil {
		t.Fatalf("explicit nulls failed: %v", err)
	}
	if prepared.Arguments["note"] != nil || readback["completed_at"] != "null/null/null/-" {
		t.Fatalf("explicit null differs from omitted: %v %v", prepared.Arguments, readback["completed_at"])
	}
}

func TestAppMCPCommandStringNumberBooleanBindings(t *testing.T) {
	app, sessionID := newOptionalArgsFixture(t)
	_, readback, err := runOptionalArgsCommand(t, app, sessionID, map[string]any{"id": 1, "project_id": 7, "note": "hi", "priority": 2.5, "flag": true})
	if err != nil {
		t.Fatalf("typed optional arguments failed: %v", err)
	}
	if readback["completed_at"] != "text/real/integer/1" {
		t.Fatalf("string, number and boolean did not bind as text, real and integer 1: %v", readback["completed_at"])
	}
}

func TestAppMCPCommandBooleanFalseBindsZero(t *testing.T) {
	app, sessionID := newOptionalArgsFixture(t)
	_, readback, err := runOptionalArgsCommand(t, app, sessionID, map[string]any{"id": 1, "project_id": 7, "flag": false})
	if err != nil {
		t.Fatal(err)
	}
	if readback["completed_at"] != "null/null/integer/0" {
		t.Fatalf("false did not bind integer 0: %v", readback["completed_at"])
	}
}

func TestAppMCPCommandRequiredAndTypedArgumentsStillEnforced(t *testing.T) {
	app, sessionID := newOptionalArgsFixture(t)
	for name, arguments := range map[string]map[string]any{
		"missing required id": {"project_id": 7},
		"null required id":    {"id": nil, "project_id": 7},
		"number out of range": {"id": 1, "project_id": 7, "priority": 101},
		"string for number":   {"id": 1, "project_id": 7, "priority": "high"},
		"string for boolean":  {"id": 1, "project_id": 7, "flag": "yes"},
		"too long note":       {"id": 1, "project_id": 7, "note": strings.Repeat("x", 65)},
	} {
		if _, _, err := runOptionalArgsCommand(t, app, sessionID, arguments); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		assertCommandTaskUnchanged(t, app)
	}
}

// newPlainOptionalNoteFixture is the optional-arguments command with `note`
// optional but NOT nullable in the tool input and the prepared schema.
func newPlainOptionalNoteFixture(t *testing.T) (*App, string) {
	t.Helper()
	plain := strings.Replace(optionalArgsFlow, "note: {type: string, maxLength: 64, nullable: true}", "note: {type: string, maxLength: 64}", 1)
	if plain == optionalArgsFlow {
		t.Fatal("optional args fixture drifted: note is not declared nullable")
	}
	app, sessionID, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, plain, "", func(m *AppMCPManifest, _ string) {
		args := m.Tools[0].InputSchema.Properties["arguments"]
		args.Properties["note"] = &AppMCPSchema{Type: "string", MaxLength: intPointer(64)}
		args.Properties["priority"] = &AppMCPSchema{Type: "number", Minimum: floatPointer(0), Maximum: floatPointer(100), Nullable: true}
		args.Properties["flag"] = &AppMCPSchema{Type: "boolean", Nullable: true}
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	return app, sessionID
}

func TestAppMCPCommandOmittedNonNullableOptionalIsDroppedNotSealedNull(t *testing.T) {
	app, sessionID := newPlainOptionalNoteFixture(t)
	prepared, readback, err := runOptionalArgsCommand(t, app, sessionID, map[string]any{"id": 1, "project_id": 7})
	if err != nil {
		t.Fatalf("omitting an optional non-nullable argument failed: %v", err)
	}
	if _, present := prepared.Arguments["note"]; present {
		t.Fatalf("omitted non-nullable note must be left out of the sealed arguments, got %v", prepared.Arguments["note"])
	}
	// The nullable siblings keep their explicit null, and SQL still binds NULL.
	for _, name := range []string{"priority", "flag"} {
		if value, present := prepared.Arguments[name]; !present || value != nil {
			t.Fatalf("omitted nullable %s must stay an explicit null, got present=%v value=%v", name, present, value)
		}
	}
	if readback["completed_at"] != "null/null/null/-" {
		t.Fatalf("omitted optionals did not bind SQL NULL: %v", readback["completed_at"])
	}
	app, sessionID = newPlainOptionalNoteFixture(t)
	_, readback, err = runOptionalArgsCommand(t, app, sessionID, map[string]any{"id": 1, "project_id": 7, "note": "hi"})
	if err != nil || !strings.HasPrefix(readback["completed_at"].(string), "text/") {
		t.Fatalf("a supplied note must still bind as text: %v %v", readback, err)
	}
}
