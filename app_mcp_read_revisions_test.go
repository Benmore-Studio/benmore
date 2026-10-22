//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

func enrollNotesRevisions(t *testing.T, app *App) {
	t.Helper()
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeAppMCPRevisionStorage(tx, []string{"notes"}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func listNotes(t *testing.T, app *App, pair *appMCPTokenPair) *appMCPReadResult {
	t.Helper()
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAppMCPReadReturnsRealRevisionsThatChangeAfterWrite(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	enrollNotesRevisions(t, app)
	first := listNotes(t, app, pair)
	if slices.Contains(first.Warnings, "data_revision_unavailable") {
		t.Fatalf("enrolled read kept the unavailable warning: %v", first.Warnings)
	}
	if first.SourceRevisions["row:notes/1"] != "1" || first.SourceRevisions["row:notes/2"] != "1" || first.SourceRevisions["execution"] != app.MCP.ExecutionDigest {
		t.Fatalf("revisions: %v", first.SourceRevisions)
	}
	if _, foreign := first.SourceRevisions["row:notes/3"]; foreign {
		t.Fatalf("foreign row cited: %v", first.SourceRevisions)
	}
	auditExec(t, app.DB, "UPDATE notes SET title='edited' WHERE id=1")
	second := listNotes(t, app, pair)
	if second.SourceRevisions["row:notes/1"] != "2" || second.SourceRevisions["row:notes/2"] != "1" {
		t.Fatalf("revisions after write: %v", second.SourceRevisions)
	}
	auditExec(t, app.DB, "DELETE FROM notes WHERE id=2")
	third := listNotes(t, app, pair)
	if _, gone := third.SourceRevisions["row:notes/2"]; gone || third.SourceRevisions["row:notes/1"] != "2" {
		t.Fatalf("revisions after delete: %v", third.SourceRevisions)
	}
	empty, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"filters": map[string]any{"id": 99999}})
	if err != nil || slices.Contains(empty.Warnings, "data_revision_unavailable") || len(empty.SourceRevisions) != 2 {
		t.Fatalf("empty enrolled page: %+v %v", empty, err)
	}
}

func TestAppMCPSingleRowReadReturnsRowRevision(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, true)
	enrollNotesRevisions(t, app)
	read := func() *appMCPReadResult {
		result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"id": 1})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if before := read(); before.SourceRevisions["row:notes/1"] != "1" || len(before.Warnings) != 0 {
		t.Fatalf("single row: %+v", before)
	}
	auditExec(t, app.DB, "UPDATE notes SET title='edited' WHERE id=1")
	if after := read(); after.SourceRevisions["row:notes/1"] != "2" {
		t.Fatalf("single row after write: %+v", after)
	}
}

func TestAppMCPReadWithoutEnrollmentKeepsRevisionWarning(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	result := listNotes(t, app, pair)
	if !slices.Contains(result.Warnings, "data_revision_unavailable") || len(result.SourceRevisions) != 2 {
		t.Fatalf("not enrolled: %+v", result)
	}
}

func TestAppMCPReadOmitsRevisionsWhenTriggersChangedOrWriteInterleaves(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	enrollNotesRevisions(t, app)
	appMCPReadRevisionRace = func() { auditExec(t, app.DB, "UPDATE notes SET title='raced' WHERE id=1") }
	raced := listNotes(t, app, pair)
	appMCPReadRevisionRace = nil
	t.Cleanup(func() { appMCPReadRevisionRace = nil })
	if !slices.Contains(raced.Warnings, "data_revision_unavailable") || len(raced.SourceRevisions) != 2 {
		t.Fatalf("interleaved write still cited revisions: %+v", raced)
	}
	if settled := listNotes(t, app, pair); slices.Contains(settled.Warnings, "data_revision_unavailable") || settled.SourceRevisions["row:notes/1"] != "2" {
		t.Fatalf("revision read did not recover: %+v", settled)
	}
	var name string
	if err := app.DB.QueryRow("SELECT name FROM main.sqlite_schema WHERE type='trigger' AND name LIKE '%_delete'").Scan(&name); err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, `DROP TRIGGER main."`+name+`"`)
	if dropped := listNotes(t, app, pair); !slices.Contains(dropped.Warnings, "data_revision_unavailable") || len(dropped.SourceRevisions) != 2 {
		t.Fatalf("missing trigger still cited revisions: %+v", dropped)
	}
}

// A revision pin holds a pooled connection while the data read takes others.
// Concurrent reads must not pin the whole pool and then wait on each other
// until the read timeout (with the hosted 25-connection pool, 25 parallel
// connector reads stalled every query the app made).
func TestAppMCPConcurrentReadsDoNotPinWholePool(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	enrollNotesRevisions(t, app)
	app.DB.SetMaxOpenConns(4)
	const readers = 4
	var wg sync.WaitGroup
	errs := make([]error, readers)
	release := make(chan struct{})
	for i := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			// A stalled pool surfaces as the grant checks' own read timeout.
			_, errs[i] = runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{})
		}()
	}
	close(release)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("reader %d stalled on the pinned pool: %v", i, err)
		}
	}
	if pinned := app.mcpRevisionPins.Load(); pinned != 0 {
		t.Fatalf("revision pins leaked: %d", pinned)
	}
	if solo := listNotes(t, app, pair); slices.Contains(solo.Warnings, "data_revision_unavailable") {
		t.Fatalf("an uncontended read must still cite revisions: %+v", solo)
	}
}

func TestAppMCPReadRevisionsWithoutProjectedIDsCiteHighestOnly(t *testing.T) {
	app, _, _ := appMCPResultFixture(t, false)
	enrollNotesRevisions(t, app)
	auditExec(t, app.DB, "UPDATE notes SET title='edited' WHERE id=2")
	pin := pinAppMCPReadRevisions(context.Background(), app)
	defer pin.close()
	found, ok := pin.revisions(context.Background(), "notes", []map[string]any{{"id": json.Number("1")}, {"id": json.Number("2")}}, false)
	if !ok || len(found) != 1 || found["rows:notes"] != "2" {
		t.Fatalf("highest revision only: %v %v", found, ok)
	}
}

// Every code any producer can emit must be in the one documented set, and the
// set must be the documented one.
func TestAppMCPErrorCodeSetCoversEveryProducer(t *testing.T) {
	files, err := filepath.Glob("app_mcp_*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("producer files: %v %v", files, err)
	}
	failure := regexp.MustCompile(`appMCPResultFailure\("([a-z_]+)"\)`)
	meta := regexp.MustCompile(`"error_code": "([a-z_]+)"`)
	classReturn := regexp.MustCompile(`return "([a-z_]+)"`)
	emitted := map[string]bool{}
	scanned := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		source := string(raw)
		for _, re := range []*regexp.Regexp{failure, meta} {
			for _, match := range re.FindAllStringSubmatch(source, -1) {
				emitted[match[1]] = true
			}
		}
		if start := strings.Index(source, "func appMCPCommandErrorClass("); start >= 0 {
			body := source[start:]
			for _, match := range classReturn.FindAllStringSubmatch(body[:strings.Index(body, "\n}\n")], -1) {
				emitted[match[1]] = true
			}
			scanned++
		}
	}
	if scanned != 1 || len(emitted) < 5 {
		t.Fatalf("producer scan found %d class functions and codes %v", scanned, emitted)
	}
	delete(emitted, "already_approved") // internal class; appMCPCommandFailure reports it as denied
	for code := range emitted {
		if !slices.Contains(appMCPErrorCodes, code) {
			t.Errorf("emitted code %q is not in the stable set", code)
		}
	}
	for _, code := range appMCPErrorCodes {
		if got := appMCPSDKFailure(appMCPResultFailure(code)).Meta["error_code"]; got != code {
			t.Errorf("code %q is reported as %v", code, got)
		}
	}
	if got := appMCPSDKFailure(appMCPResultFailure("made_up")).Meta["error_code"]; got != "incomplete_result" {
		t.Errorf("unknown code leaked: %v", got)
	}
}
