//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func readTestRevisionEnrollment(t *testing.T, dir string) *appMCPRevisionEnrollment {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, release, lease, err := acquireAppMCPWritePolicy(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	enrollment, err := readAppMCPRevisionEnrollment(lease)
	if err != nil {
		t.Fatal(err)
	}
	return enrollment
}

func verifyTestRevisionEnrollment(t *testing.T, app *App, generation *appMCPRuntimeGeneration) (*appMCPRevisionEnrollment, error) {
	t.Helper()
	ctx, release, lease, err := acquireAppMCPWritePolicy(context.Background(), app.Dir)
	if err != nil {
		return nil, err
	}
	defer release()
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	verified, err := verifyAppMCPRevisionEnrollmentForTx(ctx, app, generation, tx, lease)
	if err != nil {
		return nil, err
	}
	return verified.record, nil
}

func withTestRevisionCapability(t *testing.T, app *App, generation *appMCPRuntimeGeneration, use func(*appMCPVerifiedRevisionEnrollment) error) error {
	t.Helper()
	ctx, release, lease, err := acquireAppMCPWritePolicy(context.Background(), app.Dir)
	if err != nil {
		return err
	}
	defer release()
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	verified, err := verifyAppMCPRevisionEnrollmentForTx(ctx, app, generation, tx, lease)
	if err != nil {
		return err
	}
	return use(verified)
}

func captureTestRevisionDependencies(t *testing.T, app *App, generation *appMCPRuntimeGeneration, command appMCPRevisionCommand, intent map[string]any, actor Session) (*appMCPRevisionDependencySnapshot, error) {
	t.Helper()
	var result *appMCPRevisionDependencySnapshot
	err := withTestRevisionCapability(t, app, generation, func(verified *appMCPVerifiedRevisionEnrollment) error {
		var err error
		result, err = captureAppMCPDependencySetsForTx(verified, command, intent, actor)
		return err
	})
	return result, err
}

func compareTestRevisionDependencies(t *testing.T, app *App, generation *appMCPRuntimeGeneration, command appMCPRevisionCommand, intent map[string]any, actor Session, snapshot *appMCPRevisionDependencySnapshot) error {
	t.Helper()
	return withTestRevisionCapability(t, app, generation, func(verified *appMCPVerifiedRevisionEnrollment) error {
		return compareAppMCPDependencySetsForTx(verified, command, intent, actor, snapshot)
	})
}

func TestAppMCPRevisionEnrollmentUsesWholeUniverseAndBoundedCommandSubsets(t *testing.T) {
	hook := "on_update:\n  notes:\n    - sql: |\n        INSERT INTO lifecycle_markers(id,value) VALUES(2,'hook')\n"
	f := newCanonicalUpdateFixture(t, hook, "", "")
	generation := snapshotAppMCPGeneration(f.app)
	active, err := verifyTestRevisionEnrollment(t, f.app, generation)
	if err != nil {
		t.Fatalf("verify full enrollment: %v", err)
	}
	if !reflect.DeepEqual(active.TableNames, []string{"lifecycle_markers", "notes"}) {
		t.Fatalf("enrollment must cover authored SQL effects and canonical target: %v", active.TableNames)
	}
	caseVariant := *generation
	manifestVariant := *generation.manifest
	manifestVariant.Tools = append([]AppMCPTool(nil), generation.manifest.Tools...)
	for i := range manifestVariant.Tools {
		if manifestVariant.Tools[i].Effect == "write" {
			manifestVariant.Tools[i].Handler.Table = "NOTES"
		}
	}
	caseVariant.manifest = &manifestVariant
	tx, err := f.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	caseTables, err := appMCPRevisionUniverse(tx, &caseVariant, false)
	_ = tx.Rollback()
	if err != nil || !reflect.DeepEqual(caseTables, active.TableNames) {
		t.Fatalf("case-variant admitted table did not resolve to its one physical identity: %v (%v)", caseTables, err)
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.lifecycle_markers(id,value) VALUES(1,'seed')"); err != nil {
		t.Fatal(err)
	}
	actorPtr := GetSessionFromDB(f.app.DB, f.sid)
	if actorPtr == nil {
		t.Fatal("fixture actor session missing")
	}
	actor := *actorPtr
	commands := []appMCPRevisionCommand{
		{Name: "notes_read", Selectors: []appMCPRevisionSelector{{Name: "selected_note", Table: "notes", IntentField: "id", MaxRows: 1}}},
		{Name: "marker_read", Selectors: []appMCPRevisionSelector{{Name: "selected_marker", Table: "lifecycle_markers", IntentField: "id", MaxRows: 1}}},
	}
	for _, command := range commands {
		deps, err := captureTestRevisionDependencies(t, f.app, generation, command, map[string]any{"id": int64(1)}, actor)
		if err != nil || len(deps.Sets) != 1 || len(deps.Sets[0].Members) != 1 {
			t.Fatalf("capture command subset %q: deps=%+v err=%v", command.Name, deps, err)
		}
		if err := compareTestRevisionDependencies(t, f.app, generation, command, map[string]any{"id": int64(1)}, actor, deps); err != nil {
			t.Fatalf("unchanged bounded set %q rejected: %v", command.Name, err)
		}
		if err := compareTestRevisionDependencies(t, f.app, generation, command, map[string]any{"id": int64(2)}, actor, deps); err == nil {
			t.Fatalf("selector membership move for %q was accepted", command.Name)
		}
	}
	notesCommand := commands[0]
	notesSnapshot, err := captureTestRevisionDependencies(t, f.app, generation, notesCommand, map[string]any{"id": int64(1)}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.lifecycle_markers(id,value) VALUES(3,'unrelated')"); err != nil {
		t.Fatal(err)
	}
	if err := compareTestRevisionDependencies(t, f.app, generation, notesCommand, map[string]any{"id": int64(1)}, actor, notesSnapshot); err != nil {
		t.Fatalf("unrelated row change invalidated notes dependency set: %v", err)
	}
	if _, err := f.app.DB.Exec("UPDATE main.notes SET title='same-clock-first',updated_at='same-clock' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("UPDATE main.notes SET title='same-clock-second',updated_at='same-clock' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := compareTestRevisionDependencies(t, f.app, generation, notesCommand, map[string]any{"id": int64(1)}, actor, notesSnapshot); err == nil {
		t.Fatal("two same-clock updates preserved the prior dependency revision")
	}
	recreateSnapshot, err := captureTestRevisionDependencies(t, f.app, generation, notesCommand, map[string]any{"id": int64(1)}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("DELETE FROM main.notes WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.notes(id,user_id,title) VALUES(1,?,'recreated')", actor.UserID); err != nil {
		t.Fatal(err)
	}
	if err := compareTestRevisionDependencies(t, f.app, generation, notesCommand, map[string]any{"id": int64(1)}, actor, recreateSnapshot); err == nil {
		t.Fatal("delete-and-recreate reused a previously captured dependency revision")
	}
	tooManyRows := appMCPRevisionCommand{Name: "overbound", Selectors: []appMCPRevisionSelector{{Name: "id", Table: "notes", IntentField: "id", MaxRows: appMCPDependencySelectorRowsLimit + 1}}}
	if _, err := captureTestRevisionDependencies(t, f.app, generation, tooManyRows, map[string]any{"id": int64(1)}, actor); err == nil {
		t.Fatal("selector over-bound configuration was accepted")
	}
	duplicateSelectors := appMCPRevisionCommand{Name: "duplicate", Selectors: []appMCPRevisionSelector{
		{Name: "same", Table: "notes", IntentField: "id", MaxRows: 1},
		{Name: "same", Table: "lifecycle_markers", IntentField: "id", MaxRows: 1},
	}}
	if _, err := captureTestRevisionDependencies(t, f.app, generation, duplicateSelectors, map[string]any{"id": int64(1)}, actor); err == nil {
		t.Fatal("duplicate dependency selector names were accepted")
	}
	emptySetCommand := appMCPRevisionCommand{Name: "empty_markers", Selectors: []appMCPRevisionSelector{{Name: "matching_markers", Table: "lifecycle_markers", IntentField: "id", MaxRows: 2}}}
	emptySnapshot, err := captureTestRevisionDependencies(t, f.app, generation, emptySetCommand, map[string]any{"id": int64(999)}, actor)
	if err != nil || len(emptySnapshot.Sets) != 1 || len(emptySnapshot.Sets[0].Members) != 0 {
		t.Fatalf("empty dependency set must be explicit: %+v (%v)", emptySnapshot, err)
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.lifecycle_markers(id,value) VALUES(999,'phantom')"); err != nil {
		t.Fatal(err)
	}
	err = compareTestRevisionDependencies(t, f.app, generation, emptySetCommand, map[string]any{"id": int64(999)}, actor, emptySnapshot)
	if err == nil {
		t.Fatal("a row entering a previously empty command dependency set was accepted")
	}
	if _, err := f.app.DB.Exec("DELETE FROM main.lifecycle_markers WHERE id=999"); err != nil {
		t.Fatal(err)
	}
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), f.app, generation); err == nil {
		t.Fatal("initializer silently reused an existing active enrollment")
	}
	if _, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, generation); err != nil {
		t.Fatalf("explicit whole-universe repair: %v", err)
	}
	rotated, err := verifyTestRevisionEnrollment(t, f.app, generation)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.EnrollmentID == active.EnrollmentID || len(rotated.Tables) != len(active.Tables) {
		t.Fatal("explicit repair must rotate the independent enrollment and all table incarnations")
	}
	for i := range active.Tables {
		if rotated.Tables[i].Incarnation == active.Tables[i].Incarnation {
			t.Fatalf("repair reused table incarnation for %q", active.Tables[i].Table)
		}
	}
	if err := compareTestRevisionDependencies(t, f.app, generation, emptySetCommand, map[string]any{"id": int64(999)}, actor, emptySnapshot); err == nil {
		t.Fatal("empty dependency snapshot survived explicit enrollment repair")
	}
	state, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil || state.ApprovedWrites == nil || *state.ApprovedWrites {
		t.Fatalf("enrollment lifecycle unexpectedly enabled writes: %+v (%v)", state, err)
	}
}

func TestAppMCPRevisionEnrollmentRecognizesOnlyCapturedUpdatedAtTriggers(t *testing.T) {
	prisma := `model Member {
  id Int @id @default(autoincrement())
  org_id String
  email String
  @@map("members")
}
model Note {
  id Int @id
  user_id Int
  title String
  updated_at DateTime @updatedAt
  normalized String?
  secret String?
  @@fulltext([title])
  @@map("notes")
}
model GroupNote { id Int @id org_id String title String @@map("group_notes") }
model PublicNote { id Int @id title String @@map("public_notes") }
model NoteMember { user_id Int note_id Int @@map("note_members") }
model LifecycleMarker { id Int @id value String @@map("lifecycle_markers") }
`
	f := newCanonicalUpdateSourceFixtureWithSchema(t, "", "", "", prisma, false)
	generation := snapshotAppMCPGeneration(f.app)
	if string(generation.sourceFiles["schema.prisma"]) != prisma {
		t.Fatal("test generation did not capture the source Prisma schema")
	}
	models, err := ParsePrismaSchema(prisma)
	if err != nil {
		t.Fatal(err)
	}
	var notesHasFullText bool
	for _, model := range models {
		if model.Table == "notes" && len(model.FullText) > 0 {
			notesHasFullText = true
		}
	}
	if !strings.Contains(EmitSQL(models), "CREATE TRIGGER IF NOT EXISTS trg_notes_updated_at_updated") || !notesHasFullText {
		t.Fatal("Prisma parser/emitter did not produce the expected @updatedAt/full-text declarations")
	}
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), f.app, generation); err != nil {
		t.Fatalf("enroll actual Prisma-generated @updatedAt trigger: %v", err)
	}
	state, err := enableAppMCPRevisionEnrolledWrites(context.Background(), f.app, generation)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), f.app, f.uid, "17", "native-fixture", grantFixtureResource, "notes_update_title", f.now)
	if err != nil {
		t.Fatal(err)
	}
	pin := appMCPWriteAuthorityPin{
		Origin: f.app, Generation: generation, CredentialHash: mustAppMCPCredentialHash(t, pair.AccessToken, "access"),
		GrantID: pair.GrantID, AppID: state.App, Epoch: state.Epoch, WriteEpoch: state.ApprovedWriteEpoch,
		Resource: grantFixtureResource, Client: "native-fixture", Tenant: "17", UserID: f.uid,
		UserCreated: readUserCreatedForTest(t, f.app, f.uid), Permissions: strings.Fields(pair.Scopes),
	}
	var beforeUpdatedAt string
	if err := f.app.DB.QueryRow("SELECT updated_at FROM main.notes WHERE id=1").Scan(&beforeUpdatedAt); err != nil {
		t.Fatal(err)
	}
	// SQLite's CURRENT_TIMESTAMP has one-second precision; cross that boundary
	// so the trigger's write can be distinguished from a no-op.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), pin, "notes_update_title", canonicalTitleUpdate("updated-through-verified-trigger"), f.now); err != nil {
		t.Fatalf("command apply through verified @updatedAt trigger: %v", err)
	}
	var afterUpdatedAt string
	if err := f.app.DB.QueryRow("SELECT updated_at FROM main.notes WHERE id=1").Scan(&afterUpdatedAt); err != nil {
		t.Fatal(err)
	}
	if afterUpdatedAt == beforeUpdatedAt {
		t.Fatalf("generated @updatedAt trigger did not update timestamp: before=%q after=%q", beforeUpdatedAt, afterUpdatedAt)
	}
	var fullTextTrigger string
	if err := f.app.DB.QueryRow("SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name='notes_fts_au'").Scan(&fullTextTrigger); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("DROP TRIGGER notes_fts_au"); err != nil {
		t.Fatal(err)
	}
	changedFullTextTrigger := strings.Replace(fullTextTrigger, " END", " DELETE FROM lifecycle_markers WHERE id=1; END", 1)
	if changedFullTextTrigger == fullTextTrigger {
		t.Fatal("could not construct changed full-text trigger fixture")
	}
	if _, err := f.app.DB.Exec(changedFullTextTrigger); err != nil {
		t.Fatal(err)
	}
	ftsTx, err := f.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ftsErr := verifyAppMCPDeclaredTriggerClosure(ftsTx, generation, []string{"notes"}, false)
	_ = ftsTx.Rollback()
	if ftsErr == nil || !strings.Contains(ftsErr.Error(), "full-text index or sync triggers changed") {
		t.Fatalf("tampered full-text trigger was not refused by exact FTS closure: %v", ftsErr)
	}
	ftsBefore := canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), pin, "notes_update_title", canonicalTitleUpdate("must-not-apply-fts"), f.now); err == nil {
		t.Fatal("tampered full-text trigger was accepted by command apply")
	}
	if ftsAfter := canonicalEffectsSnapshot(t, f.app); ftsAfter != ftsBefore {
		t.Fatal("tampered full-text trigger refusal changed business or effect-ledger state")
	}
	if _, err := f.app.DB.Exec("DROP TRIGGER notes_fts_au"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec(fullTextTrigger); err != nil {
		t.Fatal(err)
	}
	fullTextDefinition, err := makeFTSDefinition("notes", []string{"title"})
	if err != nil {
		t.Fatal(err)
	}
	for _, trigger := range fullTextDefinition.triggers {
		if _, err := f.app.DB.Exec("DROP TRIGGER " + trigger.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.app.DB.Exec("DROP TABLE notes_fts"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("CREATE TABLE notes_fts(rowid INTEGER PRIMARY KEY, title TEXT)"); err != nil {
		t.Fatal(err)
	}
	indexTx, err := f.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	indexErr := verifyAppMCPDeclaredTriggerClosure(indexTx, generation, []string{"notes"}, false)
	_ = indexTx.Rollback()
	if indexErr == nil || !strings.Contains(indexErr.Error(), "full-text index or sync triggers changed") {
		t.Fatalf("replacement ordinary table was not refused as a full-text index: %v", indexErr)
	}
	if _, err := f.app.DB.Exec("DROP TABLE notes_fts"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec(fullTextDefinition.create); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range fullTextDefinition.triggers {
		if _, err := f.app.DB.Exec(trigger.sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.app.DB.Exec("INSERT INTO notes_fts(notes_fts) VALUES('rebuild')"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("DROP TRIGGER trg_notes_updated_at_updated"); err != nil {
		t.Fatal(err)
	}
	changed := `CREATE TRIGGER trg_notes_updated_at_updated AFTER UPDATE ON notes FOR EACH ROW BEGIN UPDATE notes SET updated_at=CURRENT_TIMESTAMP WHERE rowid=NEW.rowid; UPDATE lifecycle_markers SET value='unexpected' WHERE id=1; END`
	if _, err := f.app.DB.Exec(changed); err != nil {
		t.Fatal(err)
	}
	closureTx, err := f.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	closureErr := verifyAppMCPDeclaredTriggerClosure(closureTx, generation, []string{"notes"}, false)
	_ = closureTx.Rollback()
	if closureErr == nil || !strings.Contains(closureErr.Error(), "unrecognized or changed trigger") {
		t.Fatalf("tampered trigger was not rejected by trigger closure: %v", closureErr)
	}
	before := canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), pin, "notes_update_title", canonicalTitleUpdate("must-not-apply"), f.now); err == nil {
		t.Fatal("tampered @updatedAt trigger was accepted by command apply")
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != before {
		t.Fatal("tampered trigger refusal changed business state or side-effect ledgers")
	}
}

func TestAppMCPRevisionEnrollmentMissingRecordDeniesWithoutRequestRepair(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	ownerRoot := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
	record := filepath.Join(ownerRoot, f.pin.AppID+".revisions.json")
	ownerPath := filepath.Join(ownerRoot, f.pin.AppID+".json")
	canonicalPositiveThenReset(t, f)
	ownerBefore, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	state, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil || state.ApprovedWrites == nil || !*state.ApprovedWrites || state.Epoch != f.pin.Epoch || state.ApprovedWriteEpoch != f.pin.WriteEpoch {
		t.Fatalf("missing-record refusal must start with current enabled authority: %+v (%v)", state, err)
	}
	before := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app)
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("must-not-run"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("missing independent enrollment was accepted: %v", err)
	}
	if after := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app); after != before {
		t.Fatalf("missing-enrollment refusal changed DB state: before=%s after=%s", before, after)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("request path recreated missing enrollment: %v", err)
	}
	ownerAfter, err := os.ReadFile(ownerPath)
	if err != nil || string(ownerAfter) != string(ownerBefore) {
		t.Fatalf("missing-record refusal changed owner authority: %v", err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), f.app, snapshotAppMCPGeneration(f.app)); err == nil {
		t.Fatal("write enable accepted a missing independent enrollment")
	}
}

func TestAppMCPRevisionEnrollmentRefusesUnrecognizedAuthoredTriggerBeforePending(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	beforeRecord, err := os.ReadFile(filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".revisions.json"))
	if err != nil {
		t.Fatal(err)
	}
	beforeAuthority, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	beforeStorage := revisionStorageSnapshot(t, f.app)
	if _, err := f.app.DB.Exec(`CREATE TRIGGER authored_unknown AFTER UPDATE ON notes BEGIN INSERT INTO lifecycle_markers(id,value) VALUES(700,'trigger'); END`); err != nil {
		t.Fatal(err)
	}
	beforeStorage = revisionStorageSnapshot(t, f.app)
	if _, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, snapshotAppMCPGeneration(f.app)); err == nil {
		t.Fatal("explicit repair accepted an unrecognized authored SQLite trigger")
	}
	afterAuthority, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil || afterAuthority.Epoch != beforeAuthority.Epoch || afterAuthority.ApprovedWrites == nil || !*afterAuthority.ApprovedWrites {
		t.Fatalf("unsupported effect changed or disabled owner authority: %+v (%v)", afterAuthority, err)
	}
	afterRecord, err := os.ReadFile(filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".revisions.json"))
	if err != nil || string(afterRecord) != string(beforeRecord) {
		t.Fatalf("unsupported effect changed enrollment record: %v", err)
	}
	if afterStorage := revisionStorageSnapshot(t, f.app); afterStorage != beforeStorage {
		t.Fatalf("unsupported effect changed revision storage: before=%s after=%s", beforeStorage, afterStorage)
	}
}

func TestAppMCPRevisionEnrollmentUsesExactReservedTriggerPrefix(t *testing.T) {
	hook := "on_update:\n  notes:\n    - sql: |\n        INSERT INTO lifecycle_markers(id,value) VALUES(901,'hook')\n"
	f := newCanonicalUpdateFixture(t, hook, "", "")
	generation := snapshotAppMCPGeneration(f.app)
	if _, err := verifyTestRevisionEnrollment(t, f.app, generation); err != nil {
		t.Fatalf("real reserved-prefix revision triggers should verify: %v", err)
	}
	tx, err := f.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := appMCPExistingRevisionTriggers(tx)
	_ = tx.Rollback()
	if err != nil || len(reserved) == 0 {
		t.Fatalf("fixture did not install a real reserved-prefix trigger: %d (%v)", len(reserved), err)
	}
	for name := range reserved {
		if !strings.HasPrefix(name, "_benmore_mcp_rev_") {
			t.Fatalf("revision trigger %q does not use the exact reserved prefix", name)
		}
	}
	path := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".revisions.json")
	ownerPath := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".json")
	recordBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ownerBefore, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	dataBefore := canonicalEffectsSnapshot(t, f.app)
	if _, err := f.app.DB.Exec(`CREATE TRIGGER xbenmoreYmcpZrevQpayload AFTER UPDATE ON notes BEGIN INSERT INTO lifecycle_markers(id,value) VALUES(902,'lookalike'); END`); err != nil {
		t.Fatal(err)
	}
	storageBefore := revisionStorageSnapshot(t, f.app)
	assertEnrollmentVerifierDenied(t, f)
	if _, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, generation); err == nil {
		t.Fatal("explicit repair accepted a LIKE-lookalike reserved trigger")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(recordBefore) {
		t.Fatalf("lookalike trigger refusal changed enrollment bytes: %v", err)
	}
	if got, err := os.ReadFile(ownerPath); err != nil || string(got) != string(ownerBefore) {
		t.Fatalf("lookalike trigger refusal changed owner bytes: %v", err)
	}
	if got := revisionStorageSnapshot(t, f.app); got != storageBefore {
		t.Fatalf("lookalike trigger refusal changed sidecars: before=%s after=%s", storageBefore, got)
	}
	if got := canonicalEffectsSnapshot(t, f.app); got != dataBefore {
		t.Fatalf("lookalike trigger refusal changed business data: before=%s after=%s", dataBefore, got)
	}
}

// SQLite stores a trigger's tbl_name as written in its ON clause, so a trigger
// declared ON NOTES fires on enrolled notes yet escapes a BINARY tbl_name match.
func TestAppMCPRevisionEnrollmentRefusesCaseVariantOnClauseTrigger(t *testing.T) {
	hook := "on_update:\n  notes:\n    - sql: |\n        INSERT INTO lifecycle_markers(id,value) VALUES(901,'hook')\n"
	f := newCanonicalUpdateFixture(t, hook, "", "")
	generation := snapshotAppMCPGeneration(f.app)
	if _, err := verifyTestRevisionEnrollment(t, f.app, generation); err != nil {
		t.Fatalf("enrollment must verify before the case-variant trigger: %v", err)
	}
	path := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".revisions.json")
	ownerPath := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".json")
	recordBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ownerBefore, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	dataBefore := canonicalEffectsSnapshot(t, f.app)
	const name = "case_variant_notes_writer"
	if _, err := f.app.DB.Exec("CREATE TRIGGER " + name + " AFTER UPDATE ON NOTES BEGIN INSERT INTO lifecycle_markers(id,value) VALUES(903,'case-variant'); END"); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := f.app.DB.QueryRow("SELECT tbl_name FROM main.sqlite_schema WHERE type='trigger' AND name=?", name).Scan(&stored); err != nil || stored == "notes" {
		t.Fatalf("fixture must store a tbl_name a BINARY match misses: %q (%v)", stored, err)
	}
	storageBefore := revisionStorageSnapshot(t, f.app)
	if _, err := verifyTestRevisionEnrollment(t, f.app, generation); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("verifier accepted or misdiagnosed the case-variant trigger: %v", err)
	}
	if _, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, generation); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("explicit repair accepted or misdiagnosed the case-variant trigger: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(recordBefore) {
		t.Fatalf("case-variant refusal changed enrollment bytes: %v", err)
	}
	if got, err := os.ReadFile(ownerPath); err != nil || string(got) != string(ownerBefore) {
		t.Fatalf("case-variant refusal changed owner bytes: %v", err)
	}
	if got := revisionStorageSnapshot(t, f.app); got != storageBefore {
		t.Fatalf("case-variant refusal changed sidecars: before=%s after=%s", storageBefore, got)
	}
	if got := canonicalEffectsSnapshot(t, f.app); got != dataBefore {
		t.Fatalf("case-variant refusal changed business data: before=%s after=%s", dataBefore, got)
	}
}

func TestAppMCPRevisionSQLNormalizationPreservesQuotedSemantics(t *testing.T) {
	positives := [][2]string{
		{"CREATE TRIGGER IF NOT EXISTS t AFTER UPDATE ON main.notes BEGIN SELECT 'OPEN'; END", "create trigger t after update on notes begin select 'OPEN'; end"},
		{"CREATE TRIGGER IF NOT EXISTS main.\"rev_trigger\" AFTER UPDATE ON main.notes BEGIN SELECT 'same'; END", "create trigger \"rev_trigger\" after update on notes begin select 'same'; end"},
		{"CREATE TABLE IF NOT EXISTS main.notes (value TEXT)", "create table if not exists notes (value text)"},
		{"CREATE TRIGGER t AFTER UPDATE ON notes BEGIN SELECT 'a''b'; END", "create trigger t after update on notes begin select 'a''b'; end"},
	}
	for _, pair := range positives {
		if matches, err := appMCPRevisionSQLMatches(pair[0], pair[1]); err != nil || !matches {
			t.Errorf("harmless header normalization failed: %q ~= %q (%v)", pair[0], pair[1], err)
		}
	}
	negatives := [][2]string{
		{"SELECT 'OPEN'", "SELECT 'open'"},
		{"SELECT 'a  b'", "SELECT 'a b'"},
		{"SELECT 'main.secret'", "SELECT 'secret'"},
		{"SELECT \"A\"", "SELECT \"a\""},
	}
	for _, pair := range negatives {
		if matches, err := appMCPRevisionSQLMatches(pair[0], pair[1]); err != nil || matches {
			t.Errorf("quoted semantic change was normalized away: %q vs %q (%v)", pair[0], pair[1], err)
		}
	}
	if _, err := normalizeAppMCPRevisionSQL("SELECT 'unterminated"); err == nil {
		t.Fatal("malformed quoted SQL was accepted")
	}
	if _, err := appMCPRevisionSQLMatches("SELECT 'a''b'", "SELECT 'a'b'"); err == nil {
		t.Fatal("malformed SQL comparison was accepted")
	}
	if _, err := normalizeAppMCPRevisionSQL("SELECT [a][b]"); err != nil {
		t.Fatalf("adjacent valid bracket identifiers were rejected: %v", err)
	}
	for _, malformed := range []string{
		"SELECT 'unterminated",
		`SELECT "unterminated`,
		"SELECT [unterminated",
		"SELECT `unterminated",
		"SELECT [a][unterminated",
	} {
		if _, err := normalizeAppMCPRevisionSQL(malformed); err == nil {
			t.Errorf("malformed quoted SQL was accepted: %q", malformed)
		}
	}
}

func TestAppMCPRevisionEnrollmentRejectsTamperedComputedAndRevisionTriggers(t *testing.T) {
	for _, subtestName := range []string{"computed CASE literals", "revision trigger literal"} {
		subtestName := subtestName
		t.Run(subtestName, func(t *testing.T) {
			f := newCanonicalUpdateFixture(t, "", "", "")
			caseLiterals := subtestName == "computed CASE literals"
			if caseLiterals {
				writeTestFile(t, f.app.Dir, "computed.yaml", `fields:
  - table: notes
    column: normalized
    expr: "CASE WHEN title = 'OPEN' THEN 'main.secret' ELSE 'a  b' END"
`)
				reviewAppMCPFixture(t, f.app.Dir)
				if err := reloadAppConfig(f.app); err != nil {
					t.Fatalf("install captured CASE computed fixture: %v", err)
				}
				generation := snapshotAppMCPGeneration(f.app)
				if _, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, generation); err != nil {
					t.Fatalf("explicitly enroll captured CASE trigger: %v", err)
				}
				if _, err := verifyTestRevisionEnrollment(t, f.app, generation); err != nil {
					t.Fatalf("untampered CASE trigger positive control: %v", err)
				}
			}
			authorityRoot := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
			path := filepath.Join(authorityRoot, f.pin.AppID+".revisions.json")
			ownerPath := filepath.Join(authorityRoot, f.pin.AppID+".json")
			validRecord, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ownerBefore, err := os.ReadFile(ownerPath)
			if err != nil {
				t.Fatal(err)
			}
			var triggerName, original string
			if caseLiterals {
				if err := f.app.DB.QueryRow(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND name='_benmore_cf_notes_normalized_update'`).Scan(&triggerName, &original); err != nil {
					t.Fatal(err)
				}
			} else {
				revisionSQL := appMCPRevisionTriggerSQL("notes")
				if len(revisionSQL) == 0 {
					t.Fatal("notes revision trigger declaration is empty")
				}
				var count int
				if err := f.app.DB.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE type='trigger' AND tbl_name='notes' AND substr(name,1,17)='_benmore_mcp_rev_' AND name=?`, revisionSQL[0].name).Scan(&count); err != nil || count != 1 {
					t.Fatalf("expected one actual hashed revision trigger on notes, got %d (%v)", count, err)
				}
				if err := f.app.DB.QueryRow(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND tbl_name='notes' AND substr(name,1,17)='_benmore_mcp_rev_' AND name=?`, revisionSQL[0].name).Scan(&triggerName, &original); err != nil {
					t.Fatal(err)
				}
			}
			mutated := original
			if caseLiterals {
				mutated = strings.Replace(original, "'OPEN'", "'open'", 1)
			} else {
				mutated = strings.Replace(original, "'notes'", "'NOTES'", 1)
			}
			if mutated == original {
				t.Fatalf("test mutation did not change trigger SQL: %s", original)
			}
			if _, err := f.app.DB.Exec("DROP TRIGGER main." + quoteIdent(triggerName)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.app.DB.Exec(mutated); err != nil {
				t.Fatalf("install tampered native trigger: %v", err)
			}
			beforeDB := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app)
			assertEnrollmentVerifierDenied(t, f)
			if got, err := os.ReadFile(path); err != nil || string(got) != string(validRecord) {
				t.Fatalf("tampered %s trigger changed enrollment bytes: %v", subtestName, err)
			}
			if got, err := os.ReadFile(ownerPath); err != nil || string(got) != string(ownerBefore) {
				t.Fatalf("tampered %s trigger changed owner bytes: %v", subtestName, err)
			}
			if after := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app); after != beforeDB {
				t.Fatalf("tampered %s trigger refusal changed DB state", subtestName)
			}
		})
	}
}

func TestAppMCPRevisionEnrollmentRefusesComputedSecondaryWriteBeforePending(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	if _, err := f.app.DB.Exec(`CREATE TABLE unmanaged (value TEXT)`); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, f.app.Dir, "computed.yaml", `fields:
  - table: notes
    column: normalized
    expr: "0) WHERE rowid=NEW.rowid; UPDATE unmanaged SET value='extra'; UPDATE notes SET normalized=(0"
`)
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err != nil {
		t.Fatalf("install captured computed trigger fixture: %v", err)
	}
	beforeOwner, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if beforeOwner.ApprovedWrites == nil || *beforeOwner.ApprovedWrites {
		t.Fatalf("config reload did not fence writes before source validation: %+v", beforeOwner)
	}
	authorityRoot := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
	path := filepath.Join(authorityRoot, f.pin.AppID+".revisions.json")
	ownerPath := filepath.Join(authorityRoot, f.pin.AppID+".json")
	beforeRecord, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeOwnerBytes, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	var installed, installedSQL string
	if err := f.app.DB.QueryRow(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND name='_benmore_cf_notes_normalized_update'`).Scan(&installed, &installedSQL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(installedSQL), "update unmanaged set value='extra'") {
		t.Fatalf("native computed trigger lacks the captured secondary statement: %s", installedSQL)
	}
	beforeStorage := revisionStorageSnapshot(t, f.app)
	beforeData := canonicalEffectsSnapshot(t, f.app)
	if _, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, snapshotAppMCPGeneration(f.app)); err == nil {
		t.Fatal("computed fragment with a secondary write entered revision enrollment")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(beforeRecord) {
		t.Fatalf("unsupported computed fragment changed enrollment record: %v", err)
	}
	afterOwner, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil || afterOwner.ApprovedWrites == nil || *afterOwner.ApprovedWrites {
		t.Fatalf("unsupported computed fragment changed reload-fenced owner state: %+v (%v)", afterOwner, err)
	}
	if got, err := os.ReadFile(ownerPath); err != nil || string(got) != string(beforeOwnerBytes) {
		t.Fatalf("unsupported computed fragment refusal changed owner bytes: %v", err)
	}
	if after := revisionStorageSnapshot(t, f.app); after != beforeStorage {
		t.Fatalf("unsupported computed fragment changed enrollment sidecars: before=%s after=%s", beforeStorage, after)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != beforeData {
		t.Fatalf("unsupported computed fragment changed business data: before=%s after=%s", beforeData, after)
	}
}

func TestAppMCPRevisionEnrollmentDoesNotScanHooksForReadOnlyDependencies(t *testing.T) {
	flow := strings.Replace(commandTaskFlowFixture, "  dependencies:\n", `  dependencies:
    - name: selected_project
      table: projects
      query: SELECT id FROM projects WHERE id = :project_id AND org_id = :tenant
      params: {project_id: '${{ params.arguments.project_id }}', tenant: '${{ user.group_id }}'}
      max_rows: 1
`, 1)
	hooks := `on_update:
  projects:
    - sql: INSERT INTO _benmore_jobs(job_type,flow_name,payload) VALUES('flow','unrelated','{}')
`
	app, _, actorID := newUnenrolledCommandProviderTaskFixture(t, flow, hooks)
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatalf("establish fixture authority owner: %v", err)
	}
	generation := snapshotAppMCPGeneration(app)
	enrollment, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation)
	if err != nil {
		t.Fatalf("read-only project dependency must not enroll its unrelated update hook: %v", err)
	}
	if !slices.Contains(enrollment.TableNames, "projects") {
		t.Fatalf("read-only project dependency was omitted from revision enrollment: %v", enrollment.TableNames)
	}
	if slices.Contains(enrollment.TableNames, "_benmore_jobs") {
		t.Fatalf("framework job table entered the revision universe: %v", enrollment.TableNames)
	}
	activeSessionID := CreateSession(app.DB, actorID, "task-actor@example.com", "17", time.Hour)
	actor := GetSessionFromDB(app.DB, activeSessionID)
	if actor == nil || actor.UserID != actorID {
		t.Fatal("fixture actor session missing")
	}
	command := appMCPRevisionCommand{Name: "project_read", Selectors: []appMCPRevisionSelector{{Name: "selected_project", Table: "projects", IntentField: "project_id", MaxRows: 1}}}
	snapshot, err := captureTestRevisionDependencies(t, app, generation, command, map[string]any{"project_id": int64(7)}, *actor)
	if err != nil {
		t.Fatalf("capture bounded project dependency: %v", err)
	}
	if _, err := app.DB.Exec(`UPDATE main.projects SET org_id='18' WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	if err := compareTestRevisionDependencies(t, app, generation, command, map[string]any{"project_id": int64(7)}, *actor, snapshot); err == nil {
		t.Fatal("changed referenced project row did not invalidate the captured dependency")
	}
}

func TestAppMCPRevisionEnrollmentStillRejectsReservedWritesFromCommandHooks(t *testing.T) {
	hooks := `on_update:
  tasks:
    - sql: INSERT INTO _benmore_jobs(job_type,flow_name,payload) VALUES('flow','unsafe','{}')
`
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, hooks)
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatalf("establish fixture authority owner: %v", err)
	}
	beforeData := canonicalEffectsSnapshot(t, app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, snapshotAppMCPGeneration(app)); err == nil || !strings.Contains(err.Error(), `"_benmore_jobs"`) {
		t.Fatalf("reserved write through an actual command target hook was not refused: %v", err)
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if state.ApprovedWrites != nil && *state.ApprovedWrites {
		t.Fatalf("failed hook enrollment activated write authority: %+v", state)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), state.App+".revisions.json")); !os.IsNotExist(err) {
		t.Fatalf("failed hook enrollment left a revision record: %v", err)
	}
	if afterData := canonicalEffectsSnapshot(t, app); afterData != beforeData {
		t.Fatalf("failed hook enrollment changed business state: before=%s after=%s", beforeData, afterData)
	}
}

func TestAppMCPRevisionEnrollmentStillRejectsReservedWritesFromNativeUpdateHooks(t *testing.T) {
	hooks := `on_update:
  notes:
    - sql: INSERT INTO _benmore_jobs(job_type,flow_name,payload) VALUES('flow','unsafe','{}')
`
	f := newCanonicalUpdateSourceFixture(t, hooks, "", "", false)
	beforeData := canonicalEffectsSnapshot(t, f.app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), f.app, snapshotAppMCPGeneration(f.app)); err == nil || !strings.Contains(err.Error(), `"_benmore_jobs"`) {
		t.Fatalf("reserved write through native update hook was not refused: %v", err)
	}
	state, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if state.ApprovedWrites == nil || *state.ApprovedWrites {
		t.Fatalf("failed native hook enrollment activated write authority: %+v", state)
	}
	if afterData := canonicalEffectsSnapshot(t, f.app); afterData != beforeData {
		t.Fatalf("failed native hook enrollment changed business state: before=%s after=%s", beforeData, afterData)
	}
}

func TestAppMCPRevisionEnrollmentRefusesUncapturedForeignKeyCascadeBeforePending(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	beforeRecord, err := os.ReadFile(filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".revisions.json"))
	if err != nil {
		t.Fatal(err)
	}
	beforeAuthority, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec(`CREATE TABLE unmanaged_children (id INTEGER PRIMARY KEY, note_id INTEGER REFERENCES notes(id) ON UPDATE CASCADE)`); err != nil {
		t.Fatal(err)
	}
	beforeStorage := revisionStorageSnapshot(t, f.app)
	if _, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, snapshotAppMCPGeneration(f.app)); err == nil {
		t.Fatal("enrollment accepted a cascade into a physical table outside the captured app tables")
	}
	afterAuthority, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil || afterAuthority.Epoch != beforeAuthority.Epoch || afterAuthority.ApprovedWrites == nil || !*afterAuthority.ApprovedWrites {
		t.Fatalf("unsupported cascade changed owner authority: %+v (%v)", afterAuthority, err)
	}
	afterRecord, err := os.ReadFile(filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".revisions.json"))
	if err != nil || string(afterRecord) != string(beforeRecord) {
		t.Fatalf("unsupported cascade changed enrollment record: %v", err)
	}
	if afterStorage := revisionStorageSnapshot(t, f.app); afterStorage != beforeStorage {
		t.Fatalf("unsupported cascade changed revision storage: before=%s after=%s", beforeStorage, afterStorage)
	}
}

func TestAppMCPRevisionEnrollmentTracksTwoTableComputedUpdateAndRevisions(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	if _, err := f.app.DB.Exec("ALTER TABLE main.lifecycle_markers ADD COLUMN note_count INTEGER NOT NULL DEFAULT 0"); err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile(filepath.Join(f.app.Dir, "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	updatedSchema := strings.Replace(string(schema), "value TEXT NOT NULL);", "value TEXT NOT NULL, note_count INTEGER NOT NULL DEFAULT 0);", 1)
	if updatedSchema == string(schema) {
		t.Fatal("fixture lifecycle marker schema declaration was not found")
	}
	writeTestFile(t, f.app.Dir, "schema.sql", updatedSchema)
	writeTestFile(t, f.app.Dir, "computed.yaml", `fields:
  - table: lifecycle_markers
    column: note_count
    sql: "SELECT COUNT(*) FROM notes WHERE user_id = ?"
    triggers:
      - table: notes
        on: [update]
        fk: user_id
`)
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err != nil {
		t.Fatalf("load captured cross-table computed declaration: %v", err)
	}
	generation := snapshotAppMCPGeneration(f.app)
	if _, err := f.app.DB.Exec("INSERT INTO main.lifecycle_markers(id,value) VALUES(?,'computed-owner')", f.uid); err != nil {
		t.Fatal(err)
	}
	if _, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, generation); err != nil {
		t.Fatalf("enroll computed effect closure: %v", err)
	}
	active, err := verifyTestRevisionEnrollment(t, f.app, generation)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(active.TableNames, []string{"lifecycle_markers", "notes"}) {
		t.Fatalf("computed target missing from whole universe: %v", active.TableNames)
	}
	readRevision := func(table string, id int64) int64 {
		t.Helper()
		var revision int64
		var incarnation string
		if err := f.app.DB.QueryRow("SELECT incarnation FROM main._benmore_mcp_revision_tables WHERE table_name=?", table).Scan(&incarnation); err != nil {
			t.Fatal(err)
		}
		if err := f.app.DB.QueryRow("SELECT revision FROM main._benmore_mcp_row_revisions WHERE table_name=? AND incarnation=? AND key_type='integer' AND row_key=? AND deleted=0", table, incarnation, strconv.FormatInt(id, 10)).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		return revision
	}
	noteBefore, markerBefore := readRevision("notes", 1), readRevision("lifecycle_markers", f.uid)
	if _, err := f.app.DB.Exec("UPDATE main.notes SET title='aggregate-triggered' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.app.DB.QueryRow("SELECT note_count FROM main.lifecycle_markers WHERE id=?", f.uid).Scan(&count); err != nil || count != 1 {
		t.Fatalf("computed cross-table effect count=%d err=%v", count, err)
	}
	if noteAfter, markerAfter := readRevision("notes", 1), readRevision("lifecycle_markers", f.uid); noteAfter <= noteBefore || markerAfter <= markerBefore {
		t.Fatalf("computed update did not advance both actual row revisions: notes=%d->%d marker=%d->%d", noteBefore, noteAfter, markerBefore, markerAfter)
	}
}

func TestAppMCPRevisionEnrollmentCanonicalHookEffectsAndRollback(t *testing.T) {
	t.Run("committed hook effect advances both revisions", func(t *testing.T) {
		hook := "on_update:\n  notes:\n    - sql: |\n        INSERT INTO lifecycle_markers(id,value) VALUES(2,'canonical-hook')\n"
		f := newCanonicalUpdateFixture(t, hook, "", "")
		beforeInc, beforeRevision, _ := appMCPRevisionRow(t, f.app.DB, "notes", "integer", "1")
		if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("hooked"), f.now); err != nil {
			t.Fatalf("canonical update with SQL hook: %v", err)
		}
		noteInc, noteAfter, deleted := appMCPRevisionRow(t, f.app.DB, "notes", "integer", "1")
		if noteInc != beforeInc || noteAfter <= beforeRevision || deleted != 0 {
			t.Fatalf("canonical row revision did not advance: before=%q/%d after=%q/%d/%d", beforeInc, beforeRevision, noteInc, noteAfter, deleted)
		}
		markerInc, markerRevision, markerDeleted := appMCPRevisionRow(t, f.app.DB, "lifecycle_markers", "integer", "2")
		if markerInc == "" || markerRevision < 1 || markerDeleted != 0 {
			t.Fatalf("hook-created row lacks its actual enrolled revision: %q/%d/%d", markerInc, markerRevision, markerDeleted)
		}
	})
	t.Run("failed hook rolls back business and revision effects", func(t *testing.T) {
		hook := "on_update:\n  notes:\n    - sql: |\n        INSERT INTO lifecycle_markers(id,value) VALUES(2,'first');\n        INSERT INTO lifecycle_markers(id,value) VALUES(2,'duplicate')\n"
		f := newCanonicalUpdateFixture(t, hook, "", "")
		before := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app)
		if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("rollback"), f.now); err == nil {
			t.Fatal("duplicate hook insert unexpectedly committed")
		}
		if after := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app); after != before {
			t.Fatal("failed canonical hook changed business or revision state")
		}
	})
}

func TestAppMCPRevisionEnrollmentFailureBoundariesKeepWritesOff(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	stages := []struct {
		name        string
		stage       appMCPRevisionEnrollmentStage
		storeStage  string
		recordState string
		dbCommitted bool
		diskState   string // unchanged, pending, or active
		unknown     bool
	}{
		{name: "pending-file-sync", storeStage: "file_sync", recordState: "pending", diskState: "unchanged"},
		{name: "pending-before-rename", storeStage: "before_rename", recordState: "pending", diskState: "unchanged"},
		{name: "pending-directory-sync", storeStage: "directory_sync", recordState: "pending", diskState: "pending", unknown: true},
		{name: "before-begin", stage: appMCPRevisionStageBeforeBegin, diskState: "pending"},
		{name: "after-install", stage: appMCPRevisionStageAfterInstall, diskState: "pending"},
		{name: "after-verify", stage: appMCPRevisionStageAfterVerify, diskState: "pending"},
		{name: "before-commit", stage: appMCPRevisionStageBeforeCommit, diskState: "pending"},
		{name: "after-commit-before-active", stage: appMCPRevisionStageAfterCommit, dbCommitted: true, diskState: "pending"},
		{name: "active-before-rename", storeStage: "before_rename", recordState: "active", dbCommitted: true, diskState: "pending"},
		{name: "active-file-sync", storeStage: "file_sync", recordState: "active", dbCommitted: true, diskState: "pending"},
		{name: "active-directory-sync", storeStage: "directory_sync", recordState: "active", dbCommitted: true, diskState: "active", unknown: true},
	}
	for _, tc := range stages {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), f.app, snapshotAppMCPGeneration(f.app)); err != nil {
				t.Fatalf("checked-enable before %s: %v", tc.name, err)
			}
			enabled, err := currentAppMCPEpoch(f.app.Dir)
			if err != nil || enabled.ApprovedWrites == nil || !*enabled.ApprovedWrites {
				t.Fatalf("fault case %s did not start from enabled current authority: %+v (%v)", tc.name, enabled, err)
			}
			path := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".revisions.json")
			beforeRecord, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var beforeEnrollment appMCPRevisionEnrollment
			if err := json.Unmarshal(beforeRecord, &beforeEnrollment); err != nil {
				t.Fatal(err)
			}
			beforeDB := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app)
			previousEnrollmentFault := appMCPRevisionEnrollmentFault
			previousRecordFault := appMCPAuthorityRecordStoreFault
			t.Cleanup(func() {
				appMCPRevisionEnrollmentFault = previousEnrollmentFault
				appMCPAuthorityRecordStoreFault = previousRecordFault
			})
			ownerPath := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".json")
			hit := false
			writesAreOff := func() error {
				data, err := os.ReadFile(ownerPath)
				if err != nil {
					return err
				}
				var current appMCPEpochState
				if err := json.Unmarshal(data, &current); err != nil {
					return err
				}
				if current.ApprovedWrites == nil || *current.ApprovedWrites {
					return errors.New("writes were not disabled before enrollment fault boundary")
				}
				return nil
			}
			appMCPRevisionEnrollmentFault = func(appDir string, stage appMCPRevisionEnrollmentStage) error {
				if appDir == f.app.Dir && tc.stage != "" && stage == tc.stage {
					hit = true
					if err := writesAreOff(); err != nil {
						return err
					}
					return errors.New("test injected lifecycle boundary")
				}
				return nil
			}
			appMCPAuthorityRecordStoreFault = func(stage, name, recordState string) error {
				if tc.storeStage != "" && name == f.pin.AppID+".revisions.json" && stage == tc.storeStage && recordState == tc.recordState {
					hit = true
					if err := writesAreOff(); err != nil {
						return err
					}
					return errors.New("test injected atomic record boundary")
				}
				return nil
			}
			_, attemptErr := repairAppMCPRevisionEnrollment(context.Background(), f.app, snapshotAppMCPGeneration(f.app))
			appMCPRevisionEnrollmentFault = previousEnrollmentFault
			appMCPAuthorityRecordStoreFault = previousRecordFault
			if attemptErr == nil {
				t.Fatalf("failure stage %q unexpectedly succeeded", tc.name)
			}
			if !hit {
				t.Fatalf("failure injection for %q was not reached", tc.name)
			}
			var unknown *appMCPRevisionEnrollmentOutcomeUnknownError
			if tc.unknown && !errors.As(attemptErr, &unknown) {
				t.Fatalf("post-rename error was not reported as unknown: %v", attemptErr)
			}
			state, err := currentAppMCPEpoch(f.app.Dir)
			if err != nil || state.ApprovedWrites == nil || *state.ApprovedWrites {
				t.Fatalf("writes enabled after %s: %+v (%v)", tc.name, state, err)
			}
			afterRecord, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.diskState == "unchanged" {
				if string(afterRecord) != string(beforeRecord) {
					t.Fatalf("failed %s boundary changed enrollment record", tc.name)
				}
			} else {
				var record appMCPRevisionEnrollment
				if err := json.Unmarshal(afterRecord, &record); err != nil {
					t.Fatal(err)
				}
				if record.State != tc.diskState || record.OwnerEpoch != state.Epoch {
					t.Fatalf("record after %s is %+v, want %s bound to current owner epoch", tc.name, record, tc.diskState)
				}
			}
			afterDB := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app)
			if !tc.dbCommitted && afterDB != beforeDB {
				t.Fatalf("pre-commit failure %s changed DB state", tc.name)
			}
			if tc.dbCommitted && afterDB == beforeDB {
				t.Fatalf("post-commit failure %s did not retain committed DB repair", tc.name)
			}
			recovered, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, snapshotAppMCPGeneration(f.app))
			if err != nil {
				t.Fatalf("explicit recovery after %s: %v", tc.name, err)
			}
			if recovered.EnrollmentID == beforeEnrollment.EnrollmentID || len(recovered.Tables) != len(beforeEnrollment.Tables) {
				t.Fatalf("explicit recovery after %s reused prior enrollment identity", tc.name)
			}
			for i := range beforeEnrollment.Tables {
				if recovered.Tables[i].Incarnation == beforeEnrollment.Tables[i].Incarnation {
					t.Fatalf("explicit recovery after %s reused %q incarnation", tc.name, beforeEnrollment.Tables[i].Table)
				}
			}
		})
	}
}

func TestAppMCPRevisionEnrollmentProcessLockHelper(t *testing.T) {
	if os.Getenv("BENMORE_MCP_REVISION_LOCK_HELPER") != "1" {
		return
	}
	root := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
	marker := os.Getenv("BENMORE_MCP_REVISION_LOCK_MARKER")
	lock, err := os.OpenFile(filepath.Join(root, ".lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	busy := errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
	if err == nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	} else if !busy {
		_ = lock.Close()
		t.Fatal(err)
	}
	_ = lock.Close()
	if !busy {
		t.Fatal("child process did not observe the held native owner flock")
	}
	if err := publishLifecycleMarker(marker, "busy"); err != nil {
		t.Fatal(err)
	}
	_, release, _, err := acquireAppMCPWritePolicy(context.Background(), os.Getenv("BENMORE_MCP_REVISION_LOCK_APP"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := publishLifecycleMarker(marker, "acquired"); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPRevisionEnrollmentContendsOnRealCrossProcessOwnerLock(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	_, release, lease, err := acquireAppMCPWritePolicy(context.Background(), f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	marker := filepath.Join(t.TempDir(), "revision-lock-probe")
	cmd := exec.Command(os.Args[0], "-test.run=^TestAppMCPRevisionEnrollmentProcessLockHelper$")
	cmd.Env = append(os.Environ(),
		"BENMORE_MCP_REVISION_LOCK_HELPER=1",
		"BENMORE_MCP_AUTHORITY_DIR="+os.Getenv("BENMORE_MCP_AUTHORITY_DIR"),
		"BENMORE_MCP_REVISION_LOCK_APP="+f.app.Dir,
		"BENMORE_MCP_REVISION_LOCK_MARKER="+marker,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan struct{})
	var waitErr error
	t.Cleanup(func() {
		if !released {
			release()
			released = true
		}
		select {
		case <-waitDone:
		default:
			_ = cmd.Process.Kill()
			<-waitDone
		}
	})
	go func() {
		waitErr = cmd.Wait()
		close(waitDone)
	}()
	waitLifecycleMarker(t, marker, "busy")
	select {
	case <-waitDone:
		t.Fatalf("child acquired and released the real owner lock before parent released it: %v", waitErr)
	case <-time.After(100 * time.Millisecond):
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		t.Fatal(err)
	}
	release()
	released = true
	select {
	case <-waitDone:
		if waitErr != nil {
			t.Fatalf("cross-process enrollment lock helper: %v", waitErr)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-waitDone
		t.Fatal("child process did not acquire owner lock after parent release")
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "acquired" {
		t.Fatalf("child acquisition marker=%q err=%v", got, err)
	}
}

func TestAppMCPRevisionEnrollmentRejectsFinalPathReplacementAndModeChange(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	ctx, release, lease, err := acquireAppMCPWritePolicy(context.Background(), f.app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_ = ctx
	name := ".revision-path-identity-test"
	original, err := lease.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := original.Write([]byte("old")); err != nil {
		t.Fatal(err)
	}
	opened, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := lease.root.OpenFile(name+".next", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	replacementInfo, err := replacement.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.root.Rename(name+".next", name); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppMCPRevisionEnrollmentPathIdentity(lease.root, name, opened); err == nil {
		t.Fatal("final path replacement was accepted for a previously opened record")
	}
	current, err := lease.root.OpenFile(name, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := current.Chmod(0640); err != nil {
		t.Fatal(err)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppMCPRevisionEnrollmentPathIdentity(lease.root, name, replacementInfo); err == nil {
		t.Fatal("mode change after open was accepted for an enrollment record")
	}
}

func TestAppMCPRevisionEnrollmentRejectsExternalRecordCorruptionWithoutDBEffects(t *testing.T) {
	hook := "on_update:\n  notes:\n    - sql: |\n        INSERT INTO lifecycle_markers(id,value) VALUES(903,'hook')\n"
	f := newCanonicalUpdateFixture(t, hook, "", "")
	path := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".revisions.json")
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	base := readTestRevisionEnrollment(t, f.app.Dir)
	if len(base.Tables) < 2 || len(base.TableNames) < 2 || !sort.StringsAreSorted(base.TableNames) {
		t.Fatalf("reordered-entry control requires a sorted two-table universe, got %v", base.TableNames)
	}
	mutations := []struct {
		name   string
		mutate func(*appMCPRevisionEnrollment)
	}{
		{"wrong app", func(r *appMCPRevisionEnrollment) { r.App = "other-app" }},
		{"wrong epoch", func(r *appMCPRevisionEnrollment) { r.OwnerEpoch = strings.Repeat("0", 64) }},
		{"wrong version", func(r *appMCPRevisionEnrollment) { r.Version++ }},
		{"duplicate table", func(r *appMCPRevisionEnrollment) {
			r.TableNames = append(r.TableNames, r.TableNames[len(r.TableNames)-1])
		}},
		{"missing table", func(r *appMCPRevisionEnrollment) {
			r.TableNames = r.TableNames[:len(r.TableNames)-1]
			r.Tables = r.Tables[:len(r.Tables)-1]
		}},
		{"extra table", func(r *appMCPRevisionEnrollment) {
			r.TableNames = append(r.TableNames, "zz_extra")
			r.Tables = append(r.Tables, appMCPRevisionEnrollmentTable{Table: "zz_extra", Incarnation: strings.Repeat("1", 32), SchemaDigest: strings.Repeat("1", 64), TriggerSetDigest: strings.Repeat("1", 64)})
		}},
		{"reordered tables", func(r *appMCPRevisionEnrollment) {
			for i, j := 0, len(r.TableNames)-1; i < j; i, j = i+1, j-1 {
				r.TableNames[i], r.TableNames[j] = r.TableNames[j], r.TableNames[i]
				r.Tables[i], r.Tables[j] = r.Tables[j], r.Tables[i]
			}
		}},
		{"tampered incarnation", func(r *appMCPRevisionEnrollment) { r.Tables[0].Incarnation = strings.Repeat("0", 32) }},
		{"tampered schema digest", func(r *appMCPRevisionEnrollment) { r.Tables[0].SchemaDigest = strings.Repeat("0", 64) }},
		{"tampered trigger digest", func(r *appMCPRevisionEnrollment) { r.Tables[0].TriggerSetDigest = strings.Repeat("0", 64) }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			record := *base
			record.TableNames = append([]string(nil), base.TableNames...)
			record.Tables = append([]appMCPRevisionEnrollmentTable(nil), base.Tables...)
			tc.mutate(&record)
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(data, valid) {
				t.Fatalf("corruption mutation %q did not change canonical record bytes", tc.name)
			}
			assertEnrollmentCorruptionDenied(t, f, path, valid, data, 0600)
		})
	}
	assertEnrollmentCorruptionDenied(t, f, path, valid, append([]byte("{\"version\":1,"), valid[1:]...), 0600)
	assertEnrollmentCorruptionDenied(t, f, path, valid, append(append([]byte(nil), valid...), '\n'), 0600)
	assertEnrollmentCorruptionDenied(t, f, path, valid, valid, 0640)
	backup := path + ".held"
	if _, err := verifyTestRevisionEnrollment(t, f.app, snapshotAppMCPGeneration(f.app)); err != nil {
		t.Fatalf("untouched enrollment positive control failed before symlink corruption: %v", err)
	}
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, path); err != nil {
		t.Fatal(err)
	}
	beforeDB := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app)
	assertEnrollmentVerifierDenied(t, f)
	if after := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app); after != beforeDB {
		t.Fatal("symlink refusal changed the main database")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("SELECT 1"); err != nil {
		t.Fatal(err)
	}
}

func assertEnrollmentCorruptionDenied(t *testing.T, f appMCPCanonicalUpdateFixture, path string, valid, corrupt []byte, mode os.FileMode) {
	t.Helper()
	if _, err := verifyTestRevisionEnrollment(t, f.app, snapshotAppMCPGeneration(f.app)); err != nil {
		t.Fatalf("untouched enrollment positive control failed before corruption: %v", err)
	}
	beforeDB := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app)
	ownerPath := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), f.pin.AppID+".json")
	beforeOwner, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, corrupt, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	assertEnrollmentVerifierDenied(t, f)
	if after := canonicalEffectsSnapshot(t, f.app) + revisionStorageSnapshot(t, f.app); after != beforeDB {
		t.Fatal("corrupt enrollment verification changed the main database")
	}
	afterOwner, err := os.ReadFile(ownerPath)
	if err != nil || string(afterOwner) != string(beforeOwner) {
		t.Fatalf("corrupt verification changed owner bytes: %v", err)
	}
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertEnrollmentVerifierDenied(t *testing.T, f appMCPCanonicalUpdateFixture) {
	t.Helper()
	if _, err := verifyTestRevisionEnrollment(t, f.app, snapshotAppMCPGeneration(f.app)); err == nil {
		t.Fatal("corrupt external enrollment record was accepted")
	}
}

func revisionStorageSnapshot(t *testing.T, app *App) string {
	t.Helper()
	var registry, rows []map[string]any
	for _, item := range []struct {
		table string
		dest  *[]map[string]any
	}{
		{appMCPRevisionTablesName, &registry}, {appMCPRowRevisionsName, &rows},
	} {
		var exists int
		if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE type='table' AND name=?", item.table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists == 1 {
			values, err := queryRowsWithMainKey(app.DB, "SELECT * FROM main."+quoteIdent(item.table))
			if err != nil {
				t.Fatal(err)
			}
			*item.dest = values
		}
	}
	var triggers []map[string]any
	var err error
	triggers, err = queryRowsWithMainKey(app.DB, "SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := queryRowsWithMainKey(app.DB, "SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE type IN ('table','trigger') AND name NOT LIKE 'sqlite_%' ORDER BY type,name")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(struct{ Registry, Rows, Triggers, Schemas []map[string]any }{registry, rows, triggers, schemas})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestAppMCPRevisionEnrollmentActualRestoreRequiresExplicitRepair(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	old := readTestRevisionEnrollment(t, f.app.Dir)
	backup := filepath.Join(f.app.Dir, ".benmore", "backups", "revision-enrolled.db")
	if err := os.MkdirAll(filepath.Dir(backup), 0700); err != nil {
		t.Fatal(err)
	}
	if err := sqliteVacuumInto(filepath.Join(f.app.Dir, "data.db"), backup); err != nil {
		t.Fatalf("snapshot enrolled DB: %v", err)
	}
	if err := f.app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(f.app.Dir, backup); err != nil {
		t.Fatalf("restore enrolled DB through supported path: %v", err)
	}
	db, err := openDBWithEnv(f.app.Dir, f.app.environment)
	if err != nil {
		t.Fatal(err)
	}
	f.app.DB = db
	dbOnlyTx, err := f.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	dbOnlyErr := verifyAppMCPRevisionStorage(dbOnlyTx, old.TableNames)
	_ = dbOnlyTx.Rollback()
	if dbOnlyErr != nil {
		t.Fatalf("restored DB-only revision state should remain internally valid: %v", dbOnlyErr)
	}
	if _, err := updateAppMCPEpoch(f.app.Dir, true, false, false); err != nil {
		t.Fatalf("re-enable reviewed reads after restore: %v", err)
	}
	if _, err := verifyTestRevisionEnrollment(t, f.app, snapshotAppMCPGeneration(f.app)); err == nil {
		t.Fatal("restored DB accepted the prior external enrollment after reads were re-enabled")
	}
	repaired, err := repairAppMCPRevisionEnrollment(context.Background(), f.app, snapshotAppMCPGeneration(f.app))
	if err != nil {
		t.Fatalf("explicitly repair after restore: %v", err)
	}
	if repaired.EnrollmentID == old.EnrollmentID || len(repaired.Tables) != len(old.Tables) {
		t.Fatal("restore repair retained a pre-restore enrollment or incarnation")
	}
	for i := range old.Tables {
		if repaired.Tables[i].Incarnation == old.Tables[i].Incarnation {
			t.Fatalf("restore repair reused table incarnation for %q", old.Tables[i].Table)
		}
	}
	if _, err := verifyTestRevisionEnrollment(t, f.app, snapshotAppMCPGeneration(f.app)); err != nil {
		t.Fatalf("verify explicit post-restore repair: %v", err)
	}
}
