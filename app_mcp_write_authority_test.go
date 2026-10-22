//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

func TestAppMCPApprovedWriteEpochIsSeparateAndFailClosed(t *testing.T) {
	epochFixture(t)
	app, cleanup := newTestApp(t)
	defer cleanup()
	readState, err := updateAppMCPEpoch(app.Dir, true, false, true)
	if err != nil || readState.Version != 1 {
		t.Fatalf("initial read state: %+v %v", readState, err)
	}
	writeState, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil || writeState.Version != 2 || writeState.ApprovedWrites == nil || !*writeState.ApprovedWrites || writeState.Epoch != readState.Epoch || writeState.ApprovedWriteEpoch == "" {
		t.Fatalf("write enable changed read authority or failed: %+v %v", writeState, err)
	}
	idempotent, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil || idempotent.ApprovedWriteEpoch != writeState.ApprovedWriteEpoch {
		t.Fatalf("same setting rotated authority: %+v %v", idempotent, err)
	}
	disabled, err := updateAppMCPEpoch(app.Dir, false, true, false)
	if err != nil || disabled.Exposed || disabled.ApprovedWrites == nil || *disabled.ApprovedWrites || disabled.ApprovedWriteEpoch == writeState.ApprovedWriteEpoch || disabled.Epoch == writeState.Epoch {
		t.Fatalf("general disable did not revoke both epochs: %+v %v", disabled, err)
	}
	if _, err := setAppMCPApprovedWrites(app.Dir, true); err == nil {
		t.Fatal("write authority enabled while read authority was disabled")
	}
	stillDisabled, err := currentAppMCPEpoch(app.Dir)
	if err != nil || stillDisabled.Exposed || stillDisabled.ApprovedWrites == nil || *stillDisabled.ApprovedWrites {
		t.Fatalf("rejected write enable changed authority: %+v %v", stillDisabled, err)
	}
	reenabled, err := updateAppMCPEpoch(app.Dir, true, false, false)
	if err != nil || !reenabled.Exposed || reenabled.ApprovedWrites == nil || *reenabled.ApprovedWrites {
		t.Fatalf("read enable restored write authority: %+v %v", reenabled, err)
	}
	enabledAgain, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	disabledWrite, err := setAppMCPApprovedWrites(app.Dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if disabledWrite.Epoch != enabledAgain.Epoch || disabledWrite.ApprovedWriteEpoch == enabledAgain.ApprovedWriteEpoch {
		t.Fatalf("write toggle rotated the read epoch or retained write epoch: %+v %+v", enabledAgain, disabledWrite)
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil || state.ApprovedWrites == nil || *state.ApprovedWrites {
		t.Fatalf("explicit disable not persisted: %+v %v", state, err)
	}
}

func TestAppMCPWriteAuthorityUsesPinnedTransactionAndMainSchema(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	app.DB.SetMaxOpenConns(1)
	pair := fixtureGrant(t, app, uid, now)
	if _, err := app.DB.Exec("ALTER TABLE main.members ADD COLUMN member_role TEXT"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE main.members SET member_role='editor' WHERE org_id='17'"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_users SET role='unmapped' WHERE id=?", uid); err != nil {
		t.Fatal(err)
	}
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"unmapped": {}, "editor": {Scopes: "notes:read"}}}
	app.Group.RoleField = "member_role"
	state, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	pin := appMCPWriteAuthorityPin{
		Origin: app, Generation: generation, CredentialHash: mustAppMCPCredentialHash(t, pair.AccessToken, "access"),
		GrantID: pair.GrantID, AppID: state.App, Epoch: state.Epoch, WriteEpoch: state.ApprovedWriteEpoch,
		Resource: grantFixtureResource, Client: "client-fixture", Tenant: "17", UserID: uid,
		UserCreated: readUserCreatedForTest(t, app, uid), Permissions: []string{"notes:read"},
	}
	// Establish that this fixture is valid before testing TEMP shadows.
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if authority, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now); err != nil || authority == nil || authority.Actor.UserID != uid || authority.Actor.GroupID != "17" {
		_ = tx.Rollback()
		t.Fatalf("authority denied before TEMP shadows: %+v %v", authority, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	// Temp decoys on the sole pooled connection must not replace main authority,
	// including the database identity lookup used for encrypted memberships.
	for _, statement := range []string{
		`CREATE TEMP TABLE pragma_database_list(file TEXT,seq INTEGER,name TEXT)`,
		`INSERT INTO temp.pragma_database_list VALUES('/decoy.db',0,'main')`,
		`CREATE TEMP TABLE pragma_table_info(cid INTEGER,name TEXT,type TEXT)`,
		`CREATE TEMP TABLE _benmore_users(id INTEGER PRIMARY KEY,email TEXT,role TEXT,deactivated_at TEXT,verified INTEGER,email_grandfathered INTEGER,password_change_required INTEGER,created_at TEXT)`,
		`CREATE TEMP TABLE _benmore_user_roles(user_id INTEGER,role TEXT,group_id TEXT,expires_at TEXT)`,
		`CREATE TEMP TABLE members(org_id TEXT,email TEXT,deleted_at TEXT,member_role TEXT)`,
		`CREATE TEMP TABLE _benmore_mcp_grants AS SELECT * FROM main._benmore_mcp_grants`,
		`CREATE TEMP TABLE _benmore_mcp_credentials AS SELECT * FROM main._benmore_mcp_credentials`,
		`UPDATE temp._benmore_mcp_grants SET revoked=1`,
		`UPDATE temp._benmore_mcp_credentials SET used=1,expires_at=0`,
	} {
		if _, err := app.DB.Exec(statement); err != nil {
			t.Fatalf("install TEMP decoy: %v", err)
		}
	}
	tx, err = app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	authority, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
	if err != nil || authority == nil || authority.Actor.UserID != uid || authority.Actor.GroupID != "17" || authority.Actor.IsAdminBypass() || authority.Actor.connectorGrant != true || authority.GrantID != pair.GrantID {
		_ = tx.Rollback()
		var denied *appMCPWriteAuthorityError
		if errors.As(err, &denied) {
			t.Fatalf("main pinned authority denied or changed: %+v %v (cause: %v)", authority, err, denied.cause)
		}
		t.Fatalf("main pinned authority denied or changed: %+v %v", authority, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_grants SET revoked=1 WHERE id=?", pair.GrantID); err != nil {
		t.Fatal(err)
	}
	var notesBefore, notesAfter int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&notesBefore); err != nil {
		t.Fatal(err)
	}
	tx, err = app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
	_ = tx.Rollback()
	if !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("revoked grant did not fail opaquely: %v", err)
	}
	if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&notesAfter); err != nil || notesAfter != notesBefore {
		t.Fatalf("revoked grant changed business rows: before=%d after=%d err=%v", notesBefore, notesAfter, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tx, err = app.DB.BeginTx(context.Background(), nil)
	if err == nil {
		defer tx.Rollback()
		_, err = appMCPWriteAuthorityForTx(ctx, tx, pin, now)
		_ = tx.Rollback()
	}
	// A cancelled context is an infrastructure failure, not an authorization
	// refusal: it keeps its cause and is not reported as a denial.
	if err == nil || errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("canceled authority context was reported as a denial: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authority cause was discarded: %v", err)
	}
	if appMCPCommandErrorClass(err) != "unavailable_provider" {
		t.Fatalf("canceled authority context class: %q", appMCPCommandErrorClass(err))
	}
}

func TestAppMCPAuthorityRequiresPerDatabaseKeyAndLoaderRegistersWithoutEncryptedYAML(t *testing.T) {
	oldIsolation := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(true)
	t.Cleanup(func() { isolateAppEnvironment.Store(oldIsolation) })
	oldGlobalKey := appEncryptionKey
	appEncryptionKey = []byte("synthetic ambient key must not authorize")
	t.Cleanup(func() { appEncryptionKey = oldGlobalKey })
	raw, _ := auditApp(t)
	if _, err := cryptoKeyForQuerierMainChecked(raw.DB); err == nil {
		t.Fatal("unregistered database inherited ambient encryption-key authority")
	}

	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: key-registration-control\n")
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: 4242424242424242424242424242424242424242424242424242424242424242\n")
	loaded, err := loadApp(dir)
	if err != nil {
		t.Fatal("real loader failed without encrypted.yaml:", err)
	}
	defer loaded.Shutdown()
	if _, err := os.Stat(filepath.Join(dir, "encrypted.yaml")); !os.IsNotExist(err) {
		t.Fatalf("key-registration control unexpectedly had encrypted.yaml: %v", err)
	}
	registered := cryptoKeysForDBPath(filepath.Join(dir, "data.db"))
	if registered == nil || len(registered.aes) != 32 {
		t.Fatalf("real loader did not register its database owner key: %+v", registered)
	}
	tx, err := loaded.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	key, err := cryptoKeyForQuerierMainChecked(tx)
	_ = tx.Rollback()
	if err != nil || len(key) != 32 || string(key) != string(registered.aes) {
		t.Fatalf("strict transaction did not resolve the registered owner key: length=%d err=%v", len(key), err)
	}
}

func TestAppMCPWriteAuthoritySupportsIDKeyedMembershipRole(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	if _, err := app.DB.Exec("ALTER TABLE main.members ADD COLUMN member_role TEXT"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("ALTER TABLE main.members ADD COLUMN user_id INTEGER"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE main.members SET member_role='editor',user_id=? WHERE org_id='17'", uid); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE main._benmore_users SET role='unmapped' WHERE id=?", uid); err != nil {
		t.Fatal(err)
	}
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"unmapped": {}, "editor": {Scopes: "notes:read"}}}
	app.Group.RoleField = "member_role"
	app.Group.UserField = "user_id"
	pair := fixtureGrant(t, app, uid, now)
	state, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	pin := appMCPWritePinForTest(t, app, uid, pair, state)
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	authority, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
	_ = tx.Rollback()
	if err != nil || authority == nil || authority.Actor.GroupID != "17" {
		t.Fatalf("ID-keyed member did not resolve: %+v %v", authority, err)
	}
}

func TestAppMCPWriteAuthorityPreservesSQLFailureCause(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	state, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	pin := appMCPWritePinForTest(t, app, uid, pair, state)
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("authority was not positive before schema fault: %v", err)
	}
	_ = tx.Rollback()
	if _, err := app.DB.Exec("DROP TABLE main.members"); err != nil {
		t.Fatal(err)
	}
	tx, err = app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
	_ = tx.Rollback()
	var dbErr sqlite3.Error
	if !errors.Is(err, errAppMCPGrantDenied) || !errors.As(err, &dbErr) || err.Error() != errAppMCPGrantDenied.Error() {
		t.Fatalf("SQL failure was not opaquely denied with its cause preserved: %v", err)
	}
}

func TestAppMCPWriteAuthorityRejectsMalformedMembershipConfiguration(t *testing.T) {
	for _, tc := range []string{"invalid role identifier", "missing active column"} {
		t.Run(tc, func(t *testing.T) {
			app, uid, now := appMCPGrantFixture(t)
			if _, err := app.DB.Exec("ALTER TABLE main.members ADD COLUMN member_role TEXT"); err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec("UPDATE main.members SET member_role='editor' WHERE org_id='17'"); err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec("UPDATE main._benmore_users SET role='unmapped' WHERE id=?", uid); err != nil {
				t.Fatal(err)
			}
			app.Roles = &RolesConfig{Roles: map[string]RoleDef{"unmapped": {}, "editor": {Scopes: "notes:read"}}}
			app.Group.RoleField = "member_role"
			pair := fixtureGrant(t, app, uid, now)
			state, err := setAppMCPApprovedWrites(app.Dir, true)
			if err != nil {
				t.Fatal(err)
			}
			pin := appMCPWritePinForTest(t, app, uid, pair, state)
			tx, err := app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now); err != nil {
				_ = tx.Rollback()
				t.Fatalf("authority was not positive before malformed config: %v", err)
			}
			_ = tx.Rollback()
			var before int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&before); err != nil {
				t.Fatal(err)
			}
			if tc == "invalid role identifier" {
				app.Group.RoleField = "member_role;SELECT"
			} else {
				app.Group.ActiveField = "active"
			}
			pin.Generation = snapshotAppMCPGeneration(app)
			tx, err = app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
			_ = tx.Rollback()
			if !errors.Is(err, errAppMCPGrantDenied) || err.Error() != errAppMCPGrantDenied.Error() {
				t.Fatalf("malformed membership configuration did not preserve opaque denial: %v", err)
			}
			var after int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&after); err != nil || after != before {
				t.Fatalf("denied malformed config changed business rows: before=%d after=%d err=%v", before, after, err)
			}
		})
	}
}

func TestAppMCPWriteAuthoritySerializesAgainstIndependentRevoker(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	state, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	pin := appMCPWritePinForTest(t, app, uid, pair, state)
	held, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	if _, err := appMCPWriteAuthorityForTx(context.Background(), held, pin, now); err != nil {
		t.Fatal("authority was not positive inside held immediate transaction:", err)
	}
	revoker, err := sql.Open("sqlite3", filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	defer revoker.Close()
	revoker.SetMaxOpenConns(1)
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := revoker.Exec("UPDATE main._benmore_mcp_grants SET revoked=1 WHERE id=?", pair.GrantID)
		done <- err
	}()
	<-started
	deadline := time.Now().Add(time.Second)
	for revoker.Stats().InUse == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if revoker.Stats().InUse == 0 {
		t.Fatal("revoker never acquired its independent SQLite connection")
	}
	select {
	case err := <-done:
		t.Fatalf("independent revoker did not wait for held writer transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := held.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("revoker failed after lock release:", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoker did not commit after held transaction released")
	}
	next, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Rollback()
	_, err = appMCPWriteAuthorityForTx(context.Background(), next, pin, now)
	_ = next.Rollback()
	if !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("next transaction ignored committed revocation: %v", err)
	}
}

func TestAppMCPReadAccessSurvivesWriteAuthorityUpgradeAndToggles(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	if _, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err != nil || actor.UserID != uid {
		t.Fatalf("v1 read access denied: actor=%+v err=%v", actor, err)
	}
	if _, err := setAppMCPApprovedWrites(app.Dir, true); err != nil {
		t.Fatal(err)
	}
	if _, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err != nil || actor.UserID != uid {
		t.Fatalf("read access denied after v2 write enable: actor=%+v err=%v", actor, err)
	}
	if _, err := setAppMCPApprovedWrites(app.Dir, false); err != nil {
		t.Fatal(err)
	}
	if _, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err != nil || actor.UserID != uid {
		t.Fatalf("read access denied after write disable: actor=%+v err=%v", actor, err)
	}
}

func TestAppMCPWriteAuthorityRejectsUnexposedOrRotatedState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *App)
	}{
		{"v1 metadata", func(t *testing.T, app *App) {}},
		{"missing metadata", func(t *testing.T, app *App) {
			root := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
			key := hashBytesSHA256([]byte(realPathForContainment(app.Dir)))
			if err := os.Remove(filepath.Join(root, key+".json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"restore invalidation", func(t *testing.T, app *App) {
			if err := invalidateAppMCPForRestore(app.Dir); err != nil {
				t.Fatal(err)
			}
		}},
		{"general rotate", func(t *testing.T, app *App) {
			before, err := currentAppMCPEpoch(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			after, err := updateAppMCPEpoch(app.Dir, true, true, false)
			if err != nil {
				t.Fatal(err)
			}
			if after.Epoch == before.Epoch || after.ApprovedWriteEpoch == before.ApprovedWriteEpoch || after.ApprovedWrites == nil || *after.ApprovedWrites {
				t.Fatalf("general rotation did not revoke both epochs: before=%+v after=%+v", before, after)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, uid, now := appMCPGrantFixture(t)
			pair := fixtureGrant(t, app, uid, now)
			state, err := currentAppMCPEpoch(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name != "v1 metadata" {
				state, err = setAppMCPApprovedWrites(app.Dir, true)
				if err != nil {
					t.Fatal(err)
				}
			}
			pin := appMCPWritePinForTest(t, app, uid, pair, state)
			if tc.name == "v1 metadata" {
				pin.WriteEpoch = strings.Repeat("a", 64)
				if _, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, now); err != nil || actor.UserID != uid {
					t.Fatalf("v1 read authority was not positive: %+v %v", actor, err)
				}
			} else {
				tx, err := app.DB.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now); err != nil {
					_ = tx.Rollback()
					t.Fatalf("authority not positive before metadata change: %v", err)
				}
				_ = tx.Rollback()
			}
			var before int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&before); err != nil {
				t.Fatal(err)
			}
			tc.change(t, app)
			tx, err := app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
			_ = tx.Rollback()
			if !errors.Is(err, errAppMCPGrantDenied) {
				t.Fatalf("helper accepted %s metadata: %v", tc.name, err)
			}
			var after int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&after); err != nil || after != before {
				t.Fatalf("denied metadata changed business rows: before=%d after=%d err=%v", before, after, err)
			}
		})
	}
}

func TestAppMCPWriteAuthorityRejectsTransactionFromWrongApplication(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	state, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	pin := appMCPWritePinForTest(t, app, uid, pair, state)
	positive, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer positive.Rollback()
	if _, err := appMCPWriteAuthorityForTx(context.Background(), positive, pin, now); err != nil {
		_ = positive.Rollback()
		t.Fatal("authority was not positive before wrong-app check:", err)
	}
	_ = positive.Rollback()
	other, cleanup := newTestApp(t)
	defer cleanup()
	if _, err := other.DB.Exec("CREATE TABLE notes (id INTEGER PRIMARY KEY); INSERT INTO notes VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	tx, err := other.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
	_ = tx.Rollback()
	if !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("cross-app transaction accepted: %v", err)
	}
	var count int
	if err := other.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&count); err != nil || count != 1 {
		t.Fatalf("wrong-app transaction changed data: count=%d err=%v", count, err)
	}
}

func TestAppMCPWriteAuthorityRechecksIndependentCommittedRevocation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		args  func(int64, string) []any
	}{
		{"grant revoked", "UPDATE main._benmore_mcp_grants SET revoked=1 WHERE id=?", func(_ int64, id string) []any { return []any{id} }},
		{"grant expired", "UPDATE main._benmore_mcp_grants SET expires_at=0 WHERE id=?", func(_ int64, id string) []any { return []any{id} }},
		{"grant scopes changed", "UPDATE main._benmore_mcp_grants SET scopes='other:read' WHERE id=?", func(_ int64, id string) []any { return []any{id} }},
		{"credential expired", "UPDATE main._benmore_mcp_credentials SET expires_at=0 WHERE grant_id=? AND kind='access'", func(_ int64, id string) []any { return []any{id} }},
		{"credential used", "UPDATE main._benmore_mcp_credentials SET used=1 WHERE grant_id=? AND kind='access'", func(_ int64, id string) []any { return []any{id} }},
		{"credential deleted", "DELETE FROM main._benmore_mcp_credentials WHERE grant_id=? AND kind='access'", func(_ int64, id string) []any { return []any{id} }},
		{"tenant changed", "UPDATE main._benmore_mcp_grants SET tenant='29' WHERE id=?", func(_ int64, id string) []any { return []any{id} }},
		{"client changed", "UPDATE main._benmore_mcp_grants SET client='other' WHERE id=?", func(_ int64, id string) []any { return []any{id} }},
		{"membership", "DELETE FROM main.members WHERE org_id='17' AND email='delegate@example.com'", func(int64, string) []any { return nil }},
		{"membership role removed", "UPDATE main.members SET member_role='unmapped' WHERE org_id='17'", func(int64, string) []any { return nil }},
		{"role", "UPDATE main._benmore_users SET role='unmapped' WHERE id=?", func(uid int64, _ string) []any { return []any{uid} }},
		{"role grant removed", "DELETE FROM main._benmore_user_roles WHERE user_id=? AND role='editor'", func(uid int64, _ string) []any { return []any{uid} }},
		{"role expired", "UPDATE main._benmore_user_roles SET expires_at='2000-01-01' WHERE user_id=? AND role='editor'", func(uid int64, _ string) []any { return []any{uid} }},
		{"tenant scoped role moved", "UPDATE main._benmore_user_roles SET group_id='29' WHERE user_id=? AND role='editor'", func(uid int64, _ string) []any { return []any{uid} }},
		{"account deactivated", "UPDATE main._benmore_users SET deactivated_at='2026-10-02' WHERE id=?", func(uid int64, _ string) []any { return []any{uid} }},
		{"password change required", "UPDATE main._benmore_users SET password_change_required=1 WHERE id=?", func(uid int64, _ string) []any { return []any{uid} }},
		{"unverified email holder", "UPDATE main._benmore_users SET verified=0,email_grandfathered=0 WHERE id=?", func(uid int64, _ string) []any { return []any{uid} }},
		{"account incarnation", "UPDATE main._benmore_users SET created_at='changed-incarnation' WHERE id=?", func(uid int64, _ string) []any { return []any{uid} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, uid, now := appMCPGrantFixture(t)
			pair := fixtureGrant(t, app, uid, now)
			if tc.name == "membership" || tc.name == "membership role removed" {
				if _, err := app.DB.Exec("ALTER TABLE main.members ADD COLUMN member_role TEXT"); err != nil {
					t.Fatal(err)
				}
				if _, err := app.DB.Exec("UPDATE main.members SET member_role='editor' WHERE org_id='17'"); err != nil {
					t.Fatal(err)
				}
				if _, err := app.DB.Exec("UPDATE main._benmore_users SET role='unmapped' WHERE id=?", uid); err != nil {
					t.Fatal(err)
				}
				app.Roles = &RolesConfig{Roles: map[string]RoleDef{"unmapped": {}, "editor": {Scopes: "notes:read"}}}
				app.Group.RoleField = "member_role"
			}
			if tc.name == "role expired" || tc.name == "role grant removed" || tc.name == "tenant scoped role moved" {
				if _, err := app.DB.Exec("UPDATE main._benmore_users SET role='unmapped' WHERE id=?", uid); err != nil {
					t.Fatal(err)
				}
				if _, err := app.DB.Exec("INSERT INTO main._benmore_user_roles(user_id,role,group_id,expires_at) VALUES (?, 'editor','17','2099-01-01')", uid); err != nil {
					t.Fatal(err)
				}
				app.Roles = &RolesConfig{Roles: map[string]RoleDef{"unmapped": {}, "editor": {Scopes: "notes:read"}}}
			}
			state, err := setAppMCPApprovedWrites(app.Dir, true)
			if err != nil {
				t.Fatal(err)
			}
			pin := appMCPWritePinForTest(t, app, uid, pair, state)
			tx, err := app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now); err != nil {
				_ = tx.Rollback()
				t.Fatalf("authority was not positive before mutation: %v", err)
			}
			_ = tx.Rollback()
			var before int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec(tc.query, tc.args(uid, pair.GrantID)...); err != nil {
				t.Fatal(err)
			}
			tx, err = app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
			_ = tx.Rollback()
			if !errors.Is(err, errAppMCPGrantDenied) {
				t.Fatalf("committed authority change accepted: %v", err)
			}
			var after int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&after); err != nil || after != before {
				t.Fatalf("denied authority attempt changed business rows: before=%d after=%d err=%v", before, after, err)
			}
		})
	}
}

func TestAppMCPWriteAuthorityPreservesWriteImpliesReadScope(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	state, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	pin := appMCPWritePinForTest(t, app, uid, pair, state)
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("authority was not positive before scope update: %v", err)
	}
	_ = tx.Rollback()
	if _, err := app.DB.Exec("UPDATE main._benmore_mcp_grants SET scopes='notes:write' WHERE id=?", pair.GrantID); err != nil {
		t.Fatal(err)
	}
	tx, err = app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	result, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
	if err != nil || result == nil || !scopesWithin(result.Actor.Scopes, "notes:read") {
		t.Fatalf("write scope no longer authorized its implied read: %+v %v", result, err)
	}
}

func TestAppMCPWriteAuthorityRejectsStalePinsAndWriteEpoch(t *testing.T) {
	for _, tc := range []string{"grant id", "app", "epoch", "resource", "client", "tenant", "user", "user incarnation", "raw credential", "malformed credential digest", "write disabled", "write epoch", "generation", "manifest description", "manifest repinned declaration", "manifest contract pin only", "manifest execution pin only", "manifest removed", "manifest malformed", "manifest alias", "manifest oversize", "manifest directory", "manifest symlink", "execution source changed", "permission"} {
		t.Run(tc, func(t *testing.T) {
			app, uid, now := appMCPGrantFixture(t)
			pair := fixtureGrant(t, app, uid, now)
			state, err := setAppMCPApprovedWrites(app.Dir, true)
			if err != nil {
				t.Fatal(err)
			}
			pin := appMCPWritePinForTest(t, app, uid, pair, state)
			beforeTx, err := app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer beforeTx.Rollback()
			if _, err := appMCPWriteAuthorityForTx(context.Background(), beforeTx, pin, now); err != nil {
				_ = beforeTx.Rollback()
				t.Fatalf("authority was not positive before stale-pin change: %v", err)
			}
			_ = beforeTx.Rollback()
			var before int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&before); err != nil {
				t.Fatal(err)
			}
			switch tc {
			case "grant id":
				pin.GrantID = "other"
			case "app":
				pin.AppID = "other"
			case "epoch":
				pin.Epoch = strings.Repeat("0", 64)
			case "resource":
				pin.Resource = "https://other.example/api/_mcp"
			case "client":
				pin.Client = "other"
			case "tenant":
				pin.Tenant = "29"
			case "user":
				pin.UserID++
			case "user incarnation":
				pin.UserCreated = "old-incarnation"
			case "write disabled":
				if _, err := setAppMCPApprovedWrites(app.Dir, false); err != nil {
					t.Fatal(err)
				}
			case "write epoch":
				if _, err := setAppMCPApprovedWrites(app.Dir, false); err != nil {
					t.Fatal(err)
				}
				if _, err := setAppMCPApprovedWrites(app.Dir, true); err != nil {
					t.Fatal(err)
				}
			case "generation":
				app.MCP = nil
			case "manifest description", "manifest repinned declaration":
				data, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				changed := strings.Replace(string(data), "Read reviewed note fields", "Changed note fields", 1)
				writeTestFile(t, app.Dir, "mcp.yaml", changed)
				if tc == "manifest repinned declaration" {
					reviewAppMCPFixture(t, app.Dir)
				}
			case "manifest contract pin only", "manifest execution pin only":
				data, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				oldPin := pin.Generation.manifest.ContractDigest
				if tc == "manifest execution pin only" {
					oldPin = pin.Generation.manifest.ExecutionDigest
				}
				writeTestFile(t, app.Dir, "mcp.yaml", strings.Replace(string(data), oldPin, strings.Repeat("c", 64), 1))
			case "manifest removed":
				if err := os.Remove(filepath.Join(app.Dir, "mcp.yaml")); err != nil {
					t.Fatal(err)
				}
			case "manifest malformed":
				writeTestFile(t, app.Dir, "mcp.yaml", "version: [\n")
			case "manifest alias":
				data, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, app.Dir, "mcp.yaml", strings.Replace(string(data), "resources: []\nconnections: []", "resources: &empty []\nconnections: *empty", 1))
			case "manifest oversize":
				data, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, app.Dir, "mcp.yaml", string(data)+"\n#"+strings.Repeat("x", yamlMaxBytes+1))
			case "manifest directory":
				path := filepath.Join(app.Dir, "mcp.yaml")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "manifest symlink":
				path := filepath.Join(app.Dir, "mcp.yaml")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(app.Dir, ".benmore"), 0700); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, app.Dir, ".benmore/mcp-target.yaml", string(data))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(".benmore", "mcp-target.yaml"), path); err != nil {
					t.Fatal(err)
				}
			case "execution source changed":
				data, err := os.ReadFile(filepath.Join(app.Dir, "schema.sql"))
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, app.Dir, "schema.sql", string(data)+"-- source drift\n")
			case "permission":
				pin.Permissions = []string{"notes:write"}
			case "raw credential":
				pin.CredentialHash = pair.AccessToken
			case "malformed credential digest":
				pin.CredentialHash = "not-a-sha256-digest"
			}
			tx, err := app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = appMCPWriteAuthorityForTx(context.Background(), tx, pin, now)
			_ = tx.Rollback()
			if !errors.Is(err, errAppMCPGrantDenied) {
				t.Fatalf("stale %s pin accepted: %v", tc, err)
			}
			if tc == "manifest symlink" {
				var authorityErr *appMCPWriteAuthorityError
				if !errors.As(err, &authorityErr) || authorityErr.cause == nil || authorityErr.cause.Error() != "mcp.yaml must be a regular file" {
					t.Fatalf("symlink denial did not come from the regular-file check: %v", err)
				}
			}
			var after int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.notes").Scan(&after); err != nil || after != before {
				t.Fatalf("denied stale pin changed business rows: before=%d after=%d err=%v", before, after, err)
			}
		})
	}
}

func TestAppMCPWriteAuthorityAllowsEquivalentManifestFormatting(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	state, err := setAppMCPApprovedWrites(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	pin := appMCPWritePinForTest(t, app, uid, pair, state)
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("authority was not positive before formatting change: %v", err)
	}
	_ = tx.Rollback()
	data, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Content) != 1 || len(document.Content[0].Content) < 4 {
		t.Fatalf("cannot parse fixture manifest node: %v", err)
	}
	mapping := document.Content[0]
	pairs := make([][]*yaml.Node, 0, len(mapping.Content)/2)
	for i := 0; i < len(mapping.Content); i += 2 {
		pairs = append(pairs, mapping.Content[i:i+2])
	}
	pairs[0], pairs[1] = pairs[1], pairs[0]
	mapping.Content = nil
	for _, pair := range pairs {
		mapping.Content = append(mapping.Content, pair...)
	}
	document.HeadComment = "format-only comment"
	formatted, err := yaml.Marshal(&document)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", string(formatted))
	tx, err = app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := appMCPWriteAuthorityForTx(context.Background(), tx, pin, now); err != nil {
		t.Fatalf("semantically equivalent manifest formatting denied: %v", err)
	}
}

func TestAppMCPWriteAuthorityEpochV2RejectsMalformedMetadata(t *testing.T) {
	root := epochFixture(t)
	app, cleanup := newTestApp(t)
	defer cleanup()
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := setAppMCPApprovedWrites(app.Dir, false); err != nil {
		t.Fatal(err)
	}
	key := hashBytesSHA256([]byte(realPathForContainment(app.Dir)))
	path := filepath.Join(root, key+".json")
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		strings.Replace(string(valid), `"approved_writes":false`, `"approved_writes":null`, 1),
		strings.Replace(string(valid), `"approved_write_epoch":"`, `"approved_write_epoch":"A`, 1),
		strings.Replace(string(valid), `"version":2`, `"version":1`, 1),
	} {
		if err := os.WriteFile(path, []byte(malformed), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := currentAppMCPEpoch(app.Dir); err == nil {
			t.Fatalf("malformed state accepted: %s", malformed)
		}
		if err := os.WriteFile(path, valid, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func readUserCreatedForTest(t *testing.T, app *App, uid int64) string {
	t.Helper()
	var created string
	if err := app.DB.QueryRow("SELECT COALESCE(created_at,'') FROM main._benmore_users WHERE id=?", uid).Scan(&created); err != nil {
		t.Fatal(err)
	}
	return created
}

func appMCPWritePinForTest(t *testing.T, app *App, uid int64, pair *appMCPTokenPair, state *appMCPEpochState) appMCPWriteAuthorityPin {
	t.Helper()
	return appMCPWriteAuthorityPin{
		Origin: app, Generation: snapshotAppMCPGeneration(app), CredentialHash: mustAppMCPCredentialHash(t, pair.AccessToken, "access"),
		GrantID: pair.GrantID, AppID: state.App, Epoch: state.Epoch, WriteEpoch: state.ApprovedWriteEpoch,
		Resource: grantFixtureResource, Client: "client-fixture", Tenant: "17", UserID: uid,
		UserCreated: readUserCreatedForTest(t, app, uid), Permissions: []string{"notes:read"},
	}
}
