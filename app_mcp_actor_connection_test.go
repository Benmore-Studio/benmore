//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"errors"
	"github.com/mattn/go-sqlite3"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestAppMCPGrantActorMatchesScheduledActor(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := loadScheduledActor(app, uid, &grant.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	got, err := appMCPGrantActorFor(context.Background(), app, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != want.UserID || got.GroupID != want.GroupID || got.IsAdmin() != want.IsAdmin() || got.IsAdminBypass() != want.IsAdminBypass() {
		t.Fatalf("grant actor diverged from scheduled actor: got=%+v want=%+v", got, want)
	}
	want.ID, want.CredentialScopes, want.connectorGrant = got.ID, got.CredentialScopes, true
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical actor differs: got=%+v want=%+v", got, want)
	}
	if got.CredentialScopes != pair.Scopes {
		t.Fatalf("grant actor lost connector scope: got %q want %q", got.CredentialScopes, pair.Scopes)
	}
}

func TestAppMCPGrantActorRejectsDirtyConnectionAndRestoresPool(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "DELETE FROM main.members WHERE org_id='17' AND email='delegate@example.com'")
	auditExec(t, app.DB, "BEGIN")
	auditExec(t, app.DB, "UPDATE _benmore_users SET role='admin' WHERE id=?", uid)
	auditExec(t, app.DB, "INSERT INTO main.members(org_id,email) VALUES ('17','delegate@example.com')")
	if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
		t.Fatalf("uncommitted account or membership state authorized: %+v %v", actor, err)
	}
	var members int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.members WHERE org_id='17'").Scan(&members); err != nil || members != 0 {
		t.Fatalf("uncommitted membership survived discard: %d %v", members, err)
	}
	auditExec(t, app.DB, "INSERT INTO main.members(org_id,email) VALUES ('17','delegate@example.com')")
	actor, err := appMCPGrantActorFor(context.Background(), app, grant, now)
	if err != nil || actor == nil || actor.UserID != uid || actor.GroupID != "17" || actor.IsAdmin() {
		t.Fatalf("discarded transaction did not recover committed actor: %+v %v", actor, err)
	}
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var queryOnly bool
	err = conn.QueryRowContext(context.Background(), "PRAGMA query_only").Scan(&queryOnly)
	closeErr := conn.Close()
	if err != nil || closeErr != nil || queryOnly {
		t.Fatalf("pooled connection state after actor lookup: query_only=%t query_err=%v close_err=%v", queryOnly, err, closeErr)
	}
	if _, err := app.DB.Exec("UPDATE main.members SET org_id=org_id WHERE email='delegate@example.com'"); err != nil {
		t.Fatalf("ordinary write failed after actor lookup: %v", err)
	}
}

func TestAppMCPGrantActorRejectsPasswordChangeAndViewerMasksFlag(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "UPDATE _benmore_users SET password_change_required=1 WHERE id=?", uid)
	if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
		t.Fatalf("password-change-required account authorized: %+v %v", actor, err)
	}
	rows, _, truncated, err := queryReadOnlyRowsCols(context.Background(), app.DB, "SELECT password_change_required FROM _benmore_users WHERE email='delegate@example.com'", 10)
	if err != nil || truncated || len(rows) != 1 || rows[0]["password_change_required"] != nil {
		t.Fatalf("viewer exposed password-change flag: rows=%v err=%v", rows, err)
	}

	viewApp, viewUID, viewNow := appMCPGrantFixture(t)
	viewPair := fixtureGrant(t, viewApp, viewUID, viewNow)
	viewGrant, err := readAppMCPGrant(viewApp.DB, viewPair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, viewApp.DB, "UPDATE main._benmore_users SET password_change_required=1 WHERE id=?", viewUID)
	auditExec(t, viewApp.DB, "ALTER TABLE main._benmore_users RENAME TO _benmore_users_backing")
	auditExec(t, viewApp.DB, "CREATE VIEW main._benmore_users AS SELECT id,email,role,deactivated_at,verified,email_grandfathered,password_change_required,created_at FROM main._benmore_users_backing")
	if actor, err := appMCPGrantActorFor(context.Background(), viewApp, viewGrant, viewNow); err == nil || actor != nil {
		t.Fatalf("password-change flag through main users view authorized: %+v %v", actor, err)
	}
}

func TestAppMCPGrantActorFailsClosedForUnavailableRoleAndTempAuthority(t *testing.T) {
	t.Run("missing main role table", func(t *testing.T) {
		app, uid, now := appMCPGrantFixture(t)
		pair := fixtureGrant(t, app, uid, now)
		grant, err := readAppMCPGrant(app.DB, pair.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		auditExec(t, app.DB, "ALTER TABLE main._benmore_user_roles RENAME TO _benmore_user_roles_unavailable")
		if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
			t.Fatalf("missing main role table authorized through fallback: %+v %v", actor, err)
		}
	})

	t.Run("temporary authority shadow", func(t *testing.T) {
		app, uid, now := appMCPGrantFixture(t)
		pair := fixtureGrant(t, app, uid, now)
		app.DB.SetMaxOpenConns(1)
		app.DB.SetMaxIdleConns(1)
		auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_users AS SELECT * FROM main._benmore_users")
		auditExec(t, app.DB, "UPDATE temp._benmore_users SET role='admin' WHERE id=?", uid)
		auditExec(t, app.DB, "CREATE TEMP TABLE _benmore_user_roles AS SELECT * FROM main._benmore_user_roles")
		auditExec(t, app.DB, "UPDATE temp._benmore_user_roles SET role='admin' WHERE user_id=?", uid)
		auditExec(t, app.DB, "CREATE TEMP TABLE members AS SELECT * FROM main.members")
		auditExec(t, app.DB, "INSERT INTO temp.members(org_id,email) VALUES ('99','delegate@example.com')")
		grant, err := readAppMCPGrant(app.DB, pair.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		actor, err := appMCPGrantActorFor(context.Background(), app, grant, now)
		if err != nil {
			return // Denial is safe when the shadow makes identity ambiguous.
		}
		if actor == nil || actor.UserID != uid || actor.GroupID != "17" || actor.IsAdmin() {
			t.Fatalf("temporary authority shadow changed actor privilege: %+v", actor)
		}
	})
}

func TestAppMCPGrantActorUsesPhysicalMembershipColumnsAndTenantRoles(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "ALTER TABLE members ADD COLUMN live INTEGER DEFAULT 1")
	auditExec(t, app.DB, "ALTER TABLE members ADD COLUMN deleted_at TEXT")
	auditExec(t, app.DB, "ALTER TABLE members ADD COLUMN member_role TEXT DEFAULT 'member_reader'")
	app.Group.ActiveField, app.Group.RoleField = "live", "member_role"
	app.Roles.Roles["member_reader"] = RoleDef{Scopes: "notes:read"}
	app.Roles.Roles["tenant_reader"] = RoleDef{Scopes: "notes:read"}
	auditExec(t, app.DB, "INSERT INTO _benmore_user_roles(user_id,role,group_id) VALUES (?,'tenant_reader','17'),(?,'outside_tenant','29')", uid, uid)
	actor, err := appMCPGrantActorFor(context.Background(), app, grant, now)
	if err != nil || actor == nil || !HasAnyRole(actor, []string{"member_reader"}) || !HasAnyRole(actor, []string{"tenant_reader"}) || HasAnyRole(actor, []string{"outside_tenant"}) {
		t.Fatalf("physical membership or pinned roles: %+v %v", actor, err)
	}
	for _, statement := range []string{
		"UPDATE members SET live=0 WHERE org_id='17'",
		"UPDATE members SET live=1,deleted_at='deleted' WHERE org_id='17'",
	} {
		auditExec(t, app.DB, statement)
		if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
			t.Fatalf("inactive/deleted physical membership authorized: %+v %v", actor, err)
		}
	}
	auditExec(t, app.DB, "UPDATE members SET live=1,deleted_at=NULL WHERE org_id='17'")
	auditExec(t, app.DB, "ALTER TABLE members DROP COLUMN live")
	if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
		t.Fatalf("missing configured physical active column authorized: %+v %v", actor, err)
	}
}

func TestAppMCPGrantActorSnapshotAndStartedCancellationRestorePool(t *testing.T) {
	for _, cancelDuringRead := range []bool{false, true} {
		t.Run(map[bool]string{false: "snapshot", true: "cancel"}[cancelDuringRead], func(t *testing.T) {
			app, uid, now := appMCPGrantFixture(t)
			pair := fixtureGrant(t, app, uid, now)
			grant, err := readAppMCPGrant(app.DB, pair.GrantID)
			if err != nil {
				t.Fatal(err)
			}
			app.DB.SetMaxOpenConns(1)
			app.DB.SetMaxIdleConns(1)
			auditExec(t, app.DB, "CREATE TABLE actor_effects(id INTEGER)")
			auditExec(t, app.DB, "ALTER TABLE _benmore_users RENAME TO _benmore_users_actor_storage")
			auditExec(t, app.DB, `CREATE VIEW _benmore_users AS SELECT id,CASE WHEN actor_started()=1 THEN email ELSE email END AS email,role,deactivated_at,verified,email_grandfathered,password_change_required,created_at FROM _benmore_users_actor_storage`)
			started, unblock := make(chan struct{}, 1), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(unblock) }) }
			defer release()
			writes := 0
			conn, err := app.DB.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			err = conn.Raw(func(raw any) error {
				native := raw.(*sqlite3.SQLiteConn)
				return native.RegisterFunc("actor_started", func() int64 {
					if _, err := native.Exec("INSERT INTO actor_effects VALUES(1)", nil); err == nil {
						writes++
					}
					select {
					case started <- struct{}{}:
					default:
					}
					<-unblock
					return 1
				}, false)
			})
			_ = conn.Close()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				actor *Session
				err   error
			}
			done := make(chan result, 1)
			go func() { actor, err := appMCPGrantActorFor(ctx, app, grant, now); done <- result{actor, err} }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("actor SQL never started")
			}
			if cancelDuringRead {
				cancel()
			} else {
				writer, err := sql.Open("sqlite3", app.Dir+"/data.db?_journal_mode=WAL&_busy_timeout=1000")
				if err != nil {
					t.Fatal(err)
				}
				_, err = writer.Exec("DELETE FROM members WHERE org_id='17'")
				_ = writer.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			release()
			select {
			case got := <-done:
				if cancelDuringRead {
					if got.err == nil || got.actor != nil {
						t.Fatalf("started canceled read authorized: %+v %v", got.actor, got.err)
					}
				} else if got.err != nil || got.actor == nil || got.actor.GroupID != "17" {
					t.Fatalf("actor did not retain one read snapshot: %+v %v", got.actor, got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("actor read did not finish after release")
			}
			if writes != 0 {
				t.Fatalf("actor callback wrote %d times", writes)
			}
			var effects int
			if err := app.DB.QueryRow("SELECT count(*) FROM actor_effects").Scan(&effects); err != nil || effects != 0 {
				t.Fatalf("authority read changed data: %d %v", effects, err)
			}
			auditExec(t, app.DB, "INSERT INTO actor_effects VALUES(2)")
			if !cancelDuringRead {
				if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
					t.Fatalf("next actor did not observe committed membership revocation: %+v %v", actor, err)
				}
			}
		})
	}
}

func TestAppMCPGrantActorQualifiedMembershipCannotOmitDeletedPredicate(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "ALTER TABLE members ADD COLUMN deleted_at TEXT")
	app.Group.Table = "MAIN.members"
	if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err != nil || actor == nil {
		t.Fatalf("qualified live membership refused: %+v %v", actor, err)
	}
	auditExec(t, app.DB, "UPDATE main.members SET deleted_at='deleted' WHERE org_id='17'")
	if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
		t.Fatalf("metadata scan failure omitted deleted predicate: %+v %v", actor, err)
	}
	if actor, err := loadScheduledActor(app, uid, &grant.Tenant); err == nil || actor != nil {
		t.Fatalf("ordinary qualified membership omitted deleted predicate: %+v %v", actor, err)
	}
}

func TestOrdinaryMembershipMetadataFollowsTemporaryTable(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "CREATE TEMP TABLE members AS SELECT *,NULL AS deleted_at FROM main.members")
	auditExec(t, app.DB, "UPDATE temp.members SET deleted_at='deleted' WHERE org_id='17'")
	if !dbColumnChecker(app.DB, "members")("deleted_at") {
		t.Error("ordinary metadata did not follow TEMP table")
	}
	mainCol, mainErr := dbColumnCheckerWith(app.DB, "members", "main")
	if mainCol("deleted_at") || mainErr() != nil {
		t.Fatalf("main metadata unexpectedly used TEMP: %v", mainErr())
	}
	tenant := "17"
	if actor, err := loadScheduledActor(app, uid, &tenant); err == nil || actor != nil {
		t.Fatalf("ordinary soft-deleted TEMP membership authorized: %+v %v", actor, err)
	}
}

func TestAppMCPGrantActorReportsKeyScanFailure(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Raw(func(raw any) error {
		return raw.(*sqlite3.SQLiteConn).RegisterFunc("actor_key_failure", func() (string, error) { return "", errors.New("key scan failed") }, false)
	})
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, `CREATE VIEW main.pragma_database_list AS SELECT actor_key_failure() AS file,'main' AS name`)
	if _, err := cryptoKeyForQuerierChecked(app.DB); err == nil {
		t.Error("actual key Scan error was swallowed")
	}
	if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
		t.Fatalf("key Scan failure authorized actor: %+v %v", actor, err)
	}
	if actor, err := loadScheduledActor(app, uid, &grant.Tenant); err != nil || actor == nil {
		t.Fatalf("ordinary key fallback changed: %+v %v", actor, err)
	}
}

func TestOrdinaryMembershipRoleRetainsOptionalMetadataFallback(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, now)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "ALTER TABLE members ADD COLUMN member_role TEXT DEFAULT 'member_reader'")
	app.Group.RoleField = "member_role"
	auditExec(t, app.DB, "CREATE VIEW main.pragma_table_info AS SELECT 1 AS name")
	hasCol, metadataErr := dbColumnCheckerWith(app.DB, "members", "")
	_ = hasCol("deleted_at")
	if metadataErr() == nil {
		t.Fatal("fixture did not fail actual metadata query")
	}
	if role := ResolveMembershipRole(app.DB, app.Group, "delegate@example.com", "17"); role != "member_reader" {
		t.Fatalf("ordinary optional metadata fallback changed: %q", role)
	}
	if actor, err := appMCPGrantActorFor(context.Background(), app, grant, now); err == nil || actor != nil {
		t.Fatalf("connector inherited optional metadata fallback: %+v %v", actor, err)
	}
}
