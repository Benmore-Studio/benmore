//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func ensureCommandAuditFixture(t *testing.T, app *App) {
	t.Helper()
	EnsureAuditLogTable(app.DB)

	rows, err := app.DB.Query(`PRAGMA main.table_info("_benmore_audit_log")`)
	if err != nil {
		t.Fatalf("read initialized main audit table columns: %v", err)
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			t.Fatalf("scan initialized main audit table column: %v", err)
		}
		columns[name] = true
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil {
		t.Fatalf("iterate initialized main audit table columns: %v", rowsErr)
	}
	if closeErr != nil {
		t.Fatalf("close initialized main audit table columns: %v", closeErr)
	}
	for _, name := range []string{
		"id", "action", "table_name", "row_id", "user_id", "user_email",
		"old_values", "new_values", "created_at", "impersonator_user_id", "impersonator_email",
	} {
		if !columns[name] {
			t.Fatalf("initialized main audit table is missing column %q", name)
		}
	}
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_audit_log`).Scan(&count); err != nil {
		t.Fatalf("read initialized main audit table rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("audit fixture must start empty: got %d rows", count)
	}
}

func TestAppMCPCommandAggregateReadAndDatabaseBoundaries(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	generation := snapshotAppMCPGeneration(app)
	observedColumnlessRead := false
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		if err := cap.enterReadPhase("prepare", []string{"tasks"}); err != nil {
			return false, err
		}
		defer cap.leaveReadPhase()
		guard := cap.guard
		if err := cap.conn.Raw(func(raw any) error {
			conn, ok := raw.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("command connection is not SQLite")
			}
			conn.RegisterAuthorizer(func(action int, arg1, arg2, database string) int {
				if action == sqlite3.SQLITE_READ && arg1 == "tasks" && arg2 == "" && database == "" {
					observedColumnlessRead = true
				}
				return guard.authorize(action, arg1, arg2, database)
			})
			return nil
		}); err != nil {
			return false, err
		}
		var count int
		if err := cap.tx.QueryRowContext(cap.ctx, `SELECT count(*) FROM tasks`).Scan(&count); err != nil {
			return false, err
		}
		if count != 1 || !observedColumnlessRead {
			return false, errors.New("native count(*) did not use the exact empty-database, empty-column read callback")
		}
		for _, query := range []string{
			`SELECT count(*) FROM projects`,
			`SELECT count(*) FROM main._benmore_users`,
		} {
			var ignored int
			if err := cap.tx.QueryRowContext(cap.ctx, query).Scan(&ignored); err == nil {
				return false, errors.New("native command guard admitted an undeclared, internal, or TEMP read")
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("native command aggregate/read-boundary check: %v", err)
	}

	guard := &appMCPCommandExecution{allowedReads: commandTableSet([]string{"tasks"})}
	if got := guard.authorize(sqlite3.SQLITE_FUNCTION, "", "benmore_today", ""); got != sqlite3.SQLITE_OK {
		t.Fatalf("command authorizer denied benmore_today: %d", got)
	}
	if got := guard.authorize(sqlite3.SQLITE_FUNCTION, "", "load_extension", ""); got != sqlite3.SQLITE_DENY {
		t.Fatalf("command authorizer admitted unlisted function: %d", got)
	}
	cases := []struct {
		name, table, column, database string
		want                          int
	}{
		{"columnless count main", "tasks", "", "main", sqlite3.SQLITE_OK},
		{"columnless count reported without database", "tasks", "", "", sqlite3.SQLITE_OK},
		{"empty database with column", "tasks", "id", "", sqlite3.SQLITE_DENY},
		{"undeclared table", "projects", "", "main", sqlite3.SQLITE_DENY},
		{"reserved table", "_benmore_users", "", "main", sqlite3.SQLITE_DENY},
		{"temp database", "tasks", "", "temp", sqlite3.SQLITE_DENY},
		{"attached database", "tasks", "", "attached", sqlite3.SQLITE_DENY},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := guard.authorize(sqlite3.SQLITE_READ, tc.table, tc.column, tc.database); got != tc.want {
				t.Fatalf("authorize SQLITE_READ(%q,%q,%q) = %d, want %d", tc.table, tc.column, tc.database, got, tc.want)
			}
		})
	}
	guard.phase = "apply"
	if got := guard.authorize(sqlite3.SQLITE_READ, appMCPRowRevisionsName, "revision", "main"); got != sqlite3.SQLITE_OK {
		t.Fatalf("apply trigger read from main = %d, want allow", got)
	}
	if got := guard.authorize(sqlite3.SQLITE_READ, appMCPRowRevisionsName, "", ""); got != sqlite3.SQLITE_DENY {
		t.Fatalf("apply trigger columnless read without main identity = %d, want deny", got)
	}
	guard.internal = true
	if got := guard.authorize(sqlite3.SQLITE_READ, "tasks", "", ""); got != sqlite3.SQLITE_DENY {
		t.Fatalf("internal columnless read without a main database identity = %d, want deny", got)
	}
	if got := guard.authorize(sqlite3.SQLITE_READ, "tasks", "id", "main"); got != sqlite3.SQLITE_OK {
		t.Fatalf("internal main read = %d, want allow", got)
	}
}

func TestAppMCPCommandRejectsDirtyTemporaryAndAttachedNamespaces(t *testing.T) {
	for _, namespace := range []string{"temp", "attached"} {
		t.Run(namespace, func(t *testing.T) {
			app, sessionID, _ := newCommandProviderTaskFixture(t)
			app.DB.SetMaxOpenConns(1)
			app.DB.SetMaxIdleConns(1)
			beforeRevisions := commandRevisionSnapshot(t, app)
			var dirtyConnID string
			if namespace == "temp" {
				dirtyConnID = createCommandTempTasks(t, app)
			} else {
				dirtyConnID = createCommandAttachedTasks(t, app)
			}

			callbackReached := false
			generation := snapshotAppMCPGeneration(app)
			err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
				app: app, generation: generation, toolName: "complete_item",
				origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
			}, func(*appMCPCommandCapability) (bool, error) {
				callbackReached = true
				return false, errors.New("command callback should not run on a dirty connection")
			})
			if callbackReached {
				t.Fatal("command callback ran before dirty namespace refusal")
			}
			wantError := "temporary schema objects are not supported"
			if namespace == "attached" {
				wantError = "attached databases are not supported"
			}
			if err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("dirty %s namespace was not rejected by clean-main preflight: %v", namespace, err)
			}
			assertCommandTaskLedgerUnchanged(t, app, beforeRevisions)

			conn, err := app.DB.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			gotID, err := commandSQLiteConnID(conn)
			if err != nil || gotID != dirtyConnID {
				t.Fatalf("namespace setup/cleanup did not use the coordinator's same pooled connection: before=%s after=%s err=%v", dirtyConnID, gotID, err)
			}
			if namespace == "temp" {
				var tempCount int
				if err := conn.QueryRowContext(context.Background(), `SELECT count(*) FROM temp.tasks`).Scan(&tempCount); err != nil || tempCount != 1 {
					t.Fatalf("distinguishable TEMP tasks relation was not present before cleanup: count=%d err=%v", tempCount, err)
				}
				if _, err := conn.ExecContext(context.Background(), `DROP TABLE temp.tasks`); err != nil {
					t.Fatalf("remove TEMP setup relation: %v", err)
				}
			} else {
				var attachedCount int
				if err := conn.QueryRowContext(context.Background(), `SELECT count(*) FROM attached.tasks`).Scan(&attachedCount); err != nil || attachedCount != 1 {
					t.Fatalf("distinguishable attached tasks relation was not present before cleanup: count=%d err=%v", attachedCount, err)
				}
				if err := commandAssertAttachedLimit(t, conn, 0); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.ExecContext(context.Background(), `DETACH DATABASE attached`); err != nil {
					t.Fatalf("detach test database after refusal: %v", err)
				}
			}
			var mainCount int
			if err := conn.QueryRowContext(context.Background(), `SELECT count(*) FROM main.tasks`).Scan(&mainCount); err != nil || mainCount != 1 {
				t.Fatalf("cleaned native connection could not read the original main task: count=%d err=%v", mainCount, err)
			}
		})
	}
}

func TestAppMCPCommandOutcomeFinalizerBarrierAndUnknownCommit(t *testing.T) {
	t.Run("confirmed finalizer sees pending write and cannot mutate", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		generation := snapshotAppMCPGeneration(app)
		request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().Add(-24 * time.Hour)}
		finalizerCalls := 0
		outcome, err := appMCPWithCommandOutcome(context.Background(), request, func(cap *appMCPCommandCapability) (bool, error) {
			prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if err != nil {
				return false, err
			}
			if _, _, err := cap.apply(prepared); err != nil {
				return false, err
			}
			return true, nil
		}, func(cap *appMCPCommandCapability, serverNow time.Time) (appMCPCommandCommitBarrier, error) {
			finalizerCalls++
			if delta := time.Since(serverNow); delta < -time.Second || delta > time.Second {
				return appMCPCommandCommitBarrier{}, fmt.Errorf("finalizer clock was not server supplied: %s", delta)
			}
			var status string
			if err := cap.tx.QueryRowContext(cap.ctx, `SELECT status FROM main.tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
				return appMCPCommandCommitBarrier{}, fmt.Errorf("finalizer did not observe pending task write: status=%q err=%v", status, err)
			}
			var queryOnly bool
			if err := cap.tx.QueryRowContext(cap.ctx, `PRAGMA query_only`).Scan(&queryOnly); err != nil || !queryOnly {
				return appMCPCommandCommitBarrier{}, fmt.Errorf("finalizer transaction was not verified read-only: query_only=%t err=%v", queryOnly, err)
			}
			if _, err := cap.tx.ExecContext(cap.ctx, `UPDATE main.tasks SET title='finalizer-must-not-write' WHERE id=1`); err == nil {
				return appMCPCommandCommitBarrier{}, errors.New("read-only finalizer write was admitted")
			}
			if err := cap.withNativeMetadata(appMCPCommandMetadataRead, func() error { return nil }); err == nil {
				return appMCPCommandCommitBarrier{}, errors.New("finalizer admitted a nested metadata scope")
			}
			if err := cap.enterReadPhase("prepare", []string{"tasks"}); err == nil {
				cap.leaveReadPhase()
				return appMCPCommandCommitBarrier{}, errors.New("finalizer admitted an authored phase")
			}
			return appMCPCommandCommitBarrier{}, nil
		})
		if err != nil || outcome.State != appMCPCommandCommitConfirmed || outcome.RollbackConfirmed || finalizerCalls != 1 {
			t.Fatalf("confirmed outcome=%+v calls=%d err=%v", outcome, finalizerCalls, err)
		}
		var status string
		if err := app.DB.QueryRow(`SELECT status FROM main.tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
			t.Fatalf("confirmed task status=%q err=%v", status, err)
		}
	})

	t.Run("expired barrier rolls back", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		generation := snapshotAppMCPGeneration(app)
		request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
		finalizerCalls := 0
		outcome, err := appMCPWithCommandOutcome(context.Background(), request, func(cap *appMCPCommandCapability) (bool, error) {
			prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if err != nil {
				return false, err
			}
			if _, _, err := cap.apply(prepared); err != nil {
				return false, err
			}
			return true, nil
		}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
			finalizerCalls++
			return appMCPCommandCommitBarrier{ValidUntil: time.Now().UTC()}, nil
		})
		if err == nil || !strings.Contains(err.Error(), "barrier expired") || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed || finalizerCalls != 1 {
			t.Fatalf("expired barrier outcome=%+v finalizerCalls=%d err=%v", outcome, finalizerCalls, err)
		}
		assertCommandTaskUnchanged(t, app)
	})

	t.Run("finalizer error rolls back", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		ensureCommandAuditFixture(t, app)
		generation := snapshotAppMCPGeneration(app)
		request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
		const operationID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		finalizerErr := errors.New("verified finalizer refusal")
		prepareReached, auditReached, applyReached := false, false, false
		finalizerCalls, deniedUpdateReached := 0, false
		outcome, err := appMCPWithCommandOutcome(context.Background(), request, func(cap *appMCPCommandCapability) (bool, error) {
			record := appMCPOperationStoreRecord(app, operationID)
			if err := cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
				stored, err := insertAppMCPPreparedOperation(cap.ctx, cap.tx, app, record)
				prepareReached = err == nil && stored != nil
				return err
			}); err != nil {
				return false, err
			}
			if err := cap.withNativeMetadata(appMCPCommandMetadataAudit, func() error {
				err := insertAuditRowChecked(cap.tx, "command_fixture", "tasks", "1", &cap.actor, "{}", "{}")
				auditReached = err == nil
				return err
			}); err != nil {
				return false, err
			}
			prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if err != nil {
				return false, err
			}
			if _, _, err := cap.apply(prepared); err != nil {
				return false, err
			}
			applyReached = true
			return true, nil
		}, func(cap *appMCPCommandCapability, _ time.Time) (appMCPCommandCommitBarrier, error) {
			finalizerCalls++
			var status string
			if err := cap.tx.QueryRowContext(cap.ctx, `SELECT status FROM main.tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
				return appMCPCommandCommitBarrier{}, fmt.Errorf("finalizer did not see applied write: status=%q err=%v", status, err)
			}
			_, deniedErr := cap.tx.ExecContext(cap.ctx, `UPDATE main.tasks SET title='finalizer-must-not-write' WHERE id=1`)
			deniedUpdateReached = isCommandSQLiteAuthRefusal(deniedErr)
			if !deniedUpdateReached {
				return appMCPCommandCommitBarrier{}, fmt.Errorf("expected denied finalizer update, got %v", deniedErr)
			}
			return appMCPCommandCommitBarrier{}, errors.Join(finalizerErr, deniedErr)
		})
		if !errors.Is(err, finalizerErr) || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed ||
			!prepareReached || !auditReached || !applyReached || finalizerCalls != 1 || !deniedUpdateReached {
			t.Fatalf("finalizer error outcome=%+v milestones=%t/%t/%t calls=%d denied=%t err=%v", outcome, prepareReached, auditReached, applyReached, finalizerCalls, deniedUpdateReached, err)
		}
		assertCommandTaskUnchanged(t, app)
		var metadataRows int
		if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID).Scan(&metadataRows); err != nil || metadataRows != 0 {
			t.Fatalf("finalizer error retained operation metadata: rows=%d err=%v", metadataRows, err)
		}
		if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_audit_log WHERE action='command_fixture'`).Scan(&metadataRows); err != nil || metadataRows != 0 {
			t.Fatalf("finalizer error retained audit metadata: rows=%d err=%v", metadataRows, err)
		}
	})

	t.Run("finalizer panic after writes rolls back and releases connection", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		app.DB.SetMaxOpenConns(1)
		app.DB.SetMaxIdleConns(1)
		generation := snapshotAppMCPGeneration(app)
		request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
		const operationID = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		panicSentinel := errors.New("finalizer panic after pending writes")
		pendingWritesReached := false
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			_, _ = appMCPWithCommandOutcome(context.Background(), request, func(cap *appMCPCommandCapability) (bool, error) {
				if err := cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
					_, err := insertAppMCPPreparedOperation(cap.ctx, cap.tx, app, appMCPOperationStoreRecord(app, operationID))
					return err
				}); err != nil {
					return false, err
				}
				prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
				if err != nil {
					return false, err
				}
				if _, _, err := cap.apply(prepared); err != nil {
					return false, err
				}
				pendingWritesReached = true
				return true, nil
			}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
				panic(panicSentinel)
			})
		}()
		if recovered != panicSentinel || !pendingWritesReached {
			t.Fatalf("finalizer panic was not propagated after pending writes: recovered=%v reached=%t", recovered, pendingWritesReached)
		}
		assertCommandTaskUnchanged(t, app)
		var rows int
		if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("finalizer panic retained its prepared metadata: rows=%d err=%v", rows, err)
		}
		if err := appMCPWithCommandCapability(context.Background(), request, func(*appMCPCommandCapability) (bool, error) { return false, nil }); err != nil {
			t.Fatalf("native transaction could not reuse the connection after finalizer panic: %v", err)
		}
	})

	t.Run("callback decline is confirmed rollback", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		generation := snapshotAppMCPGeneration(app)
		request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
		outcome, err := appMCPWithCommandOutcome(context.Background(), request, func(cap *appMCPCommandCapability) (bool, error) {
			prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if err != nil {
				return false, err
			}
			if _, _, err := cap.apply(prepared); err != nil {
				return false, err
			}
			return false, nil
		}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
			return appMCPCommandCommitBarrier{}, nil
		})
		if err != nil || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed {
			t.Fatalf("declined outcome=%+v err=%v", outcome, err)
		}
		assertCommandTaskUnchanged(t, app)
	})

	t.Run("callback error rolls back", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		generation := snapshotAppMCPGeneration(app)
		request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
		callbackErr := errors.New("native callback failed")
		outcome, err := appMCPWithCommandOutcome(context.Background(), request, func(cap *appMCPCommandCapability) (bool, error) {
			prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if err != nil {
				return false, err
			}
			if _, _, err := cap.apply(prepared); err != nil {
				return false, err
			}
			return false, callbackErr
		}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
			return appMCPCommandCommitBarrier{}, nil
		})
		if !errors.Is(err, callbackErr) || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed {
			t.Fatalf("callback error outcome=%+v err=%v", outcome, err)
		}
		assertCommandTaskUnchanged(t, app)
	})

	t.Run("commit hook failure is unknown", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		app.DB.SetMaxOpenConns(1)
		app.DB.SetMaxIdleConns(0)
		generation := snapshotAppMCPGeneration(app)
		request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC()}
		hookReached, pendingWriteReached := false, false
		finalizerCalls := 0
		outcome, err := appMCPWithCommandOutcome(context.Background(), request, func(cap *appMCPCommandCapability) (bool, error) {
			prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if err != nil {
				return false, err
			}
			if _, _, err := cap.apply(prepared); err != nil {
				return false, err
			}
			pendingWriteReached = true
			if err := cap.conn.Raw(func(raw any) error {
				conn, ok := raw.(*sqlite3.SQLiteConn)
				if !ok {
					return errors.New("command connection is not SQLite")
				}
				conn.RegisterCommitHook(func() int { hookReached = true; return 1 })
				return nil
			}); err != nil {
				return false, err
			}
			return true, nil
		}, func(cap *appMCPCommandCapability, _ time.Time) (appMCPCommandCommitBarrier, error) {
			finalizerCalls++
			var status string
			if err := cap.tx.QueryRowContext(cap.ctx, `SELECT status FROM main.tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
				return appMCPCommandCommitBarrier{}, fmt.Errorf("commit-hook finalizer did not see pending write: status=%q err=%v", status, err)
			}
			return appMCPCommandCommitBarrier{}, nil
		})
		if !pendingWriteReached || !hookReached || finalizerCalls != 1 || err == nil || outcome.State != appMCPCommandCommitUnknown || outcome.RollbackConfirmed {
			t.Fatalf("commit hook outcome=%+v write=%t hook=%t finalizer=%d err=%v", outcome, pendingWriteReached, hookReached, finalizerCalls, err)
		}
		assertCommandTaskUnchanged(t, app)
		freshOutcome, freshErr := appMCPWithCommandOutcome(context.Background(), request, func(cap *appMCPCommandCapability) (bool, error) {
			prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if err != nil {
				return false, err
			}
			if _, _, err := cap.apply(prepared); err != nil {
				return false, err
			}
			return true, nil
		}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
			return appMCPCommandCommitBarrier{}, nil
		})
		if freshErr != nil || freshOutcome.State != appMCPCommandCommitConfirmed {
			t.Fatalf("fresh owner/connection transaction failed after rejected commit: outcome=%+v err=%v", freshOutcome, freshErr)
		}
		var status string
		if err := app.DB.QueryRow(`SELECT status FROM main.tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
			t.Fatalf("fresh transaction did not commit after rejected changes were absent: status=%q err=%v", status, err)
		}
	})
}

func TestAppMCPCommandNativeMetadataScopesUseExistingHelpers(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	ensureCommandAuditFixture(t, app)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(0)
	generation := snapshotAppMCPGeneration(app)
	operationID := strings.Repeat("f", 64)
	receipt := []byte(`{"result":{"status":"done"}}`)
	record := appMCPOperationStoreRecord(app, operationID)
	var preparedDigest string
	var forbiddenUpdateErr, forbiddenDeleteErr, forbiddenPrepareErr, forbiddenReceiptErr, forbiddenAuditInsertErr, forbiddenAuditUpdateErr error
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		if err := cap.enterReadPhase("prepare", []string{"tasks"}); err != nil {
			return false, err
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataRead, func() error { return nil }); err == nil {
			cap.leaveReadPhase()
			return false, errors.New("native metadata scope entered during an authored phase")
		}
		cap.leaveReadPhase()
		if err := cap.withNativeMetadata(0, nil); err == nil {
			return false, errors.New("native metadata scope accepted an invalid enum or nil callback")
		}
		cap.closed = true
		closedErr := cap.withNativeMetadata(appMCPCommandMetadataRead, func() error { return nil })
		cap.closed = false
		if closedErr == nil {
			return false, errors.New("closed command capability entered native metadata mode")
		}
		originalCtx := cap.ctx
		canceledCtx, cancel := context.WithCancel(originalCtx)
		cancel()
		cap.ctx = canceledCtx
		canceledErr := cap.withNativeMetadata(appMCPCommandMetadataRead, func() error { return nil })
		cap.ctx = originalCtx
		if !errors.Is(canceledErr, context.Canceled) {
			return false, errors.New("canceled command capability entered native metadata mode")
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
			if err := cap.withNativeMetadata(appMCPCommandMetadataRead, func() error { return nil }); err == nil {
				return errors.New("nested native metadata scope was admitted")
			}
			if err := cap.enterReadPhase("prepare", []string{"tasks"}); err == nil {
				cap.leaveReadPhase()
				return errors.New("metadata callback admitted an authored phase")
			}
			stored, err := insertAppMCPPreparedOperation(cap.ctx, cap.tx, app, record)
			if err == nil {
				preparedDigest = stored.PreparedDigest
			}
			return err
		}); err != nil {
			return false, err
		}
		if err := commandAssertQueryOnly(cap, true); err != nil {
			return false, err
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
			_, forbiddenUpdateErr = cap.tx.ExecContext(cap.ctx, `UPDATE main._benmore_mcp_operations SET prepared_digest=? WHERE operation_id=?`, strings.Repeat("0", 64), operationID)
			return nil
		}); err != nil || !isCommandSQLiteAuthRefusal(forbiddenUpdateErr) {
			return false, fmt.Errorf("prepare scope did not reach the expected receipt-column denial: scope=%v sql=%v", err, forbiddenUpdateErr)
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
			for _, statement := range []string{
				`UPDATE main.tasks SET title='metadata-must-not-write' WHERE id=1`,
				`UPDATE main._benmore_audit_log SET action='metadata-must-not-write'`,
				`CREATE TABLE main._benmore_command_unreviewed(id INTEGER)`,
				`SAVEPOINT command_metadata_nested`,
				`ATTACH DATABASE ':memory:' AS command_metadata_attached`,
				`PRAGMA user_version=1`,
				`PRAGMA query_only=OFF`,
			} {
				_, forbiddenPrepareErr = cap.tx.ExecContext(cap.ctx, statement)
				if !isCommandSQLiteAuthRefusal(forbiddenPrepareErr) {
					return fmt.Errorf("prepare scope admitted forbidden SQL %q", statement)
				}
			}
			return nil
		}); err != nil {
			return false, err
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataRead, func() error {
			stored, err := readAppMCPStoredOperation(cap.ctx, cap.tx, app, operationID)
			if err != nil {
				return fmt.Errorf("permitted operation readback failed: %w", err)
			}
			if stored.PreparedDigest != preparedDigest || !reflect.DeepEqual(stored.Prepared, record) {
				return errors.New("operation readback changed its prepared identity or digest")
			}
			_, forbiddenDeleteErr = cap.tx.ExecContext(cap.ctx, `DELETE FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID)
			return nil
		}); err != nil || !isCommandSQLiteAuthRefusal(forbiddenDeleteErr) {
			return false, fmt.Errorf("read scope did not reach expected delete denial: scope=%v sql=%v", err, forbiddenDeleteErr)
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataReceipt, func() error {
			stored, err := storeAppMCPCommittedReceipt(cap.ctx, cap.tx, app, operationID, preparedDigest, receipt)
			if err != nil {
				return fmt.Errorf("permitted receipt helper failed: %w", err)
			}
			if stored.ReceiptDigest == "" || string(stored.Receipt) != string(receipt) {
				return errors.New("receipt helper did not return the exact receipt")
			}
			_, forbiddenReceiptErr = cap.tx.ExecContext(cap.ctx, `UPDATE main._benmore_mcp_operations SET prepared_digest=? WHERE operation_id=?`, strings.Repeat("0", 64), operationID)
			return nil
		}); err != nil || !isCommandSQLiteAuthRefusal(forbiddenReceiptErr) {
			return false, fmt.Errorf("receipt scope did not reach expected prepared-digest denial: scope=%v sql=%v", err, forbiddenReceiptErr)
		}
		if err := cap.withNativeMetadata(appMCPCommandMetadataAudit, func() error {
			if err := insertAuditRowChecked(cap.tx, "command_fixture", "tasks", "1", &cap.actor, "{}", "{}"); err != nil {
				return fmt.Errorf("permitted audit helper failed: %w", err)
			}
			_, forbiddenAuditInsertErr = cap.tx.ExecContext(cap.ctx, `INSERT INTO main._benmore_mcp_operations(operation_id,prepared_digest,prepared_ciphertext) VALUES(?,?,?)`, strings.Repeat("a", 64), strings.Repeat("b", 64), "refused")
			if !isCommandSQLiteAuthRefusal(forbiddenAuditInsertErr) {
				return errors.New("audit scope did not reach operation-insert denial")
			}
			_, forbiddenAuditUpdateErr = cap.tx.ExecContext(cap.ctx, `UPDATE main._benmore_audit_log SET action='audit-must-not-update' WHERE action='command_fixture'`)
			if !isCommandSQLiteAuthRefusal(forbiddenAuditUpdateErr) {
				return errors.New("audit scope did not reach audit-update denial")
			}
			return nil
		}); err != nil {
			return false, err
		}
		if err := commandAssertQueryOnly(cap, true); err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("native metadata scopes: %v", err)
	}
	if !isCommandSQLiteAuthRefusal(forbiddenUpdateErr) || !isCommandSQLiteAuthRefusal(forbiddenDeleteErr) || !isCommandSQLiteAuthRefusal(forbiddenPrepareErr) ||
		!isCommandSQLiteAuthRefusal(forbiddenReceiptErr) || !isCommandSQLiteAuthRefusal(forbiddenAuditInsertErr) || !isCommandSQLiteAuthRefusal(forbiddenAuditUpdateErr) {
		t.Fatalf("one of the scoped SQL refusal controls was not an SQLite authorizer denial: %v %v %v %v %v %v", forbiddenUpdateErr, forbiddenDeleteErr, forbiddenPrepareErr, forbiddenReceiptErr, forbiddenAuditInsertErr, forbiddenAuditUpdateErr)
	}
	var stored *appMCPStoredOperation
	err = appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		return false, cap.withNativeMetadata(appMCPCommandMetadataRead, func() error {
			var readErr error
			stored, readErr = readAppMCPStoredOperation(cap.ctx, cap.tx, app, operationID)
			return readErr
		})
	})
	if err != nil || stored == nil || !reflect.DeepEqual(stored.Prepared, record) || stored.PreparedDigest != preparedDigest || string(stored.Receipt) != string(receipt) || stored.ReceiptDigest == "" {
		t.Fatalf("fresh scoped encrypted operation/receipt readback failed: stored=%+v err=%v", stored, err)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_audit_log WHERE action='command_fixture' AND table_name='tasks'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("native audit helper did not persist exactly one row: count=%d err=%v", count, err)
	}
	assertCommandTaskUnchanged(t, app)
}

func isCommandSQLiteAuthRefusal(err error) bool {
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrAuth
}

func commandAssertQueryOnly(cap *appMCPCommandCapability, want bool) error {
	return cap.withInternalRead(func() error {
		var queryOnly bool
		if err := cap.tx.QueryRowContext(cap.ctx, `PRAGMA query_only`).Scan(&queryOnly); err != nil {
			return err
		}
		if queryOnly != want {
			return fmt.Errorf("native metadata boundary query_only=%t want=%t", queryOnly, want)
		}
		return nil
	})
}

func TestAppMCPCommandNativeMetadataRollbackAfterDeclineAndError(t *testing.T) {
	for _, failWithError := range []bool{false, true} {
		name := "decline"
		if failWithError {
			name = "error"
		}
		t.Run(name, func(t *testing.T) {
			app, sessionID, _ := newCommandProviderTaskFixture(t)
			ensureCommandAuditFixture(t, app)
			generation := snapshotAppMCPGeneration(app)
			suffix := "1"
			if failWithError {
				suffix = "2"
			}
			operationID := strings.Repeat("a", 63) + suffix
			callbackErr := errors.New("metadata helper rollback sentinel")
			prepareReached, auditReached := false, false
			outcome, err := appMCPWithCommandOutcome(context.Background(), appMCPCommandRequest{
				app: app, generation: generation, toolName: "complete_item",
				origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
			}, func(cap *appMCPCommandCapability) (bool, error) {
				if err := cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
					_, err := insertAppMCPPreparedOperation(cap.ctx, cap.tx, app, appMCPOperationStoreRecord(app, operationID))
					prepareReached = err == nil
					return err
				}); err != nil {
					return false, err
				}
				if err := cap.withNativeMetadata(appMCPCommandMetadataAudit, func() error {
					err := insertAuditRowChecked(cap.tx, "command_rollback_fixture", "tasks", "1", &cap.actor, "{}", "{}")
					auditReached = err == nil
					return err
				}); err != nil {
					return false, err
				}
				if failWithError {
					return false, callbackErr
				}
				return false, nil
			}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
				return appMCPCommandCommitBarrier{}, nil
			})
			if !prepareReached || !auditReached || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed {
				t.Fatalf("metadata mutations were not reached before rollback: outcome=%+v prepare=%t audit=%t err=%v", outcome, prepareReached, auditReached, err)
			}
			if failWithError && !errors.Is(err, callbackErr) || !failWithError && err != nil {
				t.Fatalf("unexpected rollback result: err=%v", err)
			}
			var rows int
			if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID).Scan(&rows); err != nil || rows != 0 {
				t.Fatalf("rollback retained the actual prepared-operation helper row: rows=%d err=%v", rows, err)
			}
			if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_audit_log WHERE action='command_rollback_fixture'`).Scan(&rows); err != nil || rows != 0 {
				t.Fatalf("rollback retained the actual audit-helper row: rows=%d err=%v", rows, err)
			}
			assertCommandTaskUnchanged(t, app)
		})
	}
}

func TestAppMCPCommandNativeMetadataRevalidatesAfterPolicyRestore(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	generation := snapshotAppMCPGeneration(app)
	const operationID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	helperReached := false
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		return false, cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
			_, err := insertAppMCPPreparedOperation(cap.ctx, cap.tx, app, appMCPOperationStoreRecord(app, operationID))
			helperReached = err == nil
			if err != nil {
				return err
			}
			app.mu.Lock()
			app.mcpGeneration = appMCPGenerationFromAppLocked(app)
			app.mu.Unlock()
			return nil
		})
	})
	if !helperReached || err == nil || !strings.Contains(err.Error(), "command source generation changed") {
		t.Fatalf("post-scope lifetime check did not revalidate the changed source generation: helper=%t err=%v", helperReached, err)
	}
	var rows int
	if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("stale source generation committed metadata: rows=%d err=%v", rows, err)
	}
}

func TestAppMCPCommandNativeMetadataPanicRestoresConnection(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	generation := snapshotAppMCPGeneration(app)
	const operationID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	panicSentinel := errors.New("native metadata panic after insert")
	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		_ = appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
			app: app, generation: generation, toolName: "complete_item",
			origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
		}, func(cap *appMCPCommandCapability) (bool, error) {
			return false, cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
				if _, err := insertAppMCPPreparedOperation(cap.ctx, cap.tx, app, appMCPOperationStoreRecord(app, operationID)); err != nil {
					return fmt.Errorf("metadata prepare before panic: %w", err)
				}
				panic(panicSentinel)
			})
		})
	}()
	if recovered != panicSentinel {
		t.Fatalf("native metadata callback panic was swallowed or changed: %v", recovered)
	}
	assertCommandTaskUnchanged(t, app)
	var rows int
	if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("native metadata panic retained its prepared row: rows=%d err=%v", rows, err)
	}
	var queryOnly bool
	if err := app.DB.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly {
		t.Fatalf("native metadata panic left a poisoned pooled connection: query_only=%t err=%v", queryOnly, err)
	}
	if err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(*appMCPCommandCapability) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("native transaction could not reuse the connection after metadata panic: %v", err)
	}
}

func TestAppMCPCommandCanceledNativeMetadataDiscardsAndReusesPool(t *testing.T) {
	const childEnv = "BENMORE_MCP_COMMAND_CANCEL_METADATA_SCOPE"
	if os.Getenv(childEnv) == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPCommandCanceledNativeMetadataDiscardsAndReusesPool$")
		env := make([]string, 0, len(os.Environ())+1)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, childEnv+"=") {
				env = append(env, value)
			}
		}
		cmd.Env = append(env, childEnv+"=child")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("canceled native metadata cleanup exceeded eight seconds: %s", output)
		}
		if err != nil {
			t.Fatalf("canceled native metadata child failed: %v\n%s", err, output)
		}
		return
	}

	app, sessionID, _ := newCommandProviderTaskFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	generation := snapshotAppMCPGeneration(app)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const operationID = "9999999999999999999999999999999999999999999999999999999999999999"
	const connectionProbe = "command_cancel_metadata_connection_probe"
	var reachedWrite, reachedRead bool
	var oldConnID string
	var readErr error
	outcome, err := appMCPWithCommandOutcome(ctx, appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		return false, cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
			if _, err := insertAppMCPPreparedOperation(cap.ctx, cap.tx, app, appMCPOperationStoreRecord(app, operationID)); err != nil {
				return fmt.Errorf("native metadata insert before cancellation: %w", err)
			}
			reachedWrite = true
			if err := cap.conn.Raw(func(raw any) error {
				conn, ok := raw.(*sqlite3.SQLiteConn)
				if !ok {
					return errors.New("metadata cancellation connection is not SQLite")
				}
				oldConnID = fmt.Sprintf("%p", conn)
				return conn.RegisterFunc(connectionProbe, func() int { return 947 }, true)
			}); err != nil {
				return fmt.Errorf("install native cancellation disposal probe: %w", err)
			}
			reached, finish := commandCancelAtSQLiteAction(t, cap, ctx, cancel, sqlite3.SQLITE_READ, "_benmore_mcp_operations")
			var rows int
			readErr = cap.tx.QueryRowContext(cap.ctx, `SELECT count(*) FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID).Scan(&rows)
			finish()
			reachedRead = reached()
			if !errors.Is(readErr, context.Canceled) {
				return fmt.Errorf("metadata SQL did not preserve native cancellation: %v", readErr)
			}
			return readErr
		})
	}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
		return appMCPCommandCommitBarrier{}, nil
	})
	if !reachedWrite || !reachedRead || oldConnID == "" || !errors.Is(readErr, context.Canceled) || !errors.Is(err, context.Canceled) ||
		outcome.State != appMCPCommandCommitNotAttempted {
		t.Fatalf("metadata cancellation was not reached: write=%t read=%t oldConn=%q readErr=%v outcome=%+v outerErr=%v", reachedWrite, reachedRead, oldConnID, readErr, outcome, err)
	}
	assertCommandTaskUnchanged(t, app)
	var rows int
	if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("canceled metadata write was not rolled back: rows=%d err=%v", rows, err)
	}
	cleanConn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatalf("acquire clean connection after metadata cancellation: %v", err)
	}
	cleanConnID, err := commandSQLiteConnID(cleanConn)
	if err != nil || (outcome.CleanupErr != nil && cleanConnID == oldConnID) {
		_ = cleanConn.Close()
		t.Fatalf("uncertain metadata connection was not discarded: cleanupErr=%v old=%q new=%q identityErr=%v", outcome.CleanupErr, oldConnID, cleanConnID, err)
	}
	var probe int
	probeErr := cleanConn.QueryRowContext(context.Background(), `SELECT `+connectionProbe+`()`).Scan(&probe)
	if outcome.CleanupErr != nil && probeErr == nil {
		_ = cleanConn.Close()
		t.Fatalf("native function from uncertain cancellation connection survived discard: result=%d", probe)
	}
	if outcome.CleanupErr == nil && cleanConnID == oldConnID && (probeErr != nil || probe != 947) {
		_ = cleanConn.Close()
		t.Fatalf("clean reused connection lost its native probe: result=%d err=%v", probe, probeErr)
	}
	if outcome.CleanupErr == nil && cleanConnID != oldConnID && probeErr == nil {
		_ = cleanConn.Close()
		t.Fatalf("replacement connection unexpectedly retained the prior native probe: result=%d", probe)
	}
	var queryOnly bool
	if err := cleanConn.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly {
		_ = cleanConn.Close()
		t.Fatalf("post-cancellation connection was not clean: query_only=%t err=%v", queryOnly, err)
	}
	if err := cleanConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(*appMCPCommandCapability) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("fresh native owner transaction failed after metadata cancellation: %v", err)
	}
}

func commandSetBusyTimeoutFixture(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close busy-timeout fixture connection: %v", err)
		}
	}()
	if err := appMCPCommandSetBusyTimeout(context.Background(), conn, want); err != nil {
		t.Fatalf("set fixture busy timeout: %v", err)
	}
}

func commandReadBusyTimeoutFixture(t *testing.T, db *sql.DB) int {
	t.Helper()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close busy-timeout read connection: %v", err)
		}
	}()
	got, err := appMCPCommandReadBusyTimeout(context.Background(), conn)
	if err != nil {
		t.Fatalf("read fixture busy timeout: %v", err)
	}
	return got
}

func commandInstallPreBeginAuthorizer(t *testing.T, db *sql.DB, authorize func(int, string, string, string) int) (string, func()) {
	t.Helper()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			if err := conn.Close(); err != nil {
				t.Errorf("close pre-BEGIN authorizer fixture connection: %v", err)
			}
		}
	}()
	id, err := commandSQLiteConnID(conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("pre-BEGIN authorizer fixture connection is not SQLite")
		}
		sqliteConn.RegisterAuthorizer(authorize)
		return nil
	}); err != nil {
		t.Fatalf("install pre-BEGIN authorizer: %v", err)
	}
	restore := commandRestorePreBeginAuthorizer(t, db)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	return id, restore
}

func commandRestorePreBeginAuthorizer(t *testing.T, db *sql.DB) func() {
	t.Helper()
	restored := false
	restore := func() {
		if restored {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Errorf("acquire connection to restore native storage authorizer: %v", err)
			return
		}
		restoreErr := conn.Raw(func(raw any) error {
			sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("authorizer cleanup connection is not SQLite")
			}
			restoreConnAuthorizer(sqliteConn)
			return nil
		})
		closeErr := conn.Close()
		if restoreErr != nil || closeErr != nil {
			t.Errorf("restore native storage authorizer: raw=%v close=%v", restoreErr, closeErr)
			return
		}
		restored = true
	}
	t.Cleanup(restore)
	return restore
}

func TestAppMCPCommandBeginCancellationIsBoundedAndBeforeUse(t *testing.T) {
	t.Run("already canceled does not reach BEGIN", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		app.DB.SetMaxOpenConns(1)
		app.DB.SetMaxIdleConns(1)
		generation := snapshotAppMCPGeneration(app)
		originalBusyTimeout := commandReadBusyTimeoutFixture(t, app.DB)
		beginCalls := 0
		_, restoreAuthorizer := commandInstallPreBeginAuthorizer(t, app.DB, func(action int, arg1, _, _ string) int {
			if action == sqlite3.SQLITE_TRANSACTION && strings.EqualFold(arg1, "BEGIN") {
				beginCalls++
			}
			return sqlite3.SQLITE_OK
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		useCalls, finalizeCalls := 0, 0
		outcome, err := appMCPWithCommandOutcome(ctx, appMCPCommandRequest{
			app: app, generation: generation, toolName: "complete_item",
			origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
		}, func(*appMCPCommandCapability) (bool, error) { useCalls++; return true, nil }, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
			finalizeCalls++
			return appMCPCommandCommitBarrier{}, nil
		})
		if !errors.Is(err, context.Canceled) || outcome.State != appMCPCommandCommitNotAttempted || beginCalls != 0 || useCalls != 0 || finalizeCalls != 0 {
			t.Fatalf("pre-canceled command crossed native admission: outcome=%+v err=%v begin=%d use=%d finalize=%d", outcome, err, beginCalls, useCalls, finalizeCalls)
		}
		restoreAuthorizer()
		assertCommandTaskUnchanged(t, app)
		if got := commandReadBusyTimeoutFixture(t, app.DB); got != originalBusyTimeout {
			t.Fatalf("already-canceled command changed native timeout: got=%d want=%d", got, originalBusyTimeout)
		}
		if err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
			app: app, generation: generation, toolName: "complete_item",
			origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
		}, func(*appMCPCommandCapability) (bool, error) { return false, nil }); err != nil {
			t.Fatalf("fresh owner transaction failed after already-canceled call: %v", err)
		}
	})

	t.Run("cancel at real BEGIN joins worker and rolls back", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixture(t)
		app.DB.SetMaxOpenConns(1)
		app.DB.SetMaxIdleConns(1)
		generation := snapshotAppMCPGeneration(app)
		originalBusyTimeout := commandReadBusyTimeoutFixture(t, app.DB)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		trigger, workerDone := make(chan struct{}), make(chan struct{})
		beginReached := false
		_, restoreAuthorizer := commandInstallPreBeginAuthorizer(t, app.DB, func(action int, arg1, _, _ string) int {
			if action == sqlite3.SQLITE_TRANSACTION && strings.EqualFold(arg1, "BEGIN") && !beginReached {
				beginReached = true
				close(trigger)
				<-workerDone
			}
			return sqlite3.SQLITE_OK
		})
		go func() {
			defer close(workerDone)
			select {
			case <-trigger:
				cancel()
			case <-ctx.Done():
			}
		}()
		workerJoined := false
		t.Cleanup(func() {
			cancel()
			if workerJoined {
				return
			}
			select {
			case <-workerDone:
			case <-time.After(2 * time.Second):
				t.Errorf("BEGIN-cancellation worker did not join within cleanup bound")
			}
		})
		useCalls, finalizeCalls := 0, 0
		started := time.Now()
		outcome, err := appMCPWithCommandOutcome(ctx, appMCPCommandRequest{
			app: app, generation: generation, toolName: "complete_item",
			origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
		}, func(*appMCPCommandCapability) (bool, error) { useCalls++; return true, nil }, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
			finalizeCalls++
			return appMCPCommandCommitBarrier{}, nil
		})
		if !beginReached {
			cancel()
		}
		<-workerDone
		workerJoined = true
		restoreAuthorizer()
		if time.Since(started) > 3*time.Second || !beginReached || !errors.Is(err, context.Canceled) || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed || outcome.CleanupErr != nil || useCalls != 0 || finalizeCalls != 0 {
			t.Fatalf("BEGIN cancellation did not finish boundedly before use: elapsed=%s reached=%t outcome=%+v err=%v use=%d finalize=%d", time.Since(started), beginReached, outcome, err, useCalls, finalizeCalls)
		}
		assertCommandTaskUnchanged(t, app)
		if got := commandReadBusyTimeoutFixture(t, app.DB); got != originalBusyTimeout {
			t.Fatalf("BEGIN cancellation did not restore captured timeout: got=%d want=%d", got, originalBusyTimeout)
		}
		if err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
			app: app, generation: generation, toolName: "complete_item",
			origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
		}, func(*appMCPCommandCapability) (bool, error) { return false, nil }); err != nil {
			t.Fatalf("fresh owner transaction failed after BEGIN cancellation: %v", err)
		}
	})
}

func TestAppMCPCommandRestoresBusyTimeoutBeforeCallbackOnDeclineAndError(t *testing.T) {
	for _, failWithError := range []bool{false, true} {
		name := "decline"
		if failWithError {
			name = "error"
		}
		t.Run(name, func(t *testing.T) {
			app, sessionID, _ := newCommandProviderTaskFixture(t)
			app.DB.SetMaxOpenConns(1)
			app.DB.SetMaxIdleConns(1)
			const original = 1731
			commandSetBusyTimeoutFixture(t, app.DB, original)
			generation := snapshotAppMCPGeneration(app)
			callbackErr := errors.New("busy timeout callback error sentinel")
			useCalls, finalizeCalls := 0, 0
			restoreObserved := false
			_, restoreAuthorizer := commandInstallPreBeginAuthorizer(t, app.DB, func(action int, arg1, arg2, _ string) int {
				if action == sqlite3.SQLITE_PRAGMA && strings.EqualFold(arg1, "busy_timeout") && strings.TrimSpace(arg2) == strconv.Itoa(original) {
					restoreObserved = true
				}
				return sqlite3.SQLITE_OK
			})
			outcome, err := appMCPWithCommandOutcome(context.Background(), appMCPCommandRequest{
				app: app, generation: generation, toolName: "complete_item",
				origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
			}, func(*appMCPCommandCapability) (bool, error) {
				useCalls++
				if !restoreObserved {
					return false, errors.New("captured native busy timeout was not restored before callback")
				}
				if failWithError {
					return false, callbackErr
				}
				return false, nil
			}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
				finalizeCalls++
				return appMCPCommandCommitBarrier{}, nil
			})
			if !restoreObserved || useCalls != 1 || finalizeCalls != 0 || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed || outcome.CleanupErr != nil {
				t.Fatalf("declined/error callback outcome changed: outcome=%+v err=%v use=%d finalize=%d", outcome, err, useCalls, finalizeCalls)
			}
			if failWithError && !errors.Is(err, callbackErr) || !failWithError && err != nil {
				t.Fatalf("callback result changed: %v", err)
			}
			restoreAuthorizer()
			assertCommandTaskUnchanged(t, app)
			if got := commandReadBusyTimeoutFixture(t, app.DB); got != original {
				t.Fatalf("callback ran without restoring captured timeout: got=%d want=%d", got, original)
			}
		})
	}
}

func TestAppMCPCommandBusyTimeoutRestoresAfterBeginContention(t *testing.T) {
	const childEnv = "BENMORE_MCP_COMMAND_BEGIN_CONTENTION_CHILD"
	if os.Getenv(childEnv) != "child" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPCommandBusyTimeoutRestoresAfterBeginContention$")
		env := make([]string, 0, len(os.Environ())+1)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, childEnv+"=") {
				env = append(env, value)
			}
		}
		cmd.Env = append(env, childEnv+"=child")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("native BEGIN contention child exceeded eight seconds: %s", output)
		}
		if err != nil {
			t.Fatalf("native BEGIN contention child failed: %v\n%s", err, output)
		}
		return
	}

	app, sessionID, _ := newCommandProviderTaskFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	const original = 10000
	commandSetBusyTimeoutFixture(t, app.DB, original)
	if captured := commandReadBusyTimeoutFixture(t, app.DB); captured != original {
		t.Fatalf("contention fixture did not capture requested native timeout: got=%d want=%d", captured, original)
	}
	generation := snapshotAppMCPGeneration(app)
	blocker, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(app.Dir, "data.db"), app.Dir))
	if err != nil {
		t.Fatal(err)
	}
	closeBlocker := true
	defer func() {
		if closeBlocker {
			if err := blocker.Close(); err != nil {
				t.Errorf("close competing writer database: %v", err)
			}
		}
	}()
	blocker.SetMaxOpenConns(1)
	blocker.SetMaxIdleConns(1)
	blockTx, err := blocker.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("acquire real competing BEGIN IMMEDIATE lock: %v", err)
	}
	blockTxOwned := true
	defer func() {
		if blockTxOwned {
			if err := blockTx.Rollback(); err != nil {
				t.Errorf("rollback competing writer during cleanup: %v", err)
			} else {
				blockTxOwned = false
			}
		}
	}()
	if _, err := blockTx.ExecContext(context.Background(), `UPDATE main.tasks SET title=title WHERE id=1`); err != nil {
		t.Fatalf("hold competing write lock: %v", err)
	}
	useCalls, finalizeCalls := 0, 0
	started := time.Now()
	outcome, err := appMCPWithCommandOutcome(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(*appMCPCommandCapability) (bool, error) { useCalls++; return true, nil }, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
		finalizeCalls++
		return appMCPCommandCommitBarrier{}, nil
	})
	var sqliteErr sqlite3.Error
	if time.Since(started) > 2*time.Second || !errors.As(err, &sqliteErr) || sqliteErr.Code != sqlite3.ErrBusy && sqliteErr.Code != sqlite3.ErrLocked || outcome.State != appMCPCommandCommitNotAttempted || outcome.CleanupErr != nil || useCalls != 0 || finalizeCalls != 0 {
		t.Fatalf("contended BEGIN did not fail fast before callback: elapsed=%s outcome=%+v err=%v use=%d finalize=%d", time.Since(started), outcome, err, useCalls, finalizeCalls)
	}
	assertCommandTaskUnchanged(t, app)
	if got := commandReadBusyTimeoutFixture(t, app.DB); got != original {
		t.Fatalf("failed BEGIN did not restore captured timeout: got=%d want=%d", got, original)
	}
	if err := blockTx.Rollback(); err != nil {
		t.Fatalf("release competing transaction: %v", err)
	}
	blockTxOwned = false
	if err := blocker.Close(); err != nil {
		t.Fatalf("close competing writer after checked rollback: %v", err)
	}
	closeBlocker = false
	if err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		if _, _, err := cap.apply(prepared); err != nil {
			return false, err
		}
		return true, nil
	}); err != nil {
		t.Fatalf("valid task command failed after releasing writer: %v", err)
	}
	var status string
	if err := app.DB.QueryRow(`SELECT status FROM main.tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
		t.Fatalf("valid task command did not commit after contention: status=%q err=%v", status, err)
	}
}

func TestAppMCPCommandBusyTimeoutRestoreDenialDiscardsConnection(t *testing.T) {
	const childEnv = "BENMORE_MCP_COMMAND_BUSY_TIMEOUT_RESTORE_CHILD"
	if os.Getenv(childEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPCommandBusyTimeoutRestoreDenialDiscardsConnection$")
		env := make([]string, 0, len(os.Environ())+1)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, childEnv+"=") {
				env = append(env, value)
			}
		}
		cmd.Env = append(env, childEnv+"=1")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("native busy timeout restoration fault exceeded eight seconds: %s", output)
		}
		if err != nil {
			t.Fatalf("native busy timeout restoration child failed: %v\n%s", err, output)
		}
		return
	}

	app, sessionID, _ := newCommandProviderTaskFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	const requestedOriginal = 1739
	commandSetBusyTimeoutFixture(t, app.DB, requestedOriginal)
	original := commandReadBusyTimeoutFixture(t, app.DB)
	if original != requestedOriginal {
		t.Fatalf("restoration-denial fixture failed to capture timeout: got=%d want=%d", original, requestedOriginal)
	}
	const connectionProbe = "command_busy_timeout_restore_probe"
	initialReadback, zeroSetter, zeroReadback := false, false, false
	beginAfterZeroReadback, restoreDeniedAfterBegin := false, false
	rollbackObserved := false
	order := 0
	var targets []string
	oldConnID, restoreAuthorizer := commandInstallPreBeginAuthorizer(t, app.DB, func(action int, arg1, arg2, _ string) int {
		if action == sqlite3.SQLITE_PRAGMA && strings.EqualFold(arg1, "busy_timeout") {
			switch strings.TrimSpace(arg2) {
			case "":
				if order == 0 {
					initialReadback = true
					targets = append(targets, "initial-readback")
				} else if order == 1 {
					zeroReadback = true
					order = 2
					targets = append(targets, "readback-after-zero")
				} else {
					targets = append(targets, "later-readback")
				}
			case "0":
				if order == 0 && initialReadback {
					zeroSetter = true
					order = 1
					targets = append(targets, "setter-zero")
				} else {
					targets = append(targets, "setter-zero-out-of-order")
				}
			default:
				if strings.TrimSpace(arg2) == strconv.Itoa(original) {
					if order == 3 && beginAfterZeroReadback && !rollbackObserved {
						restoreDeniedAfterBegin = true
						targets = append(targets, "restore-original-denied-after-BEGIN")
					} else if rollbackObserved {
						targets = append(targets, "restore-original-retry-denied-after-ROLLBACK")
					} else {
						targets = append(targets, "restore-original-denied-out-of-order")
						return sqlite3.SQLITE_OK
					}
					return sqlite3.SQLITE_DENY
				}
			}
		}
		if action == sqlite3.SQLITE_TRANSACTION && strings.EqualFold(arg1, "BEGIN") {
			if order == 2 && zeroSetter && zeroReadback {
				beginAfterZeroReadback = true
				order = 3
				targets = append(targets, "BEGIN-after-zero-readback")
			} else {
				targets = append(targets, "BEGIN-out-of-order")
			}
		} else if action == sqlite3.SQLITE_TRANSACTION && strings.EqualFold(arg1, "ROLLBACK") {
			rollbackObserved = true
			targets = append(targets, "ROLLBACK")
		}
		return sqlite3.SQLITE_OK
	})
	// Register a connection-local marker on the same physical handle so that
	// the later check proves real driver disposal, not only pool bookkeeping.
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	connClosed := false
	defer func() {
		if !connClosed {
			if err := conn.Close(); err != nil {
				t.Errorf("close busy-timeout fault setup connection: %v", err)
			}
		}
	}()
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("busy timeout fault connection is not SQLite")
		}
		return sqliteConn.RegisterFunc(connectionProbe, func() int { return 491 }, true)
	}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	connClosed = true
	generation := snapshotAppMCPGeneration(app)
	useCalls, finalizeCalls := 0, 0
	outcome, err := appMCPWithCommandOutcome(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(*appMCPCommandCapability) (bool, error) { useCalls++; return true, nil }, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
		finalizeCalls++
		return appMCPCommandCommitBarrier{}, nil
	})
	if !initialReadback || !zeroSetter || !zeroReadback || !beginAfterZeroReadback || !restoreDeniedAfterBegin || useCalls != 0 || finalizeCalls != 0 || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed || outcome.CleanupErr == nil || err == nil {
		t.Fatalf("native BEGIN timeout restoration denial did not follow readback/zero/BEGIN/original order: targets=%v outcome=%+v err=%v use=%d finalize=%d", targets, outcome, err, useCalls, finalizeCalls)
	}
	assertCommandTaskUnchanged(t, app)
	cleanConn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatalf("acquire connection after timeout restoration denial: %v", err)
	}
	cleanConnClosed := false
	defer func() {
		if !cleanConnClosed {
			if err := cleanConn.Close(); err != nil {
				t.Errorf("close clean timeout-replacement connection: %v", err)
			}
		}
	}()
	newConnID, err := commandSQLiteConnID(cleanConn)
	if err != nil || newConnID == oldConnID {
		t.Fatalf("uncertain native timeout connection was not physically discarded: old=%q new=%q err=%v", oldConnID, newConnID, err)
	}
	var marker int
	if err := cleanConn.QueryRowContext(context.Background(), `SELECT `+connectionProbe+`()`).Scan(&marker); err == nil {
		t.Fatalf("connection-local marker survived timeout restoration discard: value=%d", marker)
	}
	queryOnly, err := func() (bool, error) {
		var value bool
		err := cleanConn.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&value)
		return value, err
	}()
	if err != nil || queryOnly {
		t.Fatalf("replacement after timeout fault is not clean: query_only=%t err=%v", queryOnly, err)
	}
	if err := cleanConn.Close(); err != nil {
		t.Fatal(err)
	}
	cleanConnClosed = true
	restoreAuthorizer()
	if err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(*appMCPCommandCapability) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("fresh owner transaction failed after timeout restoration discard: %v", err)
	}
}

func TestAppMCPCommandNativeMetadataRestorationFaultDisposesAfterRollback(t *testing.T) {
	const childEnv = "BENMORE_MCP_COMMAND_METADATA_RESTORE_CHILD"
	if os.Getenv(childEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPCommandNativeMetadataRestorationFaultDisposesAfterRollback$")
		env := make([]string, 0, len(os.Environ())+1)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, childEnv+"=") {
				env = append(env, value)
			}
		}
		cmd.Env = append(env, childEnv+"=1")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("live-Tx metadata restoration fault exceeded eight seconds: %s", output)
		}
		if err != nil {
			t.Fatalf("live-Tx metadata restoration child failed: %v\n%s", err, output)
		}
		return
	}

	app, sessionID, _ := newCommandProviderTaskFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	generation := snapshotAppMCPGeneration(app)
	const operationID = "8888888888888888888888888888888888888888888888888888888888888888"
	const connectionProbe = "command_metadata_restore_connection_probe"
	writeReached, faultInstalled, restoreDenied := false, false, false
	var poisonedConnID string
	outcome, err := appMCPWithCommandOutcome(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		return false, cap.withNativeMetadata(appMCPCommandMetadataPrepare, func() error {
			if _, err := insertAppMCPPreparedOperation(cap.ctx, cap.tx, app, appMCPOperationStoreRecord(app, operationID)); err != nil {
				return fmt.Errorf("native metadata insert before live-Tx fault: %w", err)
			}
			writeReached = true
			return cap.conn.Raw(func(raw any) error {
				conn, ok := raw.(*sqlite3.SQLiteConn)
				if !ok {
					return errors.New("metadata cleanup fixture connection is not SQLite")
				}
				poisonedConnID = fmt.Sprintf("%p", conn)
				if err := conn.RegisterFunc(connectionProbe, func() int { return 811 }, true); err != nil {
					return err
				}
				guard := cap.guard
				conn.RegisterAuthorizer(func(action int, arg1, arg2, database string) int {
					if action == sqlite3.SQLITE_PRAGMA && strings.EqualFold(arg1, "query_only") && strings.EqualFold(arg2, "ON") {
						restoreDenied = true
						return sqlite3.SQLITE_DENY
					}
					return guard.authorize(action, arg1, arg2, database)
				})
				faultInstalled = true
				return nil
			})
		})
	}, func(*appMCPCommandCapability, time.Time) (appMCPCommandCommitBarrier, error) {
		return appMCPCommandCommitBarrier{}, nil
	})
	if !writeReached || !faultInstalled || !restoreDenied || poisonedConnID == "" {
		t.Fatalf("live-Tx metadata restoration fault was not reached: write=%t installed=%t denied=%t conn=%q err=%v", writeReached, faultInstalled, restoreDenied, poisonedConnID, err)
	}
	if !isCommandSQLiteAuthRefusal(err) || !isCommandSQLiteAuthRefusal(outcome.CleanupErr) || outcome.State != appMCPCommandCommitNotAttempted || !outcome.RollbackConfirmed {
		t.Fatalf("live-Tx metadata cleanup did not report authorizer uncertainty and confirmed rollback: outcome=%+v err=%v", outcome, err)
	}
	assertCommandTaskUnchanged(t, app)
	var rows int
	if err := app.DB.QueryRow(`SELECT count(*) FROM main._benmore_mcp_operations WHERE operation_id=?`, operationID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("live-Tx metadata restoration fault retained prepared row: rows=%d err=%v", rows, err)
	}
	cleanConn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatalf("acquire replacement connection after metadata restoration fault: %v", err)
	}
	cleanConnID, err := commandSQLiteConnID(cleanConn)
	if err != nil || cleanConnID == poisonedConnID {
		_ = cleanConn.Close()
		t.Fatalf("faulted metadata connection was not physically discarded: old=%q new=%q err=%v", poisonedConnID, cleanConnID, err)
	}
	var probe int
	if err := cleanConn.QueryRowContext(context.Background(), `SELECT `+connectionProbe+`()`).Scan(&probe); err == nil {
		_ = cleanConn.Close()
		t.Fatalf("connection-local function survived metadata cleanup discard: result=%d", probe)
	}
	var queryOnly bool
	if err := cleanConn.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly {
		_ = cleanConn.Close()
		t.Fatalf("metadata cleanup replacement connection is not clean: query_only=%t err=%v", queryOnly, err)
	}
	if err := cleanConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(*appMCPCommandCapability) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("fresh owner/Tx failed after deterministic metadata cleanup fault: %v", err)
	}
}

func TestAppMCPCommandNativeMetadataAuthorizerIsClosed(t *testing.T) {
	cases := []struct {
		name     string
		op       appMCPCommandMetadataOp
		action   int
		arg1     string
		arg2     string
		database string
		want     int
	}{
		{"prepare operation insert", appMCPCommandMetadataPrepare, sqlite3.SQLITE_INSERT, "_benmore_mcp_operations", "", "main", sqlite3.SQLITE_OK},
		{"prepare operation update denied", appMCPCommandMetadataPrepare, sqlite3.SQLITE_UPDATE, "_benmore_mcp_operations", "prepared_digest", "main", sqlite3.SQLITE_DENY},
		{"receipt exact column", appMCPCommandMetadataReceipt, sqlite3.SQLITE_UPDATE, "_benmore_mcp_operations", "receipt_ciphertext", "main", sqlite3.SQLITE_OK},
		{"receipt prepared digest denied", appMCPCommandMetadataReceipt, sqlite3.SQLITE_UPDATE, "_benmore_mcp_operations", "prepared_digest", "main", sqlite3.SQLITE_DENY},
		{"receipt audit mutation denied", appMCPCommandMetadataReceipt, sqlite3.SQLITE_UPDATE, "_benmore_audit_log", "action", "main", sqlite3.SQLITE_DENY},
		{"audit insert", appMCPCommandMetadataAudit, sqlite3.SQLITE_INSERT, "_benmore_audit_log", "", "main", sqlite3.SQLITE_OK},
		{"audit sequence direct mutation denied", appMCPCommandMetadataAudit, sqlite3.SQLITE_UPDATE, "sqlite_sequence", "seq", "main", sqlite3.SQLITE_DENY},
		{"audit business update denied", appMCPCommandMetadataAudit, sqlite3.SQLITE_UPDATE, "tasks", "title", "main", sqlite3.SQLITE_DENY},
		{"metadata read operation store", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "_benmore_mcp_operations", "operation_id", "main", sqlite3.SQLITE_OK},
		{"metadata exact temp sqlite schema spelling", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "sqlite_schema", "name", "temp", sqlite3.SQLITE_OK},
		{"metadata exact temp sqlite master alias", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "sqlite_master", "name", "temp", sqlite3.SQLITE_OK},
		{"metadata temp-only schema alias denied for attached", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "sqlite_master", "name", "attached", sqlite3.SQLITE_DENY},
		{"metadata read business denied", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "tasks", "title", "main", sqlite3.SQLITE_DENY},
		{"metadata temp application denied", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "tasks", "title", "temp", sqlite3.SQLITE_DENY},
		{"metadata attached database denied", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "tasks", "title", "attached", sqlite3.SQLITE_DENY},
		{"metadata DDL denied", appMCPCommandMetadataPrepare, sqlite3.SQLITE_CREATE_TABLE, "unreviewed", "", "main", sqlite3.SQLITE_DENY},
		{"metadata transaction denied", appMCPCommandMetadataPrepare, sqlite3.SQLITE_TRANSACTION, "SAVEPOINT", "nested", "", sqlite3.SQLITE_DENY},
		{"metadata attach denied", appMCPCommandMetadataPrepare, sqlite3.SQLITE_ATTACH, ":memory:", "attached", "", sqlite3.SQLITE_DENY},
		{"metadata pragma escape denied", appMCPCommandMetadataPrepare, sqlite3.SQLITE_PRAGMA, "user_version", "", "", sqlite3.SQLITE_DENY},
		{"metadata query-only setter denied", appMCPCommandMetadataPrepare, sqlite3.SQLITE_PRAGMA, "query_only", "OFF", "", sqlite3.SQLITE_DENY},
		{"database list inspection", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "database_list", "", "", sqlite3.SQLITE_OK},
		{"operation table inspection", appMCPCommandMetadataPrepare, sqlite3.SQLITE_PRAGMA, "table_info", "_benmore_mcp_operations", "main", sqlite3.SQLITE_OK},
		{"operation index inspection", appMCPCommandMetadataPrepare, sqlite3.SQLITE_PRAGMA, "index_list", "_benmore_mcp_operations", "main", sqlite3.SQLITE_OK},
		{"only required primary index pragma", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "index_info", "sqlite_autoindex__benmore_mcp_operations_1", "main", sqlite3.SQLITE_OK},
		{"approval store read", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "_benmore_mcp_command_approvals", "state_ciphertext", "main", sqlite3.SQLITE_OK},
		{"approve inserts one approval", appMCPCommandMetadataApprove, sqlite3.SQLITE_INSERT, "_benmore_mcp_command_approvals", "", "main", sqlite3.SQLITE_OK},
		{"approve cannot update approval", appMCPCommandMetadataApprove, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_approvals", "state_ciphertext", "main", sqlite3.SQLITE_DENY},
		{"approve cannot delete approval", appMCPCommandMetadataApprove, sqlite3.SQLITE_DELETE, "_benmore_mcp_command_approvals", "", "main", sqlite3.SQLITE_DENY},
		{"consume updates only sealed state", appMCPCommandMetadataConsume, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_approvals", "state_ciphertext", "main", sqlite3.SQLITE_OK},
		{"consume cannot rewrite digest", appMCPCommandMetadataConsume, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_approvals", "approval_digest", "main", sqlite3.SQLITE_DENY},
		{"consume cannot insert approval", appMCPCommandMetadataConsume, sqlite3.SQLITE_INSERT, "_benmore_mcp_command_approvals", "", "main", sqlite3.SQLITE_DENY},
		{"prepare cannot insert approval", appMCPCommandMetadataPrepare, sqlite3.SQLITE_INSERT, "_benmore_mcp_command_approvals", "", "main", sqlite3.SQLITE_DENY},
		{"receipt cannot update approval", appMCPCommandMetadataReceipt, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_approvals", "state_ciphertext", "main", sqlite3.SQLITE_DENY},
		{"sweep deletes an operation", appMCPCommandMetadataSweep, sqlite3.SQLITE_DELETE, "_benmore_mcp_operations", "", "main", sqlite3.SQLITE_OK},
		{"sweep deletes an approval", appMCPCommandMetadataSweep, sqlite3.SQLITE_DELETE, "_benmore_mcp_command_approvals", "", "main", sqlite3.SQLITE_OK},
		{"sweep cannot delete business rows", appMCPCommandMetadataSweep, sqlite3.SQLITE_DELETE, "tasks", "", "main", sqlite3.SQLITE_DENY},
		{"sweep cannot delete audit rows", appMCPCommandMetadataSweep, sqlite3.SQLITE_DELETE, "_benmore_audit_log", "", "main", sqlite3.SQLITE_DENY},
		{"sweep cannot update operations", appMCPCommandMetadataSweep, sqlite3.SQLITE_UPDATE, "_benmore_mcp_operations", "receipt_digest", "main", sqlite3.SQLITE_DENY},
		{"sweep cannot insert", appMCPCommandMetadataSweep, sqlite3.SQLITE_INSERT, "_benmore_mcp_operations", "", "main", sqlite3.SQLITE_DENY},
		{"prepare cannot delete operations", appMCPCommandMetadataPrepare, sqlite3.SQLITE_DELETE, "_benmore_mcp_operations", "", "main", sqlite3.SQLITE_DENY},
		{"approve cannot delete operations", appMCPCommandMetadataApprove, sqlite3.SQLITE_DELETE, "_benmore_mcp_operations", "", "main", sqlite3.SQLITE_DENY},
		{"approval store inspection", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "table_info", "_benmore_mcp_command_approvals", "main", sqlite3.SQLITE_OK},
		{"encryption state marker inspection", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "table_info", "_benmore_encryption_state", "main", sqlite3.SQLITE_OK},
		{"encryption state index pragma denied", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "index_list", "_benmore_encryption_state", "main", sqlite3.SQLITE_DENY},
		{"other index pragma denied", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "index_info", "other_index", "main", sqlite3.SQLITE_DENY},
		{"attempt store read", appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "_benmore_mcp_command_attempts", "state_ciphertext", "main", sqlite3.SQLITE_OK},
		{"attempt claim inserts one attempt", appMCPCommandMetadataAttempt, sqlite3.SQLITE_INSERT, "_benmore_mcp_command_attempts", "", "main", sqlite3.SQLITE_OK},
		{"attempt claim supersedes through the sealed state only", appMCPCommandMetadataAttempt, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_attempts", "state_ciphertext", "main", sqlite3.SQLITE_OK},
		{"attempt claim cannot rewrite an attempt id", appMCPCommandMetadataAttempt, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_attempts", "attempt_id", "main", sqlite3.SQLITE_DENY},
		{"attempt claim cannot update an operation", appMCPCommandMetadataAttempt, sqlite3.SQLITE_UPDATE, "_benmore_mcp_operations", "receipt_ciphertext", "main", sqlite3.SQLITE_DENY},
		{"attempt claim cannot update an approval", appMCPCommandMetadataAttempt, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_approvals", "state_ciphertext", "main", sqlite3.SQLITE_DENY},
		{"attempt claim cannot delete an attempt", appMCPCommandMetadataAttempt, sqlite3.SQLITE_DELETE, "_benmore_mcp_command_attempts", "", "main", sqlite3.SQLITE_DENY},
		{"attempt claim cannot insert an approval", appMCPCommandMetadataAttempt, sqlite3.SQLITE_INSERT, "_benmore_mcp_command_approvals", "", "main", sqlite3.SQLITE_DENY},
		{"attempt claim cannot insert an operation", appMCPCommandMetadataAttempt, sqlite3.SQLITE_INSERT, "_benmore_mcp_operations", "", "main", sqlite3.SQLITE_DENY},
		{"attempt claim cannot write audit rows", appMCPCommandMetadataAttempt, sqlite3.SQLITE_INSERT, "_benmore_audit_log", "", "main", sqlite3.SQLITE_DENY},
		{"prepare cannot insert an attempt", appMCPCommandMetadataPrepare, sqlite3.SQLITE_INSERT, "_benmore_mcp_command_attempts", "", "main", sqlite3.SQLITE_DENY},
		{"approve cannot insert an attempt", appMCPCommandMetadataApprove, sqlite3.SQLITE_INSERT, "_benmore_mcp_command_attempts", "", "main", sqlite3.SQLITE_DENY},
		{"receipt cannot update an attempt", appMCPCommandMetadataReceipt, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_attempts", "state_ciphertext", "main", sqlite3.SQLITE_DENY},
		{"consume cannot update an attempt", appMCPCommandMetadataConsume, sqlite3.SQLITE_UPDATE, "_benmore_mcp_command_attempts", "state_ciphertext", "main", sqlite3.SQLITE_DENY},
		{"sweep deletes an attempt", appMCPCommandMetadataSweep, sqlite3.SQLITE_DELETE, "_benmore_mcp_command_attempts", "", "main", sqlite3.SQLITE_OK},
		{"sweep cannot insert an attempt", appMCPCommandMetadataSweep, sqlite3.SQLITE_INSERT, "_benmore_mcp_command_attempts", "", "main", sqlite3.SQLITE_DENY},
		{"prepare cannot delete an attempt", appMCPCommandMetadataPrepare, sqlite3.SQLITE_DELETE, "_benmore_mcp_command_attempts", "", "main", sqlite3.SQLITE_DENY},
		{"attempt index inspection", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "index_list", "_benmore_mcp_command_attempts", "main", sqlite3.SQLITE_OK},
		{"attempt table_info pragma denied", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "table_info", "_benmore_mcp_command_attempts", "main", sqlite3.SQLITE_DENY},
		{"attempt primary index pragma denied", appMCPCommandMetadataRead, sqlite3.SQLITE_PRAGMA, "index_info", "sqlite_autoindex__benmore_mcp_command_attempts_1", "main", sqlite3.SQLITE_DENY},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guard := &appMCPCommandExecution{}
			guard.publishNativeMetadataPolicy(false, tc.op, false)
			if got := guard.authorize(tc.action, tc.arg1, tc.arg2, tc.database); got != tc.want {
				t.Fatalf("authorize(%d,%q,%q,%q)=%d want %d", tc.action, tc.arg1, tc.arg2, tc.database, got, tc.want)
			}
		})
	}
}

func commandSQLiteConnID(conn *sql.Conn) (string, error) {
	var id string
	err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("native pool connection is not SQLite")
		}
		id = fmt.Sprintf("%p", sqliteConn)
		return nil
	})
	return id, err
}

func createCommandTempTasks(t *testing.T, app *App) string {
	t.Helper()
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	id, err := commandSQLiteConnID(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `CREATE TEMP TABLE tasks(id INTEGER PRIMARY KEY, status TEXT NOT NULL)`); err != nil {
		t.Fatalf("create same-name TEMP relation: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO temp.tasks(id,status) VALUES(99,'decoy')`); err != nil {
		t.Fatalf("insert distinguishable TEMP task: %v", err)
	}
	var tempCount, mainCount int
	if err := conn.QueryRowContext(context.Background(), `SELECT count(*) FROM temp.tasks`).Scan(&tempCount); err != nil || tempCount != 1 {
		t.Fatalf("verify TEMP relation: count=%d err=%v", tempCount, err)
	}
	if err := conn.QueryRowContext(context.Background(), `SELECT count(*) FROM main.tasks`).Scan(&mainCount); err != nil || mainCount != 1 {
		t.Fatalf("verify main relation remains distinct: count=%d err=%v", mainCount, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return id
}

func createCommandAttachedTasks(t *testing.T, app *App) string {
	t.Helper()
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	id, err := commandSQLiteConnID(conn)
	if err != nil {
		t.Fatal(err)
	}
	var originalLimit int
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("ATTACH fixture connection is not SQLite")
		}
		originalLimit = sqliteConn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, -1)
		return nil
	}); err != nil || originalLimit != 0 {
		t.Fatalf("ATTACH fixture did not start at driver limit zero: limit=%d err=%v", originalLimit, err)
	}
	if _, err := conn.ExecContext(context.Background(), `ATTACH DATABASE ':memory:' AS attached`); err == nil {
		t.Fatal("ordinary ATTACH unexpectedly succeeded at driver limit zero")
	}
	if commandDatabasePresent(t, conn, "attached") {
		t.Fatal("blocked ATTACH unexpectedly appeared in database_list")
	}
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("ATTACH fixture connection is not SQLite")
		}
		if previous := sqliteConn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, 1); previous != originalLimit {
			return fmt.Errorf("ATTACH limit changed before fixture setup: %d", previous)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	limitRaised := true
	defer func() {
		if limitRaised {
			_ = conn.Raw(func(raw any) error {
				sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
				if !ok {
					return errors.New("ATTACH fixture connection is not SQLite during limit restore")
				}
				sqliteConn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, originalLimit)
				return nil
			})
		}
	}()
	_, attachErr := conn.ExecContext(context.Background(), `ATTACH DATABASE ':memory:' AS attached`)
	restoreErr := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("ATTACH fixture connection is not SQLite during limit restore")
		}
		if previous := sqliteConn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, originalLimit); previous != 1 {
			return fmt.Errorf("ATTACH limit before restore=%d, want 1", previous)
		}
		return nil
	})
	if attachErr != nil {
		t.Fatalf("trusted fixture ATTACH failed: %v", attachErr)
	}
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}
	limitRaised = false
	if err := commandAssertAttachedLimit(t, conn, originalLimit); err != nil {
		t.Fatal(err)
	}
	if !commandDatabasePresent(t, conn, "attached") {
		t.Fatal("trusted attached database was not present after restoring the cap")
	}
	if _, err := conn.ExecContext(context.Background(), `CREATE TABLE attached.tasks(id INTEGER PRIMARY KEY, status TEXT NOT NULL)`); err != nil {
		t.Fatalf("create attached same-name relation: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO attached.tasks(id,status) VALUES(99,'decoy')`); err != nil {
		t.Fatalf("insert distinguishable attached task: %v", err)
	}
	var count int
	if err := conn.QueryRowContext(context.Background(), `SELECT count(*) FROM attached.tasks`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("verify attached task fixture: count=%d err=%v", count, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return id
}

func commandAssertAttachedLimit(t *testing.T, conn *sql.Conn, want int) error {
	t.Helper()
	var got int
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("ATTACH fixture connection is not SQLite")
		}
		got = sqliteConn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, -1)
		return nil
	}); err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("SQLite ATTACH limit=%d, want %d", got, want)
	}
	return nil
}

func commandDatabasePresent(t *testing.T, conn *sql.Conn, name string) bool {
	t.Helper()
	rows, err := conn.QueryContext(context.Background(), `PRAGMA database_list`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var dbName, file string
		if err := rows.Scan(&seq, &dbName, &file); err != nil {
			t.Fatal(err)
		}
		if dbName == name {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}

func commandRevisionSnapshot(t *testing.T, app *App) []string {
	t.Helper()
	rows, err := app.DB.Query(`SELECT table_name,incarnation,key_type,row_key,revision,deleted FROM main._benmore_mcp_row_revisions ORDER BY table_name,incarnation,key_type,row_key`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var snapshot []string
	for rows.Next() {
		var table, incarnation, keyType, rowKey string
		var revision int64
		var deleted int
		if err := rows.Scan(&table, &incarnation, &keyType, &rowKey, &revision, &deleted); err != nil {
			t.Fatal(err)
		}
		snapshot = append(snapshot, fmt.Sprintf("%s|%s|%s|%s|%d|%d", table, incarnation, keyType, rowKey, revision, deleted))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertCommandTaskLedgerUnchanged(t *testing.T, app *App, before []string) {
	t.Helper()
	var status string
	var activities int
	if err := app.DB.QueryRow(`SELECT status FROM main.tasks WHERE id=1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM main.activities WHERE task_id=1`).Scan(&activities); err != nil {
		t.Fatal(err)
	}
	if status != "open" || activities != 0 {
		t.Fatalf("dirty namespace refusal changed business state: status=%q activities=%d", status, activities)
	}
	if after := commandRevisionSnapshot(t, app); !slices.Equal(before, after) {
		t.Fatalf("dirty namespace refusal changed command revision ledger: before=%v after=%v", before, after)
	}
}

func TestAppMCPCommandCleanupRestoresNativeStorageCeiling(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	dbPath := filepath.Join(app.Dir, "data.db")
	setDBStorageLimit(dbPath, 1<<20)
	t.Cleanup(func() { dbStorageLimits.Delete(canonicalDBPath(dbPath)) })

	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var beforeID string
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("storage fixture connection is not SQLite")
		}
		beforeID = fmt.Sprintf("%p", sqliteConn)
		return applyDBStorageLimit(sqliteConn, canonicalDBPath(sqliteConn.GetFilename("main")))
	}); err != nil {
		conn.Close()
		t.Fatalf("install native SQLite storage ceiling: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), `PRAGMA max_page_count=1000000`); err == nil || !strings.Contains(strings.ToLower(err.Error()), "not authorized") {
		conn.Close()
		t.Fatalf("native storage authorizer did not deny the baseline ceiling increase: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatalf("prepare command with native storage ceiling: %v", err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err != nil {
		t.Fatalf("apply command with native storage ceiling: %v", err)
	}
	conn, err = app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("reused command connection is not SQLite")
		}
		if got := fmt.Sprintf("%p", sqliteConn); got != beforeID {
			return fmt.Errorf("successful command replaced the reusable physical connection: before=%s after=%s", beforeID, got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `PRAGMA max_page_count=1000000`); err == nil || !strings.Contains(strings.ToLower(err.Error()), "not authorized") {
		t.Fatalf("successful command cleanup did not restore the storage ceiling authorizer: %v", err)
	}
}

func TestAppMCPCommandConnectionGuardRestoresReusablePoolConnection(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatalf("prepare native command: %v", err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err != nil {
		t.Fatalf("apply native command: %v", err)
	}
	var queryOnly bool
	if err := app.DB.QueryRow(`PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly {
		t.Fatalf("reused pool connection retained command query_only state: query_only=%t err=%v", queryOnly, err)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM activities WHERE task_id=1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("reused pool connection did not serve a clean follow-up query: count=%d err=%v", count, err)
	}
}

func TestAppMCPCommandCleanupFailureDisposesAfterRollback(t *testing.T) {
	const childEnv = "BENMORE_MCP_COMMAND_CLEANUP_CHILD"
	if os.Getenv(childEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPCommandCleanupFailureDisposesAfterRollback$")
		env := make([]string, 0, len(os.Environ())+1)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, childEnv+"=") {
				env = append(env, value)
			}
		}
		cmd.Env = append(env, childEnv+"=1")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("connection cleanup exceeded the eight-second hang guard: %s", output)
		}
		if err != nil {
			t.Fatalf("native cleanup child failed: %v\n%s", err, output)
		}
		return
	}

	app, sessionID, _ := newCommandProviderTaskFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	generation := snapshotAppMCPGeneration(app)
	applyReached := false
	faultInstalled := false
	var poisonedConnID string
	const connectionProbe = "command_cleanup_connection_probe"
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		if _, _, err := cap.apply(prepared); err != nil {
			return false, err
		}
		applyReached = true
		return true, cap.conn.Raw(func(raw any) error {
			conn, ok := raw.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("command connection is not SQLite")
			}
			poisonedConnID = fmt.Sprintf("%p", conn)
			if err := conn.RegisterFunc(connectionProbe, func() int { return 731 }, true); err != nil {
				return err
			}
			guard := cap.guard
			conn.RegisterAuthorizer(func(action int, arg1, arg2, database string) int {
				if action == sqlite3.SQLITE_PRAGMA && strings.EqualFold(arg1, "query_only") {
					return sqlite3.SQLITE_DENY
				}
				return guard.authorize(action, arg1, arg2, database)
			})
			faultInstalled = true
			return nil
		})
	})
	if !applyReached || !faultInstalled || poisonedConnID == "" {
		t.Fatalf("query_only restoration fault was not reached after apply: apply=%t installed=%t conn=%q err=%v", applyReached, faultInstalled, poisonedConnID, err)
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "not authorized") {
		t.Fatalf("authorizer-denied query_only restoration did not fail closed: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
	cleanConn, connErr := app.DB.Conn(context.Background())
	if connErr != nil {
		t.Fatalf("acquire replacement pooled connection: %v", connErr)
	}
	defer cleanConn.Close()
	cleanConnID, connErr := commandSQLiteConnID(cleanConn)
	if connErr != nil || cleanConnID == poisonedConnID {
		t.Fatalf("poisoned connection was not discarded after rollback: old=%s replacement=%s err=%v", poisonedConnID, cleanConnID, connErr)
	}
	var probe int
	if err := cleanConn.QueryRowContext(context.Background(), `SELECT `+connectionProbe+`()`).Scan(&probe); err == nil {
		t.Fatalf("native connection-local function survived on the replacement connection: result=%d", probe)
	}
	var queryOnly bool
	if err := cleanConn.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly {
		t.Fatalf("disposed command connection did not leave a clean replacement: query_only=%t err=%v", queryOnly, err)
	}
}

func commandCancelAtSQLiteAction(t *testing.T, cap *appMCPCommandCapability, ctx context.Context, cancel context.CancelFunc, action int, table string) (func() bool, func()) {
	t.Helper()
	trigger := make(chan struct{}, 1)
	released := make(chan struct{})
	reached := false
	go func() {
		select {
		case <-trigger:
			cancel()
		case <-ctx.Done():
		}
		close(released)
	}()
	if err := cap.conn.Raw(func(raw any) error {
		conn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("command connection is not SQLite")
		}
		guard := cap.guard
		conn.RegisterAuthorizer(func(gotAction int, arg1, arg2, database string) int {
			if gotAction == action && sqliteIdentifierFold(arg1) == sqliteIdentifierFold(table) && !reached {
				reached = true
				trigger <- struct{}{}
				<-released
			}
			return guard.authorize(gotAction, arg1, arg2, database)
		})
		return nil
	}); err != nil {
		cancel()
		<-released
		t.Fatalf("install native cancellation authorizer: %v", err)
	}
	finish := func() {
		if !reached {
			cancel()
		}
		<-released
	}
	return func() bool { return reached }, finish
}

func TestAppMCPCommandCanceledReadAndApplyLeavePoolUsable(t *testing.T) {
	const childEnv = "BENMORE_MCP_COMMAND_CANCEL_PHASE"
	phase := os.Getenv(childEnv)
	if phase == "" {
		for _, childPhase := range []string{"read", "apply"} {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPCommandCanceledReadAndApplyLeavePoolUsable$")
			env := make([]string, 0, len(os.Environ())+1)
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, childEnv+"=") {
					env = append(env, value)
				}
			}
			cmd.Env = append(env, childEnv+"="+childPhase)
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				cancel()
				t.Fatalf("canceled %s cleanup exceeded the eight-second hang guard: %s", childPhase, output)
			}
			cancel()
			if err != nil {
				t.Fatalf("canceled %s child failed: %v\n%s", childPhase, err, output)
			}
		}
		return
	}
	if phase != "read" && phase != "apply" {
		t.Fatalf("unexpected cancellation child phase %q", phase)
	}
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	generation := snapshotAppMCPGeneration(app)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelReached := false
	var phaseErr error
	err := appMCPWithCommandCapability(ctx, appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item",
		origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		if phase == "read" {
			if err := cap.enterReadPhase("prepare", []string{"tasks"}); err != nil {
				return false, err
			}
			reached, finish := commandCancelAtSQLiteAction(t, cap, ctx, cancel, sqlite3.SQLITE_READ, "tasks")
			var count int
			phaseErr = cap.tx.QueryRowContext(cap.ctx, `SELECT count(*) FROM tasks`).Scan(&count)
			finish()
			cancelReached = reached()
			cap.leaveReadPhase()
		} else {
			reached, finish := commandCancelAtSQLiteAction(t, cap, ctx, cancel, sqlite3.SQLITE_UPDATE, "tasks")
			_, _, phaseErr = cap.apply(prepared)
			finish()
			cancelReached = reached()
		}
		if phaseErr == nil {
			return false, fmt.Errorf("canceled %s phase unexpectedly succeeded", phase)
		}
		return false, phaseErr
	})
	if !cancelReached {
		t.Fatalf("%s cancellation point was not reached: phase error=%v outer error=%v", phase, phaseErr, err)
	}
	if !errors.Is(phaseErr, context.Canceled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("%s failure did not preserve context cancellation: phase error=%v outer error=%v", phase, phaseErr, err)
	}
	assertCommandTaskUnchanged(t, app)
	var queryOnly bool
	if err := app.DB.QueryRow(`PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly {
		t.Fatalf("pool was not usable after canceled %s cleanup: query_only=%t err=%v", phase, queryOnly, err)
	}
}
