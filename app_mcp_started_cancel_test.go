//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func TestAppMCPReadFlowCancellationAfterSQLStarts(t *testing.T) {
	for _, transaction := range []bool{false, true} {
		t.Run(fmt.Sprintf("transaction=%t", transaction), func(t *testing.T) {
			app, uid, _, _ := appMCPReadFlowFixture(t, http.MethodGet, transaction)
			app.DB.SetMaxOpenConns(1)
			app.DB.SetMaxIdleConns(1)

			path := filepath.Join(app.Dir, "flows", "read_note.yaml")
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			oldQuery := "SELECT id, user_id AS actor_id, CAST(:_group_id AS TEXT) AS tenant_id, title FROM notes WHERE id = :id AND user_id = :user_id"
			query := `|
          WITH RECURSIVE x(n) AS (
            SELECT length('ready')
            UNION ALL SELECT n+1 FROM x WHERE n < 1000000000
          ) SELECT sum(n) AS id FROM x`
			updated := strings.Replace(string(source), oldQuery, query, 1)
			if updated == string(source) {
				t.Fatal("read flow fixture query was not found")
			}
			writeTestFile(t, app.Dir, "flows/read_note.yaml", updated)
			reviewAppMCPFixture(t, app.Dir)
			config, err := loadRuntimeConfig(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			app.MCP, app.Flows, app.sourceFiles = config.mcp, config.flows, config.sourceFiles
			tool := &app.MCP.Tools[0]
			pair := fixtureGrant(t, app, uid, time.Now())

			started := make(chan struct{}, 1)
			conn, err := app.DB.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.Raw(func(raw any) error {
				return raw.(*sqlite3.SQLiteConn).RegisterFunc("length", func(value string) int64 {
					select {
					case started <- struct{}{}:
					default:
					}
					return int64(len(value))
				}, false)
			}); err != nil {
				_ = conn.Close()
				t.Fatal(err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}

			type flowResult struct {
				result *appMCPReadResult
				err    error
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan flowResult, 1)
			go func() {
				got, err := runAppMCPReadFlow(ctx, app, pair.AccessToken, grantFixtureResource, tool, map[string]any{"id": json.Number("1")})
				result <- flowResult{got, err}
			}()

			select {
			case <-started:
				cancel()
			case <-time.After(time.Second):
				cancel()
				t.Fatal("read flow SQL did not reach the registered SQLite callback")
			}
			select {
			case got := <-result:
				if got.result != nil || got.err == nil {
					t.Fatalf("canceled started flow returned: result=%+v err=%v", got.result, got.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("read flow did not stop promptly after cancellation")
			}

			fresh, err := app.DB.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := fresh.Raw(func(raw any) error {
				if !raw.(*sqlite3.SQLiteConn).AutoCommit() {
					return fmt.Errorf("canceled read left a transaction open")
				}
				return nil
			}); err != nil {
				_ = fresh.Close()
				t.Fatal(err)
			}
			var queryOnly bool
			if err := fresh.QueryRowContext(context.Background(), "PRAGMA query_only").Scan(&queryOnly); err != nil {
				_ = fresh.Close()
				t.Fatal(err)
			}
			if err := fresh.Close(); err != nil {
				t.Fatal(err)
			}
			if queryOnly {
				t.Fatal("canceled read left query_only enabled")
			}
			if _, err := app.DB.Exec("INSERT INTO notes(user_id,title) VALUES (?, 'after-cancel')", uid); err != nil {
				t.Fatalf("canceled read left pooled connection unusable: %v", err)
			}
		})
	}
}

func TestAppMCPComputeCancellationAfterExecutionStarts(t *testing.T) {
	app, _, _ := appMCPGrantFixture(t)
	module := `export function cancel(args) { args.started(); while (true) {} }
export function normal() { return "ok"; }`
	writeTestFile(t, app.Dir, "static/app-mcp-cancel.ts", module)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP, app.sourceFiles = config.mcp, config.sourceFiles
	identity := &appMCPPrivateFlow{app: app, manifest: config.mcp}
	ctx := context.WithValue(context.Background(), appMCPPrivateFlowKey{}, identity)

	started := make(chan struct{}, 1)
	args := map[string]any{"started": func() {
		select {
		case started <- struct{}{}:
		default:
		}
	}}
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan struct {
		value any
		err   error
	}, 1)
	go func() {
		value, err := RunComputeContext(callCtx, app, "app-mcp-cancel", "cancel", args, time.Minute)
		result <- struct {
			value any
			err   error
		}{value, err}
	}()

	select {
	case <-started:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("compute function did not invoke its Go callback")
	}
	select {
	case got := <-result:
		if got.value != nil || got.err == nil {
			t.Fatalf("canceled started compute returned: value=%#v err=%v", got.value, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("compute did not stop promptly after cancellation")
	}
	if got, err := RunComputeContext(ctx, app, "app-mcp-cancel", "normal", nil, time.Second); err != nil || got != "ok" {
		t.Fatalf("normal compute after cancellation: value=%#v err=%v", got, err)
	}
}
