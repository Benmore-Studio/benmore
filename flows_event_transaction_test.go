//go:build !cli

package main

import (
	"context"
	"testing"
	"time"
)

func TestRunFlowEventTransactionRollsBackOnPanic(t *testing.T) {
	app := newWALJobsTestApp(t)
	app.DB.SetMaxOpenConns(1)
	if _, err := app.DB.Exec("CREATE TABLE event_rows (name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create table: %v", err)
	}

	ctx := &FlowContext{App: app}
	func() {
		defer func() { _ = recover() }()
		runFlowEventTransaction(ctx, Flow{Name: "panic_event", Transaction: true}, func(ctx *FlowContext) {
			if _, err := ctx.Tx.Exec("INSERT INTO event_rows (name) VALUES ('before panic')"); err != nil {
				t.Fatalf("insert in event transaction: %v", err)
			}
			panic("simulated event step panic")
		})
	}()

	queryCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := app.DB.ExecContext(queryCtx, "INSERT INTO event_rows (name) VALUES ('after panic')"); err != nil {
		t.Fatalf("single-connection pool remained occupied after panic: %v", err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM event_rows WHERE name = 'before panic'").Scan(&count); err != nil {
		t.Fatalf("count panic-path rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("panic-path insert committed %d rows; want rollback", count)
	}
}
