//go:build !cli

package main

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestAssertContiguousWALSegments(t *testing.T) {
	mk := func(seq int) string {
		return fmt.Sprintf("app/litestream/20260623T120000Z/wal/%016d-0000000000001000-20260623T120010Z.wal.gz", seq)
	}
	if err := assertContiguousWALSegments([]string{mk(1), mk(2), mk(3)}); err != nil {
		t.Fatalf("contiguous 1..3 should pass: %v", err)
	}
	if err := assertContiguousWALSegments(nil); err != nil {
		t.Fatalf("empty (base-only restore) should pass: %v", err)
	}
	if err := assertContiguousWALSegments([]string{mk(1), mk(3)}); err == nil {
		t.Fatal("a gap (missing seq 2) must be rejected, not silently truncate the restore")
	}
	if err := assertContiguousWALSegments([]string{mk(2), mk(3)}); err == nil {
		t.Fatal("a stream not starting at seq 1 must be rejected")
	}
	if err := assertContiguousWALSegments([]string{"app/litestream/g/wal/bogus.wal.gz"}); err == nil {
		t.Fatal("an unparseable segment key must be rejected")
	}
}

func TestChooseWALPITRPlan(t *testing.T) {
	asOf := time.Date(2026, 6, 23, 12, 0, 30, 0, time.UTC)
	objs := []S3Object{
		{Key: "app/litestream/20260623T110000Z/snapshot.db.gz"},
		{Key: "app/litestream/20260623T115900Z/snapshot.db.gz"},
		{Key: "app/litestream/20260623T115900Z/wal/0000000000000001-0000000000001000-20260623T120000Z.wal.gz"},
		{Key: "app/litestream/20260623T115900Z/wal/0000000000000002-0000000000002000-20260623T120020Z.wal.gz"},
		{Key: "app/litestream/20260623T115900Z/wal/0000000000000003-0000000000003000-20260623T120100Z.wal.gz"},
		{Key: "other/litestream/20260623T115900Z/snapshot.db.gz"},
	}
	plan, ok := chooseWALPITRPlan(objs, "app", asOf)
	if !ok {
		t.Fatal("expected PITR plan")
	}
	if plan.SnapshotKey != "app/litestream/20260623T115900Z/snapshot.db.gz" {
		t.Fatalf("snapshot = %s", plan.SnapshotKey)
	}
	wantSegments := []string{
		"app/litestream/20260623T115900Z/wal/0000000000000001-0000000000001000-20260623T120000Z.wal.gz",
		"app/litestream/20260623T115900Z/wal/0000000000000002-0000000000002000-20260623T120020Z.wal.gz",
	}
	if !reflect.DeepEqual(plan.SegmentKeys, wantSegments) {
		t.Fatalf("segments = %#v, want %#v", plan.SegmentKeys, wantSegments)
	}
}

func TestWALCheckpointModeWaitsForShipping(t *testing.T) {
	t.Setenv("BENMORE_WAL_SHIP", "1")
	// walShippingEnabledForApp now also requires a configured object store, so
	// the PASSIVE/TRUNCATE coordination only engages when shipping can actually
	// happen (a half-configured deployment keeps truncating instead of bloating).
	t.Setenv("BACKUP_S3_BUCKET", "test-bucket")
	app := &App{Dir: "/apps/example"}
	app.walShippedOffset.Store(1024)
	if got := walCheckpointMode(app, 2048); got != "PASSIVE" {
		t.Fatalf("walCheckpointMode behind = %s, want PASSIVE", got)
	}
	app.walShippedOffset.Store(2048)
	if got := walCheckpointMode(app, 2048); got != "TRUNCATE" {
		t.Fatalf("walCheckpointMode caught up = %s, want TRUNCATE", got)
	}
}
