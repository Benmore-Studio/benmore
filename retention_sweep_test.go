//go:build !cli

package main

import (
	"reflect"
	"testing"
	"time"
)

func TestRetentionKeysToDeleteKeepsExpectedWindows(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	objs := []S3Object{
		{Key: "app/2026-06-23-12.db.gz"},                  // hourly
		{Key: "app/2026-06-23-11.db.gz"},                  // hourly
		{Key: "app/2026-06-21-08.db.gz"},                  // daily winner
		{Key: "app/2026-06-21-01.db.gz"},                  // daily duplicate
		{Key: "app/2026-06-14-08.db.gz"},                  // weekly winner
		{Key: "app/2026-06-14-01.db.gz"},                  // weekly duplicate
		{Key: "app/2026-05-01-00.db.gz"},                  // too old
		{Key: "app/pre-deploy-20260620-120000.db.gz"},     // pre-deploy < 7d
		{Key: "app/pre-deploy-20260610-120000.db.gz"},     // pre-deploy > 7d
		{Key: "app/litestream/20260623T120000Z/wal/x.gz"}, // unrelated PITR object
	}
	got := retentionKeysToDelete(objs, now)
	want := []string{
		"app/2026-05-01-00.db.gz",
		"app/2026-06-14-01.db.gz",
		"app/2026-06-21-01.db.gz",
		"app/pre-deploy-20260610-120000.db.gz",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("retentionKeysToDelete = %#v, want %#v", got, want)
	}
}

func TestLitestreamKeysToDeleteGCsOldGenerationsAtomically(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	objs := []S3Object{
		// app: newest generation (1h old) - kept entirely.
		{Key: "app/litestream/20260623T110000Z/snapshot.db.gz"},
		{Key: "app/litestream/20260623T110000Z/wal/0000000000000001-0000000000001000-20260623T110010Z.wal.gz"},
		// app: old generation (~22d old, past the 7d window) - deleted snapshot + all segments together.
		{Key: "app/litestream/20260601T100000Z/snapshot.db.gz"},
		{Key: "app/litestream/20260601T100000Z/wal/0000000000000001-0000000000001000-20260601T100010Z.wal.gz"},
		{Key: "app/litestream/20260601T100000Z/wal/0000000000000002-0000000000002000-20260601T100020Z.wal.gz"},
		// lonely: a single very-old generation is still the newest for its app - never deleted.
		{Key: "lonely/litestream/20260101T100000Z/snapshot.db.gz"},
	}
	got := litestreamKeysToDelete(objs, now)
	want := []string{
		"app/litestream/20260601T100000Z/snapshot.db.gz",
		"app/litestream/20260601T100000Z/wal/0000000000000001-0000000000001000-20260601T100010Z.wal.gz",
		"app/litestream/20260601T100000Z/wal/0000000000000002-0000000000002000-20260601T100020Z.wal.gz",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("litestreamKeysToDelete = %#v, want %#v", got, want)
	}
}
