//go:build !cli

package main

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

type activeRetentionStore struct {
	objects []S3Object
	deleted []string
	listErr error
}

func (s *activeRetentionStore) List(string) ([]S3Object, error) { return s.objects, s.listErr }
func (s *activeRetentionStore) Delete(key string) error {
	s.deleted = append(s.deleted, key)
	return nil
}

func TestBackupRetentionDistinguishesActiveAndRemovedApps(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	objects := []S3Object{
		{Key: "active/2026-08-01-12.db.gz"},
		{Key: "active/2026-07-01-12.db.gz"},
		{Key: "predeploy/pre-deploy-20260801-120000.db.gz"},
		{Key: "removed/2026-08-01-12.db.gz"},
		{Key: "removed/2026-10-20-11.db.gz"},
		{Key: "future/2099-01-01-00.db.gz"},
		{Key: "unrelated/2026-08-01-12"},
	}
	active := map[string]bool{"active": true, "predeploy": true}
	want := []string{"active/2026-07-01-12.db.gz", "removed/2026-08-01-12.db.gz"}
	if got := retentionKeysToDeleteForApps(objects, now, active); !reflect.DeepEqual(got, want) {
		t.Fatalf("deleted=%v want=%v", got, want)
	}
}

func TestBackupRetentionKeepsLastCandidateUntilReplacementExists(t *testing.T) {
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	old := S3Object{Key: "active/2026-09-01-12.db.gz"}
	active := map[string]bool{"active": true}
	for day := 0; day <= 40; day++ {
		// No new object models either an unchanged-data skip or an upload that
		// never completed. Retention must not infer a replacement from elapsed time.
		if got := retentionKeysToDeleteForApps([]S3Object{old}, start.AddDate(0, 0, day), active); len(got) != 0 {
			t.Fatalf("day %d deleted last candidate: %v", day, got)
		}
	}
	replacement := S3Object{Key: "active/2026-10-11-12.db.gz"}
	if got := retentionKeysToDeleteForApps([]S3Object{old, replacement}, start.AddDate(0, 0, 40), active); !reflect.DeepEqual(got, []string{old.Key}) {
		t.Fatalf("replacement did not permit old expiry: %v", got)
	}
}

func TestBackupRetentionUnknownInventoryNeverDeletes(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		for _, unavailable := range []bool{false, true} {
			store := &activeRetentionStore{objects: []S3Object{{Key: "removed/2000-01-01-00.db.gz"}}}
			calls := 0
			failure := errors.New("synthetic inventory read failure")
			inventory := func() (map[string]bool, error) {
				calls++
				if calls == failAt {
					if unavailable {
						return nil, nil
					}
					return nil, failure
				}
				return map[string]bool{"active": true}, nil
			}
			if _, err := runRetentionSweep(store, inventory); err == nil {
				t.Fatal("unknown inventory reported successful retention")
			} else if !unavailable && !errors.Is(err, failure) {
				t.Fatalf("inventory error lost cause: %v", err)
			}
			if len(store.deleted) != 0 {
				t.Fatalf("unknown inventory deleted %v", store.deleted)
			}
		}
	}
}

func TestBackupRetentionRechecksInventoryAndDryRun(t *testing.T) {
	for _, dry := range []string{"0", "1"} {
		t.Run("dry="+dry, func(t *testing.T) {
			t.Setenv("BENMORE_RETENTION_DRYRUN", dry)
			store := &activeRetentionStore{objects: []S3Object{
				{Key: "existing/2000-01-01-00.db.gz"},
				{Key: "newly-listed/2000-01-01-00.db.gz"},
				{Key: "removed/2000-01-01-00.db.gz"},
			}}
			calls := 0
			inventory := func() (map[string]bool, error) {
				calls++
				if calls == 1 {
					return map[string]bool{"existing": true}, nil
				}
				// Keep both sides of an inventory change across object listing.
				return map[string]bool{"newly-listed": true}, nil
			}
			n, err := runRetentionSweep(store, inventory)
			if err != nil || n != 1 || calls != 2 {
				t.Fatalf("planned=%d reads=%d err=%v", n, calls, err)
			}
			if dry == "1" && len(store.deleted) != 0 {
				t.Fatalf("dry run deleted %v", store.deleted)
			}
			if dry == "0" && !reflect.DeepEqual(store.deleted, []string{"removed/2000-01-01-00.db.gz"}) {
				t.Fatalf("deleted=%v", store.deleted)
			}
		})
	}
}

func TestBackupRetentionListingFailureNeverDeletes(t *testing.T) {
	failure := errors.New("synthetic incomplete listing")
	store := &activeRetentionStore{objects: []S3Object{{Key: "removed/2000-01-01-00.db.gz"}}, listErr: failure}
	_, err := runRetentionSweep(store, func() (map[string]bool, error) { return map[string]bool{}, nil })
	if !errors.Is(err, failure) || len(store.deleted) != 0 {
		t.Fatalf("partial listing: err=%v deleted=%v", err, store.deleted)
	}
}
