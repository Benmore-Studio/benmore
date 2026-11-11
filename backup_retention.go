//go:build !cli

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type backupObjectStore interface {
	List(prefix string) ([]S3Object, error)
	Delete(path string) error
}

// backupAppInventory returns a fresh authoritative production-app inventory.
// nil is unavailable, never an assertion that all apps have been removed.
type backupAppInventory func() (map[string]bool, error)

// backupPrefixStore lists the bucket's top-level prefixes and streams a
// prefix page by page; *S3Storage does. With it the sweep lists and prunes
// one instance prefix at a time, so a prefix that cannot be listed (one that
// grew past the complete-listing budget) blocks only itself. Without it (test
// stores) the sweep lists the whole bucket at once.
type backupPrefixStore interface {
	ListPrefixes(prefix string) ([]string, error)
	ListPages(prefix string, fn func([]S3Object) error) error
}

func runRetentionSweep(store backupObjectStore, inventory backupAppInventory) (int, error) {
	if inventory == nil {
		return 0, errors.New("backup retention requires an app inventory")
	}
	before, err := inventory()
	if err != nil {
		return 0, fmt.Errorf("backup retention inventory: %w", err)
	}
	if before == nil {
		return 0, errors.New("backup retention app inventory unavailable")
	}
	ps, perPrefix := store.(backupPrefixStore)
	if !perPrefix {
		objs, err := store.List("")
		if err != nil {
			return 0, err
		}
		active, err := retentionActiveApps(before, inventory)
		if err != nil {
			return 0, err
		}
		keys, junk := retentionPlan(objs, time.Now().UTC(), active)
		n, err := retentionApply(store, keys)
		m, jerr := retentionApply(store, junk)
		return n + m, errors.Join(err, jerr)
	}
	prefixes, err := ps.ListPrefixes("")
	if err != nil {
		return 0, fmt.Errorf("backup retention prefixes: %w", err)
	}
	sort.Strings(prefixes)
	total := 0
	var errs []error
	for _, prefix := range prefixes {
		objs, err := store.List(prefix)
		if errors.Is(err, errS3ListBudget) {
			// Too many objects to list whole: never decide generations from
			// a partial view, but clear what cannot belong to any (keys that
			// do not parse, older than the PITR window), page by page.
			n, cerr := retentionSweepJunk(store, ps, prefix, time.Now().UTC())
			total += n
			errs = append(errs, fmt.Errorf("%s: too many objects to list whole (%d unparseable old object(s) deleted; the rest needs an operator): %w", strings.TrimSuffix(prefix, "/"), n, errors.Join(err, cerr)))
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", strings.TrimSuffix(prefix, "/"), err))
			continue
		}
		active, err := retentionActiveApps(before, inventory)
		if err != nil {
			// The inventory is global: stop rather than guess for the rest.
			return total, errors.Join(append(errs, err)...)
		}
		keys, junk := retentionPlan(objs, time.Now().UTC(), active)
		// Snapshots and generations first, the junk in its own call: a
		// refused or failed junk delete never holds up the real pruning.
		n, err := retentionApply(store, keys)
		total += n
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", strings.TrimSuffix(prefix, "/"), err))
		}
		n, err = retentionApply(store, junk)
		total += n
		if err != nil {
			errs = append(errs, fmt.Errorf("%s litestream/ cleanup: %w", strings.TrimSuffix(prefix, "/"), err))
		}
	}
	return total, errors.Join(errs...)
}

// retentionActiveApps re-reads the inventory after a listing and keeps apps
// present at either boundary rather than treating a route change during
// enumeration as proof of retirement.
func retentionActiveApps(before map[string]bool, inventory backupAppInventory) (map[string]bool, error) {
	after, err := inventory()
	if err != nil {
		return nil, fmt.Errorf("backup retention inventory recheck: %w", err)
	}
	if after == nil {
		return nil, errors.New("backup retention app inventory unavailable after listing")
	}
	active := make(map[string]bool, len(before)+len(after))
	for _, snapshot := range []map[string]bool{before, after} {
		for sub, present := range snapshot {
			if present {
				active[sub] = true
			}
		}
	}
	return active, nil
}

// retentionPlan is what a sweep deletes from a complete listing: snapshots
// and PITR generations (keys), and unusable litestream/ objects (junk), which
// go in a separate call.
func retentionPlan(objs []S3Object, now time.Time, active map[string]bool) (keys, junk []string) {
	keys = retentionKeysToDeleteForApps(objs, now, active)
	// PITR (litestream) objects live under <sub>/litestream/ and are GC'd
	// separately, by generation - parseBackupSnapshotKey deliberately ignores
	// them (they have 4-5 path segments, not 2). Without this they accumulate
	// forever (~8.6k WAL segments/app/day).
	keys = append(keys, litestreamKeysToDelete(objs, now)...)
	return keys, litestreamJunkKeys(objs, now)
}

// retentionKeyRefused reports a key the delete path would refuse (the
// hosted router: one a tenant's backup-prune helper does not take). Such
// keys are never sent, so they cannot fail a call that carries others, and a
// dry run reports them exactly as the real run does.
var retentionKeyRefused = func(string) bool { return false }

// retentionApply deletes keys (or, in a dry run, logs what the real run
// would do), skipping and reporting refused ones.
func retentionApply(store backupObjectStore, keys []string) (int, error) {
	var send, refused []string
	for _, key := range keys {
		if retentionKeyRefused(key) {
			refused = append(refused, key)
		} else {
			send = append(send, key)
		}
	}
	var refusal error
	if len(refused) > 0 {
		refusal = fmt.Errorf("%d key(s) the prune helper refuses were not deleted (first: %s)", len(refused), refused[0])
	}
	if os.Getenv("BENMORE_RETENTION_DRYRUN") == "1" {
		for _, key := range send {
			log.Printf("backup: retention dry-run would delete %s", key)
		}
		for _, key := range refused {
			log.Printf("backup: retention dry-run would NOT delete %s (refused by the prune helper)", key)
		}
		return len(send), refusal
	}
	if len(send) == 0 {
		return 0, refusal
	}
	n, err := retentionDeleteKeys(store, send)
	return n, errors.Join(err, refusal)
}

// litestreamJunkKeys are objects under <instance>/litestream/ that no PITR
// plan can use (parseLitestreamKey refuses their key) and that are older than
// the PITR window. A WAL session can create any key under that prefix, so
// these are what a misbehaving app leaves; nothing else would remove them.
func litestreamJunkKeys(objs []S3Object, now time.Time) []string {
	window := pitrRetentionWindow()
	var del []string
	for _, obj := range objs {
		parts := strings.SplitN(obj.Key, "/", 3)
		if len(parts) < 3 || parts[1] != "litestream" {
			continue
		}
		if _, _, _, ok := parseLitestreamKey(obj.Key); ok {
			continue
		}
		t, err := time.Parse(time.RFC3339, obj.LastModified)
		if err != nil || now.Sub(t) <= window {
			continue // an unreadable time is kept
		}
		del = append(del, obj.Key)
	}
	sort.Strings(del)
	return del
}

// retentionSweepJunk deletes a prefix's litestreamJunkKeys page by page, for
// a prefix too large to list whole.
func retentionSweepJunk(store backupObjectStore, ps backupPrefixStore, prefix string, now time.Time) (int, error) {
	total := 0
	var applyErrs []error
	err := ps.ListPages(prefix+"litestream/", func(page []S3Object) error {
		n, err := retentionApply(store, litestreamJunkKeys(page, now))
		total += n
		if err != nil {
			// Keep going: a refused or failed page does not stop the rest.
			applyErrs = append(applyErrs, err)
		}
		return nil
	})
	if len(applyErrs) > 3 {
		applyErrs = append(applyErrs[:3], fmt.Errorf("and %d more", len(applyErrs)-3))
	}
	return total, errors.Join(append([]error{err}, applyErrs...)...)
}

// retentionDeleteKeys deletes the sweep's keys and returns how many it
// deleted. The hosted router replaces it: a tenant app's keys are deleted
// with a session scoped to that app's prefix (backup_session_router.go).
var retentionDeleteKeys = func(store backupObjectStore, keys []string) (int, error) {
	for i, key := range keys {
		if err := store.Delete(key); err != nil {
			return i, fmt.Errorf("delete %s: %w", key, err)
		}
	}
	return len(keys), nil
}

func retentionKeysToDeleteForApps(objs []S3Object, now time.Time, active map[string]bool) []string {
	if active == nil {
		return nil // unknown inventory is never permission to delete
	}
	type snap struct {
		key       string
		sub       string
		t         time.Time
		preDeploy bool
	}
	var snaps []snap
	for _, obj := range objs {
		sub, ts, preDeploy, ok := parseBackupSnapshotKey(obj.Key)
		if !ok {
			continue
		}
		snaps = append(snaps, snap{key: obj.Key, sub: sub, t: ts, preDeploy: preDeploy})
	}

	keep := map[string]bool{}
	newest := map[string]snap{}
	daily := map[string]snap{}
	weekly := map[string]snap{}
	for _, s := range snaps {
		if previous, ok := newest[s.sub]; !ok || s.t.After(previous.t) {
			newest[s.sub] = s
		}
		age := now.Sub(s.t)
		if age < 0 {
			keep[s.key] = true
			continue
		}
		if s.preDeploy {
			if age <= 7*24*time.Hour {
				keep[s.key] = true
			}
			continue
		}
		switch {
		case age <= 24*time.Hour:
			keep[s.key] = true
		case age <= 7*24*time.Hour:
			bucket := s.sub + ":" + s.t.Format("2006-01-02")
			if prev, ok := daily[bucket]; !ok || s.t.After(prev.t) {
				daily[bucket] = s
			}
		case age <= 30*24*time.Hour:
			year, week := s.t.ISOWeek()
			bucket := fmt.Sprintf("%s:%04d-W%02d", s.sub, year, week)
			if prev, ok := weekly[bucket]; !ok || s.t.After(prev.t) {
				weekly[bucket] = s
			}
		}
	}
	// Preserve an active app's newest candidate, including a predeploy-only
	// history. Its filename does not certify restorability. Removed apps keep
	// the documented age windows rather than an indefinite newest-object hold.
	for _, s := range newest {
		if active[s.sub] {
			keep[s.key] = true
		}
	}
	for _, s := range daily {
		keep[s.key] = true
	}
	for _, s := range weekly {
		keep[s.key] = true
	}

	var del []string
	for _, s := range snaps {
		if !keep[s.key] {
			del = append(del, s.key)
		}
	}
	sort.Strings(del)
	return del
}

// litestreamKeysToDelete returns PITR object keys to delete. PITR objects (a
// per-app full-DB snapshot + its WAL segments) are GC'd by GENERATION, never
// individually: a generation's snapshot and ALL its WAL segments are kept or
// deleted together. This guarantees a base snapshot is never removed while WAL
// segments that depend on it remain (which would orphan an unrestorable chain -
// C4). The newest generation per app is always kept (C4); older generations are
// dropped once they age past the PITR retention window (C3).
func litestreamKeysToDelete(objs []S3Object, now time.Time) []string {
	type generation struct {
		ts   time.Time // recency = max stamp across the generation's objects
		keys []string
	}
	gens := map[string]*generation{} // "sub\x00gen" -> objects
	bySub := map[string][]string{}   // sub -> generation ids
	for _, obj := range objs {
		sub, gen, ts, ok := parseLitestreamKey(obj.Key)
		if !ok {
			continue
		}
		id := sub + "\x00" + gen
		g, exists := gens[id]
		if !exists {
			g = &generation{ts: ts}
			gens[id] = g
			bySub[sub] = append(bySub[sub], id)
		}
		g.keys = append(g.keys, obj.Key)
		if ts.After(g.ts) {
			g.ts = ts
		}
	}
	// Newest generation per sub is never deleted.
	newest := map[string]string{}
	for sub, ids := range bySub {
		best := ""
		for _, id := range ids {
			if best == "" || gens[id].ts.After(gens[best].ts) {
				best = id
			}
		}
		newest[sub] = best
	}
	window := pitrRetentionWindow()
	var del []string
	for id, g := range gens {
		sub := id[:strings.IndexByte(id, '\x00')]
		if newest[sub] == id {
			continue
		}
		if now.Sub(g.ts) <= window {
			continue
		}
		del = append(del, g.keys...)
	}
	sort.Strings(del)
	return del
}

// pitrRetentionWindow is how long to retain non-newest PITR generations.
func pitrRetentionWindow() time.Duration {
	if raw := os.Getenv("BENMORE_PITR_RETENTION_HOURS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return time.Duration(n) * time.Hour
		}
	}
	return 7 * 24 * time.Hour
}

// parseLitestreamKey classifies a PITR object key and returns its app sub,
// generation id, and a recency timestamp (the generation stamp for a snapshot,
// the segment stamp for a WAL segment). Non-PITR or malformed keys yield ok=false.
func parseLitestreamKey(key string) (sub, gen string, ts time.Time, ok bool) {
	parts := strings.Split(key, "/")
	if len(parts) < 4 || parts[1] != "litestream" {
		return "", "", time.Time{}, false
	}
	sub, gen = parts[0], parts[2]
	if len(parts) == 4 && parts[3] == "snapshot.db.gz" {
		t, err := time.ParseInLocation("20060102T150405Z", gen, time.UTC)
		if err != nil {
			return "", "", time.Time{}, false
		}
		return sub, gen, t, true
	}
	if len(parts) == 5 && parts[3] == "wal" && strings.HasSuffix(parts[4], ".wal.gz") {
		fields := strings.Split(strings.TrimSuffix(parts[4], ".wal.gz"), "-")
		if len(fields) < 3 {
			return "", "", time.Time{}, false
		}
		t, err := time.ParseInLocation("20060102T150405Z", fields[len(fields)-1], time.UTC)
		if err != nil {
			return "", "", time.Time{}, false
		}
		return sub, gen, t, true
	}
	return "", "", time.Time{}, false
}

func parseBackupSnapshotKey(key string) (sub string, ts time.Time, preDeploy bool, ok bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 2 || parts[0] == "" || !strings.HasSuffix(parts[1], ".db.gz") {
		return "", time.Time{}, false, false
	}
	name := strings.TrimSuffix(parts[1], ".db.gz")
	if strings.HasPrefix(name, "pre-deploy-") {
		t, err := time.ParseInLocation("20060102-150405", strings.TrimPrefix(name, "pre-deploy-"), time.UTC)
		return parts[0], t, true, err == nil
	}
	t, err := time.ParseInLocation("2006-01-02-15", name, time.UTC)
	return parts[0], t, false, err == nil
}
