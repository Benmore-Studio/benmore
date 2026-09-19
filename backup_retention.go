//go:build !cli

package main

import (
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

func runRetentionSweep(store backupObjectStore) (int, error) {
	objs, err := store.List("")
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	keys := retentionKeysToDelete(objs, now)
	// PITR (litestream) objects live under <sub>/litestream/ and are GC'd
	// separately, by generation - parseBackupSnapshotKey deliberately ignores
	// them (they have 4-5 path segments, not 2). Without this they accumulate
	// forever (~8.6k WAL segments/app/day).
	keys = append(keys, litestreamKeysToDelete(objs, now)...)
	dryRun := os.Getenv("BENMORE_RETENTION_DRYRUN") == "1"
	for _, key := range keys {
		if dryRun {
			log.Printf("backup: retention dry-run would delete %s", key)
			continue
		}
		if err := store.Delete(key); err != nil {
			return 0, fmt.Errorf("delete %s: %w", key, err)
		}
	}
	return len(keys), nil
}

func retentionKeysToDelete(objs []S3Object, now time.Time) []string {
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
	daily := map[string]snap{}
	weekly := map[string]snap{}
	for _, s := range snaps {
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
	if len(parts) != 2 {
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
