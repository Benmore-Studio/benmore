//go:build !cli

package main

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type walPITRPlan struct {
	Generation  string
	SnapshotKey string
	SegmentKeys []string
}

func chooseWALPITRPlan(objs []S3Object, sub string, asOf time.Time) (walPITRPlan, bool) {
	type snapshot struct {
		gen string
		key string
		ts  time.Time
	}
	var snapshots []snapshot
	for _, obj := range objs {
		gen, ts, ok := parseWALSnapshotKey(obj.Key, sub)
		if !ok || ts.After(asOf) {
			continue
		}
		snapshots = append(snapshots, snapshot{gen: gen, key: obj.Key, ts: ts})
	}
	if len(snapshots) == 0 {
		return walPITRPlan{}, false
	}
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].ts.After(snapshots[j].ts) })
	pick := snapshots[0]
	plan := walPITRPlan{Generation: pick.gen, SnapshotKey: pick.key}
	for _, obj := range objs {
		gen, ts, ok := parseWALSegmentKey(obj.Key, sub)
		if !ok || gen != pick.gen || ts.After(asOf) {
			continue
		}
		plan.SegmentKeys = append(plan.SegmentKeys, obj.Key)
	}
	sort.Strings(plan.SegmentKeys)
	return plan, true
}

// walSegmentSeq extracts the monotonic sequence number from a shipped WAL
// segment key (".../wal/<seq>-<size>-<stamp>.wal.gz").
func walSegmentSeq(key string) (int64, bool) {
	name := strings.TrimSuffix(path.Base(key), ".wal.gz")
	fields := strings.Split(name, "-")
	if len(fields) < 3 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// assertContiguousWALSegments verifies that sorted segment keys form an
// unbroken 1..N sequence. A gap means a segment failed to upload or was GC'd
// while still referenced; replaying a truncated stream would silently restore a
// DB missing its tail, so we hard-fail rather than produce a quietly-wrong DB.
func assertContiguousWALSegments(keys []string) error {
	for i, key := range keys {
		seq, ok := walSegmentSeq(key)
		if !ok {
			return fmt.Errorf("unparseable WAL segment key %q", key)
		}
		if seq != int64(i+1) {
			return fmt.Errorf("WAL segment gap: expected seq %d, found %d (%s)", i+1, seq, key)
		}
	}
	return nil
}

func parseWALSnapshotKey(key, sub string) (gen string, ts time.Time, ok bool) {
	prefix := sub + "/litestream/"
	if !strings.HasPrefix(key, prefix) || path.Base(key) != "snapshot.db.gz" {
		return "", time.Time{}, false
	}
	rest := strings.TrimPrefix(key, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", time.Time{}, false
	}
	t, err := time.ParseInLocation("20060102T150405Z", parts[0], time.UTC)
	return parts[0], t, err == nil
}

func parseWALSegmentKey(key, sub string) (gen string, ts time.Time, ok bool) {
	prefix := sub + "/litestream/"
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, ".wal.gz") {
		return "", time.Time{}, false
	}
	rest := strings.TrimPrefix(key, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[1] != "wal" {
		return "", time.Time{}, false
	}
	name := strings.TrimSuffix(parts[2], ".wal.gz")
	fields := strings.Split(name, "-")
	if len(fields) < 3 {
		return "", time.Time{}, false
	}
	t, err := time.ParseInLocation("20060102T150405Z", fields[len(fields)-1], time.UTC)
	return parts[0], t, err == nil
}
