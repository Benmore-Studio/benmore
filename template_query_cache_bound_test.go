//go:build !cli

package main

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func resetQueryCacheForTest(t *testing.T) {
	t.Helper()
	queryCache.mu.Lock()
	queryCache.entries = map[string]*queryCacheEntry{}
	queryCache.mu.Unlock()
	t.Cleanup(func() {
		queryCache.mu.Lock()
		queryCache.entries = map[string]*queryCacheEntry{}
		queryCache.mu.Unlock()
	})
}

func queryCacheLen() int {
	queryCache.mu.RLock()
	defer queryCache.mu.RUnlock()
	return len(queryCache.entries)
}

// `<query cache="5m" sql="... WHERE title = {{query.q}}">` binds request input
// into the cache key, so each distinct visitor value adds an entry. Expired
// entries were never removed, so the map only ever grew.
func TestQueryCacheIsBoundedUnderDistinctKeys(t *testing.T) {
	resetQueryCacheForTest(t)
	row := []map[string]any{{"body": string(make([]byte, 1024))}}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < 50000; i++ {
		queryCacheSet(queryCacheKey("/apps/a", "SELECT * FROM t WHERE q = ?", []any{fmt.Sprint(i)}), row, time.Minute, "t")
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("entries=%d heap growth=%dMB", queryCacheLen(), (int64(after.HeapAlloc)-int64(before.HeapAlloc))>>20)
	if n := queryCacheLen(); n > queryCacheMaxEntries {
		t.Fatalf("query cache grew to %d entries; cap is %d", n, queryCacheMaxEntries)
	}
	// The newest entry is still served.
	last := queryCacheKey("/apps/a", "SELECT * FROM t WHERE q = ?", []any{fmt.Sprint(49999)})
	if _, ok := queryCacheGet(last); !ok {
		t.Error("most recent entry was evicted")
	}
}

func TestQueryCachePurgesExpiredEntriesOnInsert(t *testing.T) {
	resetQueryCacheForTest(t)
	for i := 0; i < 100; i++ {
		queryCacheSet(fmt.Sprint("old", i), nil, time.Nanosecond, "t")
	}
	time.Sleep(5 * time.Millisecond)
	for i := 0; i < queryCacheMaxEntries; i++ {
		queryCacheSet(fmt.Sprint("new", i), nil, time.Minute, "t")
	}
	queryCache.mu.RLock()
	_, oldLeft := queryCache.entries["old0"]
	queryCache.mu.RUnlock()
	if oldLeft {
		t.Error("expired entry survived a full-cache insert")
	}
}

func TestQueryCacheSkipsHugeResultSets(t *testing.T) {
	resetQueryCacheForTest(t)
	rows := make([]map[string]any, queryCacheMaxRows+1)
	queryCacheSet("big", rows, time.Minute, "t")
	if _, ok := queryCacheGet("big"); ok {
		t.Error("oversized result set was cached")
	}
}
