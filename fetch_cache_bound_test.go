//go:build !cli

package main

import (
	"fmt"
	"testing"
	"time"
)

func resetFetchCacheForTest(t *testing.T) {
	t.Helper()
	reset := func() {
		fetchCache.Lock()
		fetchCache.entries = map[string]*cacheEntry{}
		fetchCache.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// A fetch URL that embeds request input gives every visitor value its own
// cache entry of up to 1 MiB, and nothing ever removed an expired one.
func TestFetchCacheIsBoundedByCountAndBytes(t *testing.T) {
	resetFetchCacheForTest(t)
	const body = 200 << 10
	for i := 0; i < 5000; i++ {
		fetchCacheStore(fmt.Sprint("k", i), map[string]any{"i": i}, body, time.Hour)
	}
	fetchCache.RLock()
	n, total := len(fetchCache.entries), 0
	for _, e := range fetchCache.entries {
		total += e.size
	}
	_, newest := fetchCache.entries["k4999"]
	fetchCache.RUnlock()
	t.Logf("entries=%d retained=%dMB", n, total>>20)
	if n > fetchCacheMaxEntries || total > fetchCacheMaxBytes {
		t.Fatalf("fetch cache holds %d entries / %d bytes; caps %d / %d", n, total, fetchCacheMaxEntries, fetchCacheMaxBytes)
	}
	if !newest {
		t.Error("newest entry evicted")
	}
}

func TestFetchCacheDropsExpiredEntriesOnStore(t *testing.T) {
	resetFetchCacheForTest(t)
	for i := 0; i < 50; i++ {
		fetchCacheStore(fmt.Sprint("old", i), "x", 10, time.Nanosecond)
	}
	time.Sleep(5 * time.Millisecond)
	fetchCacheStore("fresh", "x", 10, time.Hour)
	fetchCache.RLock()
	n := len(fetchCache.entries)
	fetchCache.RUnlock()
	if n != 1 {
		t.Errorf("expired entries kept: %d", n)
	}
}
