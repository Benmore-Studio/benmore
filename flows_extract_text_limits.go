//go:build !cli

package main

// Cost limits for `run: extract_text`.
//
// An extraction holds the app's job worker (and the app's one extraction
// slot) for up to 10 minutes, so one user who queues large OCR jobs over and
// over could keep every other job of the app waiting. Two limits bound that:
//
//   - a result cache keyed by the file's SHA-256 and the OCR switch: the same
//     bytes always give the same text, so a repeat costs one storage read and
//     no extraction. The step has already authorized the reference (record
//     ownership, the caller's read of the row) before it reads the bytes, and
//     a hit needs those exact bytes, so the cache reveals nothing the caller
//     could not extract. Bounded by total text and age, per process.
//   - a per-user extraction-time budget: a signed-in user's extractions may
//     take extractTextUserBudget of extractor time per window; past that the
//     step fails `limit_exceeded` before it waits for the slot. One run that
//     starts within the budget may finish past it, so a user holds the worker
//     at most budget + one run (10 min) per window. Runs without a signed-in
//     user (schedules, data events, jobs with no actor) read references the
//     author chose and are not counted.

import (
	"strconv"
	"sync"
	"time"
)

const (
	extractTextUserBudget   = 15 * time.Minute
	extractTextBudgetWindow = time.Hour
	extractTextCacheTTL     = time.Hour
	extractTextCacheBytes   = 32 << 20
)

// extractTextResult is the cacheable part of a step's output (everything but
// the reference the step was given).
type extractTextResult struct {
	sha256, parserVersion string
	complete, truncated   bool
	quality               []string
	pages                 []string
}

func (r extractTextResult) size() int {
	n := len(r.sha256) + len(r.parserVersion)
	for _, q := range r.quality {
		n += len(q)
	}
	for _, p := range r.pages {
		n += len(p) + 16
	}
	return n
}

type extractTextCacheEntry struct {
	result extractTextResult
	stored time.Time
}

var extractTextCache = struct {
	sync.Mutex
	entries map[string]extractTextCacheEntry
	order   []string // insertion order, oldest first
	bytes   int
}{entries: map[string]extractTextCacheEntry{}}

func extractTextCacheKey(appDir, sha string, ocr bool) string {
	return appDir + "\x00" + sha + "\x00" + strconv.FormatBool(ocr)
}

func extractTextCacheGet(key string, now time.Time) (extractTextResult, bool) {
	extractTextCache.Lock()
	defer extractTextCache.Unlock()
	e, ok := extractTextCache.entries[key]
	if !ok || now.Sub(e.stored) > extractTextCacheTTL {
		return extractTextResult{}, false
	}
	return e.result, true
}

func extractTextCachePut(key string, r extractTextResult, now time.Time) {
	size := r.size()
	if size > extractTextCacheBytes {
		return
	}
	c := &extractTextCache
	c.Lock()
	defer c.Unlock()
	if old, ok := c.entries[key]; ok {
		c.bytes -= old.result.size()
		delete(c.entries, key)
		for i, k := range c.order {
			if k == key {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
	}
	// Evict expired entries and then the oldest until the new one fits.
	for len(c.order) > 0 {
		oldest := c.order[0]
		e, ok := c.entries[oldest]
		if ok && now.Sub(e.stored) <= extractTextCacheTTL && c.bytes+size <= extractTextCacheBytes {
			break
		}
		if ok {
			c.bytes -= e.result.size()
			delete(c.entries, oldest)
		}
		c.order = c.order[1:]
	}
	c.entries[key] = extractTextCacheEntry{result: r, stored: now}
	c.order = append(c.order, key)
	c.bytes += size
}

type extractTextUsage struct {
	windowStart time.Time
	used        time.Duration
}

var extractTextBudgets = struct {
	sync.Mutex
	users map[string]*extractTextUsage
}{users: map[string]*extractTextUsage{}}

func extractTextBudgetKey(appDir string, userID int64) string {
	return appDir + "\x00" + strconv.FormatInt(userID, 10)
}

// extractTextBudgetAllows reports whether the user still has extraction time
// in the current window.
func extractTextBudgetAllows(key string, now time.Time) bool {
	extractTextBudgets.Lock()
	defer extractTextBudgets.Unlock()
	u, ok := extractTextBudgets.users[key]
	if !ok || now.Sub(u.windowStart) >= extractTextBudgetWindow {
		return true
	}
	return u.used < extractTextUserBudget
}

// extractTextBudgetSpend charges d of extractor time, started at start.
func extractTextBudgetSpend(key string, start time.Time, d time.Duration) {
	b := &extractTextBudgets
	b.Lock()
	defer b.Unlock()
	if len(b.users) > 4096 {
		for k, u := range b.users {
			if start.Sub(u.windowStart) >= extractTextBudgetWindow {
				delete(b.users, k)
			}
		}
	}
	u, ok := b.users[key]
	if !ok || start.Sub(u.windowStart) >= extractTextBudgetWindow {
		u = &extractTextUsage{windowStart: start}
		b.users[key] = u
	}
	u.used += d
}
