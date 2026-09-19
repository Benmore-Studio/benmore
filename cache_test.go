//go:build !cli

package main

import (
	"testing"
	"time"
)

func TestPerTableCacheInvalidation(t *testing.T) {
	// Seed two entries for different tables
	queryCacheSet("contacts_q1", []map[string]any{{"id": 1, "name": "Alice"}}, 5*time.Minute, "contacts")
	queryCacheSet("deals_q1", []map[string]any{{"id": 1, "title": "Big Deal"}}, 5*time.Minute, "deals")

	// Both should be cached
	if _, ok := queryCacheGet("contacts_q1"); !ok {
		t.Fatal("contacts cache entry should exist before invalidation")
	}
	if _, ok := queryCacheGet("deals_q1"); !ok {
		t.Fatal("deals cache entry should exist before invalidation")
	}

	// Invalidate only contacts
	InvalidateQueryCacheForTable("contacts")

	// Contacts cache should be gone
	if _, ok := queryCacheGet("contacts_q1"); ok {
		t.Fatal("contacts cache entry should be cleared after invalidation")
	}

	// Deals cache should still be warm
	if _, ok := queryCacheGet("deals_q1"); !ok {
		t.Fatal("deals cache entry should survive contacts invalidation")
	}

	// Clean up
	InvalidateQueryCacheForTable("deals")
}

func TestCacheInvalidationDoesNotAffectOtherTables(t *testing.T) {
	// Seed entries for 3 tables
	queryCacheSet("a_q1", []map[string]any{{"x": 1}}, 5*time.Minute, "table_a")
	queryCacheSet("b_q1", []map[string]any{{"x": 2}}, 5*time.Minute, "table_b")
	queryCacheSet("c_q1", []map[string]any{{"x": 3}}, 5*time.Minute, "table_c")

	// Invalidate table_b
	InvalidateQueryCacheForTable("table_b")

	if _, ok := queryCacheGet("a_q1"); !ok {
		t.Fatal("table_a cache should survive table_b invalidation")
	}
	if _, ok := queryCacheGet("b_q1"); ok {
		t.Fatal("table_b cache should be cleared")
	}
	if _, ok := queryCacheGet("c_q1"); !ok {
		t.Fatal("table_c cache should survive table_b invalidation")
	}

	// Clean up
	InvalidateQueryCacheForTable("table_a")
	InvalidateQueryCacheForTable("table_c")
}
