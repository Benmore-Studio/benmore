package main

import (
	"os"
	"strings"
	"testing"
)

func TestEmbeddedBMSDKStoreAndQuerySurface(t *testing.T) {
	src, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	mustContain := []string{
		"export function createStore",
		"export const query =",
		"subscribe(selector, listener",
		"async fetch(key, fetcher",
		"async read(spec",
		"async mutate(opts",
		"query.invalidateTable(table,",
		"createStore, query, html, raw",
	}
	for _, s := range mustContain {
		if !strings.Contains(js, s) {
			t.Fatalf("embedded/bm.js missing %q", s)
		}
	}
}
