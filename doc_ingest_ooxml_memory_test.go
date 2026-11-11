//go:build !cli

package main

import (
	"bytes"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ooxmlDistinctName(i int) string {
	const first = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const rest = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := []byte{first[i%52]}
	i /= 52
	for k := 0; k < 3; k++ {
		b = append(b, rest[i%62])
		i /= 62
	}
	return string(b)
}

// Every element kept a map of its children's names, so a small part with
// millions of distinct names under one parent (each name carrying a 512-byte
// namespace) held them all: a 1.4 MB DOCX grew memory by 732 MiB in the
// round-2 review (2026-10-23), past a hosted app's 768 MB limit. Only table,
// row and cell positions are read, so only those are counted now.
func TestOOXMLDistinctChildNamesUseBoundedMemory(t *testing.T) {
	const names = 300_000 // about 220 MiB of retained keys before the fix
	ns := "urn:" + strings.Repeat("n", 508)
	var body strings.Builder
	body.WriteString(`<x:root xmlns:x="` + ns + `">`)
	for i := 0; i < names; i++ {
		body.WriteString("<x:" + ooxmlDistinctName(i) + "/>")
	}
	body.WriteString(`</x:root><p><r><t>kept</t></r></p>`)
	doc := testDOCX(t, body.String(), "", "")

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peak.Load() {
				peak.Store(ms.HeapInuse)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	result, err := IngestDOCX(bytes.NewReader(doc), int64(len(doc)), IngestLimits{})
	close(stop)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	grew := int64(peak.Load()) - int64(base.HeapInuse)
	if grew > 64<<20 {
		t.Fatalf("heap grew %d MiB parsing %d distinct child names", grew>>20, names)
	}
	var found bool
	for _, b := range result.Blocks {
		if strings.Contains(b.Value, "kept") {
			found = true
		}
	}
	if !found {
		t.Fatalf("document text lost: %+v", result.Blocks)
	}
}
