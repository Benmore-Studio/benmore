//go:build !cli

package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

// A record wider than the cell limit is refused before encoding/csv
// materializes its fields: a line of commas used to allocate about 40 bytes
// per field (gigabytes at the 25 MiB file limit) before the per-cell check ran.
func TestIngestCSVWideRecordRefusedBeforeAllocation(t *testing.T) {
	data := bytes.Repeat([]byte{','}, 4<<20)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res, err := IngestCSV(bytes.NewReader(data), DefaultIngestLimits())
	runtime.ReadMemStats(&after)
	var le *IngestLimitError
	if !errors.As(err, &le) || le.Limit != "MaxCells" || res.Complete || len(res.Blocks) != 0 {
		t.Fatalf("wide record: err=%v complete=%v blocks=%d", err, res.Complete, len(res.Blocks))
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Fatalf("refusing a %d MiB record allocated %d MiB", len(data)>>20, grew>>20)
	}
}

func TestIngestCSVWidestRecordMatchesReader(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"", 0},
		{"\n\r\n\n", 0},
		{"a", 1},
		{"a,b,c\nd\n", 3},
		{"a,\n", 2},
		{",,,", 4},
		{"\"x,y\",z\r\n", 2},
		{"\"multi\nline,with,commas\",b\n", 2},
		{"\"say \"\"hi\"\"\",b,c\n", 3},
		{"a\rb,c\r", 2},
		{"\r\r\n", 1},
		{"a,b\"c,d,e\n", 1}, // bare quote: the reader fails in field two
		{"\"a\"x,b,c\n", 0}, // text after a closing quote
		{"x,y,\"open\n", 2}, // unterminated quote
		{"a\n\"q\"\r\n,,\n", 3},
	} {
		if got := ingestCSVWidestRecord([]byte(tc.in), 1<<30); got != tc.want {
			t.Errorf("widest(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
	if got := ingestCSVWidestRecord([]byte("a,b,c,d,e\n"), 2); got != 3 {
		t.Errorf("early stop = %d, want 3", got)
	}
}

// FuzzIngestCSVWidestRecord checks the counter against encoding/csv itself:
// for input the reader accepts, the widest record must match exactly, so the
// pre-check can never refuse a file the reader would have read in full.
func FuzzIngestCSVWidestRecord(f *testing.F) {
	for _, s := range []string{"a,b\n1,2\n", "\"q\"\"x\",\r\n", "a,\"unterminated\n", "\"m\nl\",x\n", ",,\r\n\r\n,", "a\rb\r", "\"a\"\r\n\"b\"", "x,\"\"\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := csv.NewReader(bytes.NewReader(data))
		r.FieldsPerRecord = -1
		widest := 0
		for {
			rec, err := r.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				if got := ingestCSVWidestRecord(data, 1<<30); got < widest {
					t.Fatalf("counter %d below the reader's widest good record %d for %q", got, widest, data)
				}
				return
			}
			widest = max(widest, len(rec))
		}
		if got := ingestCSVWidestRecord(data, 1<<30); got != widest {
			t.Fatalf("counter %d, reader %d for %q", got, widest, strings.ReplaceAll(string(data), "\n", `\n`))
		}
	})
}
