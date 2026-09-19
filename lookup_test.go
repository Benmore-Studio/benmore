//go:build !cli

package main

import (
	"testing"
)

func TestLookupValueEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		data map[string]any
		key  string
		want any
	}{
		{
			name: "flat key only (no nested map)",
			data: map[string]any{"staff_avg.rating": 3.5},
			key:  "staff_avg.rating",
			want: 3.5,
		},
		{
			name: "nested map only",
			data: map[string]any{"staff_avg": map[string]any{"rating": 3.5}},
			key:  "staff_avg.rating",
			want: 3.5,
		},
		{
			name: "both flat and nested (flat wins)",
			data: map[string]any{
				"staff_avg.rating": "flat",
				"staff_avg":        map[string]any{"rating": "nested"},
			},
			key:  "staff_avg.rating",
			want: "flat",
		},
		{
			name: "simple key",
			data: map[string]any{"count": 42},
			key:  "count",
			want: 42,
		},
		{
			name: "missing key",
			data: map[string]any{"other": 1},
			key:  "count",
			want: "",
		},
		{
			name: "nil value returns empty string",
			data: map[string]any{"val": nil},
			key:  "val",
			want: "",
		},
		{
			name: "zero int",
			data: map[string]any{"val": 0},
			key:  "val",
			want: 0,
		},
		{
			name: "zero float",
			data: map[string]any{"val": 0.0},
			key:  "val",
			want: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lookupValue(tt.data, tt.key)
			if got != tt.want {
				t.Errorf("lookupValue(%v, %q) = %v (%T), want %v (%T)", tt.data, tt.key, got, got, tt.want, tt.want)
			}
		})
	}
}
