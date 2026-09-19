package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTestFile is shared by feature-pack and CLI feature tests across
// editions - keep it untagged so every test build links it.
func writeTestFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func stringSliceContains(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}
