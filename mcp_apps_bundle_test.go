//go:build !cli

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

type mcpAppsVendor struct {
	Package   string            `json:"package"`
	Version   string            `json:"version"`
	Artifact  string            `json:"artifact"`
	Integrity string            `json:"registry_integrity"`
	Size      int               `json:"size_bytes"`
	SHA256    map[string]string `json:"sha256"`
	Dynamic   []struct {
		Pattern string `json:"pattern"`
		Count   int    `json:"count"`
		Why     string `json:"why"`
	} `json:"dynamic_code_allowlist"`
}

func loadMCPAppsVendor(t *testing.T) mcpAppsVendor {
	t.Helper()
	raw, err := mcpAppsFS.ReadFile("embedded/mcp-apps/VENDOR.json")
	if err != nil {
		t.Fatal(err)
	}
	var v mcpAppsVendor
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("VENDOR.json: %v", err)
	}
	return v
}

// Every embedded file (except VENDOR.json itself) must match its recorded
// sha256, and every recorded file must exist: tampering or a partial refresh
// fails CI.
func TestMCPAppsBundleVendorIntegrity(t *testing.T) {
	v := loadMCPAppsVendor(t)
	if v.Package != "@modelcontextprotocol/ext-apps" || v.Version != "2.0.3" || v.Artifact != mcpAppsBundleName {
		t.Fatalf("unexpected VENDOR.json identity: %+v", v)
	}
	if !strings.HasPrefix(v.Integrity, "sha512-") || len(v.SHA256) == 0 {
		t.Fatalf("VENDOR.json lacks registry integrity or file hashes")
	}
	entries, err := fs.ReadDir(mcpAppsFS, "embedded/mcp-apps")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		if e.Name() == "VENDOR.json" {
			continue
		}
		want, ok := v.SHA256[e.Name()]
		if !ok {
			t.Errorf("%s is embedded but not recorded in VENDOR.json", e.Name())
			continue
		}
		data, err := mcpAppsFS.ReadFile("embedded/mcp-apps/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s sha256 %s != VENDOR.json %s", e.Name(), got, want)
		}
		seen++
	}
	if seen != len(v.SHA256) {
		t.Errorf("VENDOR.json records %d files, %d embedded", len(v.SHA256), seen)
	}
	b, sum := mcpAppsBundle()
	if sum != v.SHA256[mcpAppsBundleName] || len(b) != v.Size {
		t.Errorf("accessor disagrees with VENDOR.json (sha %s, %d bytes)", sum, len(b))
	}
}

// The bundle must stay free of string-to-code evaluation, except the allowlisted
// zod capability probe whose count and justification VENDOR.json records.
func TestMCPAppsBundleNoDynamicCode(t *testing.T) {
	v := loadMCPAppsVendor(t)
	b, _ := mcpAppsBundle()
	allowed := map[string]int{}
	for _, a := range v.Dynamic {
		if strings.TrimSpace(a.Why) == "" {
			t.Errorf("allowlist entry %q has no justification", a.Pattern)
		}
		allowed[a.Pattern] = a.Count
	}
	for _, pat := range []string{"eval(", "new Function("} {
		if got := bytes.Count(b, []byte(pat)); got != allowed[pat] {
			t.Errorf("%q appears %d times, VENDOR.json allowlists %d", pat, got, allowed[pat])
		}
	}
	if len(v.Dynamic) != 1 || v.Dynamic[0].Pattern != "new Function(" {
		t.Errorf("unexpected dynamic_code_allowlist: %+v", v.Dynamic)
	}
}
