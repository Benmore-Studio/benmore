//go:build !cli

package main

import "testing"

func TestCDNKeyUnsafe(t *testing.T) {
	for _, k := range []string{"a/../b", "%2e%2e/x", "a\\b", "a//b", "..", "x%2Fy"} {
		if !cdnKeyUnsafe(k) {
			t.Errorf("%q must be rejected", k)
		}
	}
	for _, k := range []string{"uploads/files/abc.pdf", "images/logo.png", "a.b.c/d-e_f"} {
		if cdnKeyUnsafe(k) {
			t.Errorf("%q must be allowed", k)
		}
	}
}
