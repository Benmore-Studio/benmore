//go:build !cli

package main

import "testing"

func TestParseCLIPortState(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef"
	cases := []struct {
		in          string
		port, state string
		ok          bool
	}{
		{"45123", "45123", "", true},
		{"45123~" + good, "45123", good, true},
		{"45123~short", "", "", false},
		{"45123~0123456789abcdef0123456789abcde&", "", "", false},
		{"45123~", "", "", false},
	}
	for _, c := range cases {
		port, state, ok := parseCLIPortState(c.in)
		if ok != c.ok || port != c.port || state != c.state {
			t.Errorf("%q => %q %q %v", c.in, port, state, ok)
		}
	}
}
