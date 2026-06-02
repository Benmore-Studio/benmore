package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadAccess_BothShapes verifies the parser accepts both the
// per-op map form AND the string-as-mode shorthand on the same call.
func TestLoadAccess_BothShapes(t *testing.T) {
	dir := t.TempDir()
	yaml := `
access:
  default:
    read: admin
    write: admin
  posts:
    read: public
    write: self
    update: self
    delete: admin
  messages: everyone
  settings: off
`
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadAccess(dir)
	if cfg == nil {
		t.Fatal("LoadAccess returned nil")
	}

	cases := []struct {
		table string
		op    AccessOp
		want  string
	}{
		// Per-op explicit
		{"posts", OpRead, "public"},
		{"posts", OpWrite, "self"},
		{"posts", OpDelete, "admin"},
		// Shorthand: everyone applies to every op
		{"messages", OpRead, "everyone"},
		{"messages", OpWrite, "everyone"},
		{"messages", OpDelete, "everyone"},
		// Shorthand: off applies to every op
		{"settings", OpRead, "off"},
		{"settings", OpUpdate, "off"},
		// Falls through to global default (no per-table entry):
		{"undeclared", OpRead, "admin"},
		{"undeclared", OpWrite, "admin"},
	}
	for _, c := range cases {
		got := cfg.ModeFor(c.table, c.op, false, false)
		if got != c.want {
			t.Errorf("ModeFor(%s, %s) = %q, want %q", c.table, c.op, got, c.want)
		}
	}
}

// TestAccess_PrivateDefaultForUnscoped pins the v2.7.12 default-private
// behavior. A table with NO user_id and NO group_key column, and NO
// `access:` config, gets implicit mode "admin" — non-admins can't list
// or read it. Pre-v2.7.12 it was world-readable to all authed users.
func TestAccess_PrivateDefaultForUnscoped(t *testing.T) {
	var cfg *AccessConfig // nil
	// No user_id, no group_key → admin everywhere
	if mode := cfg.ModeFor("system_logs", OpRead, false, false); mode != "admin" {
		t.Errorf("expected admin (private-by-default), got %q", mode)
	}
	// Table has user_id → still self (no change)
	if mode := cfg.ModeFor("posts", OpRead, true, false); mode != "self" {
		t.Errorf("expected self, got %q", mode)
	}
	// Table has group_key → still group (no change)
	if mode := cfg.ModeFor("orders", OpRead, false, true); mode != "group" {
		t.Errorf("expected group, got %q", mode)
	}
}

// TestAccess_Allowed pins the mode→session evaluation. Spans the
// common cases for every mode.
func TestAccess_Allowed(t *testing.T) {
	var cfg *AccessConfig
	anon := (*Session)(nil)
	user := &Session{UserID: 7, Role: "user"}
	admin := &Session{UserID: 1, Role: "admin"}
	grouped := &Session{UserID: 5, Role: "user", GroupID: "orgA"}

	cases := []struct {
		name         string
		mode         string
		sess         *Session
		targetUserID int64
		want         bool
	}{
		{"anon allows anon", "anon", anon, 0, true},
		{"anon allows user", "anon", user, 0, true},
		{"everyone blocks anon", "everyone", anon, 0, false},
		{"everyone allows user", "everyone", user, 0, true},
		{"admin blocks user", "admin", user, 0, false},
		{"admin allows admin", "admin", admin, 0, true},
		{"self allows owner-of-row", "self", user, 7, true},
		{"self denies non-owner", "self", user, 9, false},
		{"self admin sees others", "self", admin, 9, true},
		{"self list (target=0)", "self", user, 0, true},
		{"group needs HasGroup", "group", user, 0, false},
		{"group allows grouped", "group", grouped, 0, true},
		{"role:editor matches", "role:editor", &Session{Role: "editor"}, 0, true},
		{"role:editor mismatches", "role:editor", user, 0, false},
		{"role:editor admin bypass", "role:editor", admin, 0, true},
		{"off blocks admin", "off", admin, 0, false},
		{"unknown mode fails closed", "bananas", admin, 0, false},
	}
	for _, c := range cases {
		got := cfg.Allowed(c.mode, c.sess, c.targetUserID)
		if got != c.want {
			t.Errorf("%s: Allowed(%q) = %v, want %v", c.name, c.mode, got, c.want)
		}
	}
}
