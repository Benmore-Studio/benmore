//go:build !cli

package main

import "testing"

func TestHasScope_EmptyScopes_ReturnsTrue(t *testing.T) {
	s := &Session{Scopes: ""}
	if !hasScope(s, "contacts", "read") {
		t.Error("empty scopes should allow everything")
	}
}

func TestHasScope_WildcardScopes_ReturnsTrue(t *testing.T) {
	s := &Session{Scopes: "*"}
	if !hasScope(s, "contacts", "delete") {
		t.Error("wildcard scopes should allow everything")
	}
}

func TestHasScope_ExactMatchRead(t *testing.T) {
	s := &Session{Scopes: "contacts:read"}
	if !hasScope(s, "contacts", "read") {
		t.Error("contacts:read should allow reading contacts")
	}
}

func TestHasScope_ExactMatchWrite(t *testing.T) {
	s := &Session{Scopes: "contacts:write"}
	if !hasScope(s, "contacts", "write") {
		t.Error("contacts:write should allow writing contacts")
	}
}

func TestHasScope_ExactMatchDelete(t *testing.T) {
	s := &Session{Scopes: "contacts:delete"}
	if !hasScope(s, "contacts", "delete") {
		t.Error("contacts:delete should allow deleting contacts")
	}
}

func TestHasScope_WildcardAction(t *testing.T) {
	s := &Session{Scopes: "contacts:*"}
	for _, action := range []string{"read", "write", "delete"} {
		if !hasScope(s, "contacts", action) {
			t.Errorf("contacts:* should allow %s", action)
		}
	}
}

func TestHasScope_WildcardResource(t *testing.T) {
	s := &Session{Scopes: "*:read"}
	if !hasScope(s, "contacts", "read") {
		t.Error("*:read should allow reading any table")
	}
	if !hasScope(s, "deals", "read") {
		t.Error("*:read should allow reading any table")
	}
}

func TestHasScope_WriteImpliesRead(t *testing.T) {
	s := &Session{Scopes: "contacts:write"}
	if !hasScope(s, "contacts", "read") {
		t.Error("write should imply read")
	}
}

func TestHasScope_WriteDoesNotImplyDelete(t *testing.T) {
	s := &Session{Scopes: "contacts:write"}
	if hasScope(s, "contacts", "delete") {
		t.Error("write should NOT imply delete")
	}
}

func TestHasScope_DeleteDoesNotImplyRead(t *testing.T) {
	s := &Session{Scopes: "contacts:delete"}
	if hasScope(s, "contacts", "read") {
		t.Error("delete should NOT imply read")
	}
}

func TestHasScope_DeleteDoesNotImplyWrite(t *testing.T) {
	s := &Session{Scopes: "contacts:delete"}
	if hasScope(s, "contacts", "write") {
		t.Error("delete should NOT imply write")
	}
}

func TestHasScope_NoMatchReturnsFalse(t *testing.T) {
	s := &Session{Scopes: "contacts:read"}
	if hasScope(s, "deals", "read") {
		t.Error("contacts:read should NOT allow reading deals")
	}
	if hasScope(s, "contacts", "write") {
		t.Error("contacts:read should NOT allow writing contacts")
	}
}

func TestHasScope_MultipleScopes(t *testing.T) {
	s := &Session{Scopes: "contacts:read deals:write tasks:delete"}
	if !hasScope(s, "contacts", "read") {
		t.Error("should allow contacts:read")
	}
	if !hasScope(s, "deals", "write") {
		t.Error("should allow deals:write")
	}
	if !hasScope(s, "deals", "read") {
		t.Error("deals:write should imply deals:read")
	}
	if !hasScope(s, "tasks", "delete") {
		t.Error("should allow tasks:delete")
	}
	if hasScope(s, "tasks", "write") {
		t.Error("tasks:delete should NOT allow tasks:write")
	}
	if hasScope(s, "users", "read") {
		t.Error("should NOT allow reading unlisted tables")
	}
}

func TestHasScope_MalformedScopeSkipped(t *testing.T) {
	s := &Session{Scopes: "bad contacts:read also_bad:"}
	if !hasScope(s, "contacts", "read") {
		t.Error("should still allow contacts:read despite malformed scopes")
	}
	if hasScope(s, "bad", "read") {
		t.Error("malformed scope 'bad' should not grant access")
	}
}

func TestHasScope_NilSession(t *testing.T) {
	if hasScope(nil, "contacts", "read") {
		t.Error("nil session should deny")
	}
}

func TestValidateScopes_Valid(t *testing.T) {
	valid := []string{
		"",
		"*",
		"contacts:read",
		"contacts:write",
		"contacts:delete",
		"contacts:*",
		"contacts:read deals:write",
		"contacts:read deals:write tasks:* users:delete",
	}
	for _, s := range valid {
		if err := validateScopes(s); err != nil {
			t.Errorf("validateScopes(%q) should be valid, got: %s", s, err)
		}
	}
}

func TestValidateScopes_AcceptsCustomActions(t *testing.T) {
	// Custom verbs (anything not in the read/write/delete/* set) are
	// app-defined and used by the developer's own flow handlers. The
	// validator must accept them as long as they're well-formed
	// identifiers — pre-2.7.31 we hardcoded an allowlist that rejected
	// patterns like `reports:review` and `orders:approve` even though the
	// docs showed exactly those shapes.
	valid := []string{
		"contacts:execute",
		"accounts:review",
		"orders:approve",
		"posts:publish posts:archive",
		"items:custom_verb",
	}
	for _, s := range valid {
		if err := validateScopes(s); err != nil {
			t.Errorf("validateScopes(%q) should be valid, got: %s", s, err)
		}
	}
}

func TestValidateScopes_RejectsMalformedActions(t *testing.T) {
	// We still reject junk that isn't a well-formed identifier — the
	// rules match the framework's table/column naming shape.
	invalid := []string{
		"posts:do-stuff",     // hyphen
		"orders:approve all", // would split as two scopes; "all" lacks ':'
		"posts: ",            // empty action
		"posts:!",            // punctuation
	}
	for _, s := range invalid {
		if err := validateScopes(s); err == nil {
			t.Errorf("validateScopes(%q) should be invalid", s)
		}
	}
}

func TestValidateScopes_MalformedFormat(t *testing.T) {
	err := validateScopes("contacts")
	if err == nil {
		t.Error("'contacts' without action should be invalid")
	}
}

func TestValidateScopes_EmptyParts(t *testing.T) {
	err := validateScopes(":read")
	if err == nil {
		t.Error("':read' with empty resource should be invalid")
	}
}

func TestParseScope_Valid(t *testing.T) {
	r, a := parseScope("contacts:read")
	if r != "contacts" || a != "read" {
		t.Errorf("expected contacts/read, got %s/%s", r, a)
	}
}

func TestParseScope_Wildcard(t *testing.T) {
	r, a := parseScope("*:*")
	if r != "*" || a != "*" {
		t.Errorf("expected */*,  got %s/%s", r, a)
	}
}

func TestParseScope_Invalid(t *testing.T) {
	r, a := parseScope("nocolon")
	if r != "" || a != "" {
		t.Errorf("expected empty, got %s/%s", r, a)
	}
}

func TestCheckScope_Denied(t *testing.T) {
	s := &Session{Scopes: "contacts:read"}
	err := checkScope(s, "contacts", "write")
	if err == nil {
		t.Error("should deny write when only read is scoped")
	}
	if err.Error() != "scope denied: token does not have contacts:write permission" {
		t.Errorf("unexpected error message: %s", err)
	}
}

func TestCheckScope_Allowed(t *testing.T) {
	s := &Session{Scopes: "contacts:write"}
	err := checkScope(s, "contacts", "write")
	if err != nil {
		t.Errorf("should allow, got: %s", err)
	}
}
