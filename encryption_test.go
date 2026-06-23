//go:build !cli

package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEncryptedFieldYAMLSimpleFormat(t *testing.T) {
	yamlStr := `
encrypted:
  contacts: [notes, ssn]
`
	var raw EncryptedYAML
	if err := yaml.Unmarshal([]byte(yamlStr), &raw); err != nil {
		t.Fatalf("parse error: %s", err)
	}

	if len(raw.Encrypted["contacts"]) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(raw.Encrypted["contacts"]))
	}
	if raw.Encrypted["contacts"][0].Column != "notes" {
		t.Errorf("expected 'notes', got '%s'", raw.Encrypted["contacts"][0].Column)
	}
	if raw.Encrypted["contacts"][1].Column != "ssn" {
		t.Errorf("expected 'ssn', got '%s'", raw.Encrypted["contacts"][1].Column)
	}
	if len(raw.Encrypted["contacts"][0].Roles) != 0 {
		t.Errorf("simple format should have no roles, got %v", raw.Encrypted["contacts"][0].Roles)
	}
}

func TestEncryptedFieldYAMLDetailedFormat(t *testing.T) {
	yamlStr := `
encrypted:
  contacts:
    - column: ssn
      roles: [admin, manager]
    - column: notes
`
	var raw EncryptedYAML
	if err := yaml.Unmarshal([]byte(yamlStr), &raw); err != nil {
		t.Fatalf("parse error: %s", err)
	}

	if len(raw.Encrypted["contacts"]) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(raw.Encrypted["contacts"]))
	}
	if raw.Encrypted["contacts"][0].Column != "ssn" {
		t.Errorf("expected 'ssn', got '%s'", raw.Encrypted["contacts"][0].Column)
	}
	if len(raw.Encrypted["contacts"][0].Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(raw.Encrypted["contacts"][0].Roles))
	}
	if raw.Encrypted["contacts"][0].Roles[0] != "admin" {
		t.Errorf("expected 'admin', got '%s'", raw.Encrypted["contacts"][0].Roles[0])
	}
	// Second field has no roles
	if raw.Encrypted["contacts"][1].Column != "notes" {
		t.Errorf("expected 'notes', got '%s'", raw.Encrypted["contacts"][1].Column)
	}
	if len(raw.Encrypted["contacts"][1].Roles) != 0 {
		t.Errorf("notes should have no roles, got %v", raw.Encrypted["contacts"][1].Roles)
	}
}

func TestEncryptedFieldYAMLMixedFormat(t *testing.T) {
	yamlStr := `
encrypted:
  contacts:
    - notes
    - column: ssn
      roles: [admin]
`
	var raw EncryptedYAML
	if err := yaml.Unmarshal([]byte(yamlStr), &raw); err != nil {
		t.Fatalf("parse error: %s", err)
	}

	if len(raw.Encrypted["contacts"]) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(raw.Encrypted["contacts"]))
	}
	if raw.Encrypted["contacts"][0].Column != "notes" {
		t.Errorf("expected 'notes', got '%s'", raw.Encrypted["contacts"][0].Column)
	}
	if raw.Encrypted["contacts"][1].Column != "ssn" {
		t.Errorf("expected 'ssn', got '%s'", raw.Encrypted["contacts"][1].Column)
	}
	if raw.Encrypted["contacts"][1].Roles[0] != "admin" {
		t.Errorf("expected 'admin' role, got '%s'", raw.Encrypted["contacts"][1].Roles[0])
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"123-45-6789", "*******6789"},
		{"abc", "****"},
		{"", "****"},
		{"secret data here", "************here"},
	}
	for _, tt := range tests {
		got := maskValue(tt.input)
		if got != tt.expected {
			t.Errorf("maskValue(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
