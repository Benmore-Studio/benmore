//go:build !cli

package main

import (
	"encoding/json"
	"math"
	"testing"
)

func TestAppMCPCommandBindingDeclarationAcceptsOptionalScalarsOnly(t *testing.T) {
	closed := commandBoolPtr(false)
	input := &AppMCPSchema{Type: "object", AdditionalProperties: closed, Required: []string{"id"}, Properties: map[string]*AppMCPSchema{
		"id":      {Type: "integer"},
		"note":    {Type: "string", Nullable: true},
		"ratio":   {Type: "number"},
		"flag":    {Type: "boolean"},
		"tags":    {Type: "array", Items: &AppMCPSchema{Type: "string"}},
		"nested":  {Type: "object", AdditionalProperties: closed, Properties: map[string]*AppMCPSchema{"deep": {Type: "string"}}},
		"nothing": {Type: "null"},
	}}
	bind := func(path string) error {
		return validateAppMCPCommandIntentBindings([]FlowStep{{Type: "sql", SQLParams: map[string]string{"v": "x"},
			CommandSQLParams: map[string]FlowCommandParamRef{"v": {Kind: "phase_path", Path: path}}}}, input, "prepare")
	}
	for _, path := range []string{"id", "note", "ratio", "flag", "nested.deep"} {
		if err := bind(path); err != nil {
			t.Fatalf("scalar path %q refused: %v", path, err)
		}
	}
	for _, path := range []string{"tags", "nested", "nothing", "missing", "nested.missing", "id.deeper", ""} {
		if bind(path) == nil {
			t.Fatalf("non-scalar or undeclared path %q accepted", path)
		}
	}
	// for_each sources stay required and bounded arrays.
	input.Properties["list"] = &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "string"}, MaxItems: func() *int { n := 3; return &n }()}
	if validateAppMCPCommandIntentBindings([]FlowStep{{Type: "for_each", ForEach: "params.list"}}, input, "prepare") == nil {
		t.Fatal("optional array accepted as a for_each source")
	}
	// A required source must also be non-nullable, array and elements alike.
	three := 3
	input.Required = append(input.Required, "list", "nullable_list", "nullable_items")
	input.Properties["nullable_list"] = &AppMCPSchema{Type: "array", Nullable: true, Items: &AppMCPSchema{Type: "string"}, MaxItems: &three}
	input.Properties["nullable_items"] = &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "object", Nullable: true}, MaxItems: &three}
	loop := func(path string) error {
		return validateAppMCPCommandIntentBindings([]FlowStep{{Type: "for_each", ForEach: "params." + path}}, input, "prepare")
	}
	if err := loop("list"); err != nil {
		t.Fatalf("required non-nullable bounded array refused: %v", err)
	}
	for _, path := range []string{"nullable_list", "nullable_items"} {
		if loop(path) == nil {
			t.Fatalf("nullable for_each source %q accepted", path)
		}
	}
}

func TestAppMCPCommandBindScalarShapes(t *testing.T) {
	for in, want := range map[any]any{true: int64(1), false: int64(0), int64(7): int64(7), "s": "s", 2.5: 2.5} {
		got, err := appMCPCommandBindScalar(in)
		if err != nil || got != want {
			t.Fatalf("%#v bound as %#v, %v", in, got, err)
		}
	}
	for _, bad := range []any{math.NaN(), math.Inf(1), math.Inf(-1), json.Number("1e400"), json.Number("1e16"), nil, []any{}} {
		if _, err := appMCPCommandBindScalar(bad); err == nil {
			t.Fatalf("%#v bound", bad)
		}
	}
}
