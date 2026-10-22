//go:build !cli

package main

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestValidateAppMCPSchemaValue(t *testing.T) {
	falseValue := false
	zero, two := 0, 2
	min, max := 1.5, 9.5
	minLength, maxLength := 2, 3
	schema := &AppMCPSchema{
		Type: "object",
		Properties: map[string]*AppMCPSchema{
			"name":     {Type: "string", MinLength: &minLength, MaxLength: &maxLength, Enum: []any{"é猫", "ok"}},
			"count":    {Type: "integer", Minimum: &min, Maximum: &max, Enum: []any{int64(3), json.Number("4.0")}},
			"tags":     {Type: "array", Items: &AppMCPSchema{Type: "boolean"}, MinItems: &zero, MaxItems: &two},
			"nullable": {Type: "null"},
		},
		Required: []string{"name", "count", "nullable"}, AdditionalProperties: &falseValue,
	}
	for _, value := range []any{
		map[string]any{"name": "é猫", "count": json.Number("3.0"), "tags": []any{true, false}, "nullable": nil},
		map[string]any{"name": "ok", "count": json.Number("4"), "tags": []any{}, "nullable": nil},
	} {
		if err := validateAppMCPSchemaValue(schema, value); err != nil {
			t.Errorf("valid value rejected: %v", err)
		}
	}
	for _, value := range []any{
		map[string]any{"name": "é猫", "count": json.Number("3.0"), "tags": []any{}, "nullable": nil, "extra": true},
		map[string]any{"name": "é猫", "count": json.Number("3.0"), "tags": []any{true, "bad"}, "nullable": nil},
		map[string]any{"name": "é猫", "count": json.Number("3.0"), "tags": []any{true, false, true}, "nullable": nil},
		map[string]any{"name": "é猫", "count": json.Number("3.0"), "tags": []any{}},
		map[string]any{"name": nil, "count": json.Number("3.0"), "tags": []any{}, "nullable": nil},
		map[string]any{"name": "x", "count": json.Number("3.0"), "tags": []any{}, "nullable": nil},
		map[string]any{"name": "é猫", "count": json.Number("3.1"), "tags": []any{}, "nullable": nil},
		map[string]any{"name": "é猫", "count": json.Number("10"), "tags": []any{}, "nullable": nil},
	} {
		if err := validateAppMCPSchemaValue(schema, value); err == nil {
			t.Errorf("invalid value accepted: %#v", value)
		}
	}
}

func TestValidateAppMCPSchemaValueNumbers(t *testing.T) {
	integer := &AppMCPSchema{Type: "integer"}
	for _, value := range []any{json.Number("9007199254740993"), json.Number("1e1000"), int64(math.MaxInt64)} {
		if err := validateAppMCPSchemaValue(integer, value); err != nil {
			t.Errorf("exact integer rejected: %v", err)
		}
	}
	for _, value := range []any{
		json.Number("9007199254740993.1"), json.Number("1/2"), json.Number("01"),
		json.Number("1e999999999"), json.Number("1e1025"), json.Number(strings.Repeat("1", appMCPNumberMaxLength+1)),
		math.NaN(), math.Inf(1),
	} {
		if err := validateAppMCPSchemaValue(integer, value); err == nil {
			t.Errorf("invalid integer accepted: %T", value)
		}
	}
	min := float64(9007199254740992)
	bounded := &AppMCPSchema{Type: "number", Minimum: &min}
	for _, tc := range []struct {
		value any
		valid bool
	}{
		{json.Number("9007199254740992.1"), true},
		{json.Number("9007199254740991.999999999999999999"), false},
	} {
		if err := validateAppMCPSchemaValue(bounded, tc.value); (err == nil) != tc.valid {
			t.Errorf("bounded number %T validity mismatch: err=%v", tc.value, err)
		}
	}
	decimalBound := 0.1
	decimal := &AppMCPSchema{Type: "number", Minimum: &decimalBound, Maximum: &decimalBound}
	if err := validateAppMCPSchemaValue(decimal, json.Number("0.1")); err != nil {
		t.Fatalf("decimal bound rejected its exact JSON value: %v", err)
	}
}

func TestValidateAppMCPSchemaValueEnumUsesJSONNumbers(t *testing.T) {
	schema := &AppMCPSchema{Type: "number", Enum: []any{int64(1), json.Number("2.5"), float64(0.1)}}
	for _, value := range []any{json.Number("1.0"), json.Number("2.50"), json.Number("0.1")} {
		if err := validateAppMCPSchemaValue(schema, value); err != nil {
			t.Errorf("JSON-equivalent enum value rejected: %v", err)
		}
	}
	if err := validateAppMCPSchemaValue(schema, json.Number("1.1")); err == nil {
		t.Fatal("non-enum number accepted")
	}
}

func TestValidateAppMCPSchemaValueDepthIsBounded(t *testing.T) {
	schema := &AppMCPSchema{Type: "array"}
	schema.Items = schema
	value := any(nil)
	for i := 0; i < appMCPSchemaValueMaxDepth+2; i++ {
		value = []any{value}
	}
	if err := validateAppMCPSchemaValue(schema, value); err == nil {
		t.Fatal("recursive schema accepted")
	}
	if err := validateAppMCPSchemaValueAt(schema, value, appMCPSchemaValueMaxDepth); err == nil {
		t.Fatal("over-depth recursive value accepted")
	}
	invalidBound := math.NaN()
	if err := validateAppMCPSchemaValue(&AppMCPSchema{Type: "number", Minimum: &invalidBound}, json.Number("0")); err == nil {
		t.Fatal("schema with nonfinite bound accepted")
	}
}

func TestValidateAppMCPSchemaValueJSONRepresentations(t *testing.T) {
	closed := false
	one, two := 1, 2
	min, max := 1.0, 3.0
	for _, tc := range []struct {
		name   string
		schema *AppMCPSchema
		value  any
		valid  bool
	}{
		{"nil array", &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "boolean"}, Enum: []any{[]any{}}}, []any(nil), false},
		{"nil object", &AppMCPSchema{Type: "object", AdditionalProperties: &closed}, map[string]any(nil), false},
		{"typed nil as null", &AppMCPSchema{Type: "null"}, []any(nil), true},
		{"typed array enum", &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "string"}, Enum: []any{[]string{"ok"}}}, []any{"ok"}, true},
		{"typed object enum", &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Properties: map[string]*AppMCPSchema{"name": {Type: "string"}}, Enum: []any{map[string]string{"name": "ok"}}}, map[string]any{"name": "ok"}, true},
		{"invalid utf8", &AppMCPSchema{Type: "string", MinLength: &one, MaxLength: &one}, string([]byte{0xff}), false},
		{"minimum length", &AppMCPSchema{Type: "string", MinLength: &two}, "a", false},
		{"maximum length", &AppMCPSchema{Type: "string", MaxLength: &one}, "ab", false},
		{"minimum items", &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "boolean"}, MinItems: &one}, []any{}, false},
		{"fractional integer", &AppMCPSchema{Type: "integer"}, json.Number("3.1"), false},
		{"minimum number", &AppMCPSchema{Type: "number", Minimum: &min}, json.Number("0.9"), false},
		{"maximum number", &AppMCPSchema{Type: "number", Maximum: &max}, json.Number("3.1"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateAppMCPSchemaValue(tc.schema, tc.value); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
