//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

const appMCPSchemaValueMaxDepth = 32

// ponytail: cap decimal parsing at 1024 characters and exponent magnitude 1024;
// raise these limits only if a real schema needs larger numeric literals.
const appMCPNumberMaxLength = 1024
const appMCPNumberMaxExponent = 1024

func validateAppMCPSchemaValue(schema *AppMCPSchema, value any) error {
	if err := validateAppMCPSchema(schema, 0); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	return validateAppMCPSchemaValueAt(schema, value, 0)
}

func appMCPProjectSchemaValue(schema *AppMCPSchema, value any) any {
	switch schema.Type {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return value
		}
		projected := make(map[string]any, len(schema.Properties))
		for name, property := range schema.Properties {
			if child, present := object[name]; present {
				projected[name] = appMCPProjectSchemaValue(property, child)
			}
		}
		return projected
	case "array":
		items, ok := value.([]any)
		if !ok || schema.Items == nil {
			return value
		}
		projected := make([]any, len(items))
		for i, item := range items {
			projected[i] = appMCPProjectSchemaValue(schema.Items, item)
		}
		return projected
	default:
		return value
	}
}

func validateAppMCPSchemaValueAt(schema *AppMCPSchema, value any, depth int) error {
	if schema == nil || depth > appMCPSchemaValueMaxDepth {
		return fmt.Errorf("schema value exceeds depth limit")
	}
	value = appMCPJSONNull(value)
	if len(schema.Enum) > 0 {
		matched := false
		for _, candidate := range schema.Enum {
			raw, err := json.Marshal(candidate)
			if err != nil {
				return fmt.Errorf("invalid schema enum")
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var normalized any
			if err := decoder.Decode(&normalized); err != nil {
				return fmt.Errorf("invalid schema enum")
			}
			if appMCPJSONValueEqual(value, normalized, 0) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("value is not in enum")
		}
	}

	// A nullable schema accepts JSON null after the enum check, matching the
	// advertised [X, "null"]: an enum that omits null still refuses it.
	if schema.Nullable && value == nil {
		return nil
	}
	switch schema.Type {
	case "null":
		if value != nil {
			return fmt.Errorf("expected null")
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean")
		}
	case "string":
		v, ok := value.(string)
		if !ok || !utf8.ValidString(v) {
			return fmt.Errorf("expected valid UTF-8 string")
		}
		n := utf8.RuneCountInString(v)
		if schema.MinLength != nil && n < *schema.MinLength || schema.MaxLength != nil && n > *schema.MaxLength {
			return fmt.Errorf("string length is outside schema bounds")
		}
	case "number", "integer":
		n, ok := appMCPExactNumber(value)
		if !ok {
			return fmt.Errorf("expected finite number")
		}
		if schema.Type == "integer" && !n.IsInt() {
			return fmt.Errorf("expected integer")
		}
		if schema.Minimum != nil {
			bound, _ := appMCPExactNumber(*schema.Minimum)
			if n.Cmp(bound) < 0 {
				return fmt.Errorf("number is outside schema bounds")
			}
		}
		if schema.Maximum != nil {
			bound, _ := appMCPExactNumber(*schema.Maximum)
			if n.Cmp(bound) > 0 {
				return fmt.Errorf("number is outside schema bounds")
			}
		}
	case "object":
		v, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object")
		}
		for _, name := range schema.Required {
			if _, ok := v[name]; !ok {
				return fmt.Errorf("required property is missing")
			}
		}
		for name, item := range v {
			if !utf8.ValidString(name) {
				return fmt.Errorf("invalid object property encoding")
			}
			property, ok := schema.Properties[name]
			if !ok {
				if schema.AdditionalProperties != nil && !*schema.AdditionalProperties {
					return fmt.Errorf("additional property is not allowed")
				}
				continue
			}
			if err := validateAppMCPSchemaValueAt(property, item, depth+1); err != nil {
				return err
			}
		}
	case "array":
		v, ok := value.([]any)
		if !ok {
			return fmt.Errorf("expected array")
		}
		if schema.MinItems != nil && len(v) < *schema.MinItems || schema.MaxItems != nil && len(v) > *schema.MaxItems {
			return fmt.Errorf("array length is outside schema bounds")
		}
		for _, item := range v {
			if err := validateAppMCPSchemaValueAt(schema.Items, item, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported schema type")
	}
	return nil
}

func appMCPExactNumber(value any) (*big.Rat, bool) {
	switch v := value.(type) {
	case json.Number:
		if len(v.String()) == 0 || len(v.String()) > appMCPNumberMaxLength {
			return nil, false
		}
		decoder := json.NewDecoder(strings.NewReader(v.String()))
		decoder.UseNumber()
		var parsed any
		if decoder.Decode(&parsed) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, false
		}
		if _, ok := parsed.(json.Number); !ok {
			return nil, false
		}
		if !appMCPNumberExponentInRange(v.String()) {
			return nil, false
		}
		r, ok := new(big.Rat).SetString(v.String())
		return r, ok
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, false
		}
		r, ok := new(big.Rat).SetString(strconv.FormatFloat(v, 'g', -1, 64))
		return r, ok
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, false
		}
		r, ok := new(big.Rat).SetString(strconv.FormatFloat(f, 'g', -1, 32))
		return r, ok
	case int:
		return new(big.Rat).SetInt64(int64(v)), true
	case int8:
		return new(big.Rat).SetInt64(int64(v)), true
	case int16:
		return new(big.Rat).SetInt64(int64(v)), true
	case int32:
		return new(big.Rat).SetInt64(int64(v)), true
	case int64:
		return new(big.Rat).SetInt64(v), true
	case uint:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(uint64(v))), true
	case uint8:
		return new(big.Rat).SetInt64(int64(v)), true
	case uint16:
		return new(big.Rat).SetInt64(int64(v)), true
	case uint32:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(uint64(v))), true
	case uint64:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(v)), true
	default:
		return nil, false
	}
}

func appMCPNumberExponentInRange(number string) bool {
	i := strings.IndexAny(number, "eE")
	if i < 0 {
		return true
	}
	exponent := number[i+1:]
	if len(exponent) == 0 {
		return false
	}
	if exponent[0] == '+' || exponent[0] == '-' {
		exponent = exponent[1:]
	}
	if len(exponent) == 0 {
		return false
	}
	value := 0
	for i := 0; i < len(exponent); i++ {
		if exponent[i] < '0' || exponent[i] > '9' {
			return false
		}
		value = value*10 + int(exponent[i]-'0')
		if value > appMCPNumberMaxExponent {
			return false
		}
	}
	return true
}

func appMCPJSONValueEqual(a, b any, depth int) bool {
	if depth > appMCPSchemaValueMaxDepth {
		return false
	}
	a, b = appMCPJSONNull(a), appMCPJSONNull(b)
	if an, ok := appMCPExactNumber(a); ok {
		bn, ok := appMCPExactNumber(b)
		return ok && an.Cmp(bn) == 0
	}
	switch av := a.(type) {
	case nil:
		return b == nil
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !appMCPJSONValueEqual(av[i], bv[i], depth+1) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for key, value := range av {
			other, exists := bv[key]
			if !exists || !appMCPJSONValueEqual(value, other, depth+1) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// Typed nil JSON containers encode as null, not as empty objects or arrays.
func appMCPJSONNull(value any) any {
	switch v := value.(type) {
	case map[string]any:
		if v == nil {
			return nil
		}
	case []any:
		if v == nil {
			return nil
		}
	}
	return value
}
