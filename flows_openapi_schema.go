//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"github.com/dop251/goja"
)

func validateFlowOpenAPISchema(value any, depth int) error {
	schema, ok := value.(map[string]any)
	if !ok || depth > 24 {
		return fmt.Errorf("schema must be an object within depth 24")
	}
	if alternatives, exists := schema["anyOf"]; exists {
		choices, ok := alternatives.([]any)
		if !ok || len(choices) < 2 || len(schema) != 1 {
			return fmt.Errorf("anyOf requires at least two schemas and no sibling keywords")
		}
		for _, choice := range choices {
			if err := validateFlowOpenAPISchema(choice, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	kind, ok := schema["type"].(string)
	if !ok || !map[string]bool{"object": true, "array": true, "string": true, "number": true, "integer": true, "boolean": true, "null": true}[kind] {
		return fmt.Errorf("unsupported schema type")
	}
	allowed := map[string]bool{"type": true, "enum": true}
	var pairs [][2]string
	switch kind {
	case "string":
		allowed["pattern"] = true
		pairs = append(pairs, [2]string{"minLength", "maxLength"})
	case "array":
		pairs = append(pairs, [2]string{"minItems", "maxItems"})
	case "number", "integer":
		pairs = append(pairs, [2]string{"minimum", "maximum"})
	}
	for _, pair := range pairs {
		for _, key := range pair {
			allowed[key] = true
			if value, exists := schema[key]; exists {
				number, ok := appMCPExactNumber(value)
				if !ok {
					return fmt.Errorf("%s must be a finite number", key)
				}
				if key != "minimum" && key != "maximum" && (!number.IsInt() || number.Sign() < 0 || !number.Num().IsInt64() || number.Num().Int64() > 1000000) {
					return fmt.Errorf("%s must be an integer from zero to 1000000", key)
				}
			}
		}
		lower, lok := appMCPExactNumber(schema[pair[0]])
		upper, uok := appMCPExactNumber(schema[pair[1]])
		if lok && uok && lower.Cmp(upper) > 0 {
			return fmt.Errorf("schema minimum exceeds maximum")
		}
	}
	if raw, exists := schema["pattern"]; exists {
		pattern, ok := raw.(string)
		if !ok || len(pattern) > 512 {
			return fmt.Errorf("pattern must be a string of at most 512 bytes")
		}
		vm := goja.New()
		if _, err := vm.New(vm.Get("RegExp"), vm.ToValue(pattern)); err != nil {
			return fmt.Errorf("pattern must be a valid ECMAScript regular expression")
		}
	}
	if kind == "object" {
		for _, key := range []string{"properties", "required", "additionalProperties"} {
			allowed[key] = true
		}
	}
	if kind == "array" {
		allowed["items"] = true
	}
	for key := range schema {
		if !allowed[key] {
			return fmt.Errorf("unsupported schema keyword %q for %s", key, kind)
		}
	}
	if values, exists := schema["enum"]; exists {
		choices, ok := values.([]any)
		if !ok || len(choices) == 0 || kind == "object" || kind == "array" {
			return fmt.Errorf("enum requires nonempty scalar values")
		}
		seen := map[string]bool{}
		for _, choice := range choices {
			valid := false
			switch kind {
			case "string":
				_, valid = choice.(string)
			case "boolean":
				_, valid = choice.(bool)
			case "null":
				valid = choice == nil
			case "number", "integer":
				switch n := choice.(type) {
				case int:
					valid = true
				case uint64:
					valid = true
				case int64:
					valid = true
				case float64:
					valid = kind == "number" || n == float64(int64(n))
				}
			}
			encoded, err := json.Marshal(choice)
			if !valid || err != nil || seen[string(encoded)] {
				return fmt.Errorf("enum values must be unique and match type")
			}
			seen[string(encoded)] = true
		}
	}
	if kind == "array" {
		return validateFlowOpenAPISchema(schema["items"], depth+1)
	}
	if kind != "object" {
		return nil
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return fmt.Errorf("object requires properties")
	}
	for _, property := range properties {
		if err := validateFlowOpenAPISchema(property, depth+1); err != nil {
			return err
		}
	}
	if required, exists := schema["required"]; exists {
		names, ok := required.([]any)
		if !ok {
			return fmt.Errorf("required must be an array of property names")
		}
		seen := map[string]bool{}
		for _, name := range names {
			text, ok := name.(string)
			if !ok || properties[text] == nil || seen[text] {
				return fmt.Errorf("required contains an unknown or repeated property")
			}
			seen[text] = true
		}
	}
	extra, exists := schema["additionalProperties"]
	if !exists {
		return fmt.Errorf("object requires additionalProperties false or a schema")
	}
	{
		if extra == false {
			return nil
		}
		if err := validateFlowOpenAPISchema(extra, depth+1); err != nil {
			return fmt.Errorf("additionalProperties: %w", err)
		}
	}
	return nil
}

func validateFlowOpenAPIResponse(value any) error {
	response, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("response must be a schema or content object")
	}
	raw, exists := response["content"]
	if !exists {
		return validateFlowOpenAPISchema(value, 0)
	}
	content, ok := raw.(map[string]any)
	if !ok || len(response) != 1 || len(content) == 0 || len(content) > 2 {
		return fmt.Errorf("response content requires one or two supported media types and no sibling keys")
	}
	for media, schema := range content {
		if media != "application/json" && media != "text/plain" {
			return fmt.Errorf("unsupported response media type")
		}
		if err := validateFlowOpenAPISchema(schema, 0); err != nil {
			return err
		}
		if media == "text/plain" && schema.(map[string]any)["type"] != "string" {
			return fmt.Errorf("text/plain response requires a string schema")
		}
	}
	return nil
}
