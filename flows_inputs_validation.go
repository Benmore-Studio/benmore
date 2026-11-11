//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

func validateFlowInputValues(inputs map[string]FlowInput, values map[string]any) error {
	for name, input := range inputs {
		value, present := values[name]
		if !present || value == nil || input.Required && value == "" {
			if input.Required {
				return fmt.Errorf("flow input %q is required", name)
			}
			continue
		}

		invalid := func(expected string) error {
			return fmt.Errorf("flow input %q must be %s", name, expected)
		}
		switch input.Type {
		case "text", "textarea":
			if _, ok := value.(string); !ok {
				return invalid("text")
			}
		case "email":
			s, ok := value.(string)
			if !ok || !validAuthEmail(s) {
				return invalid("a valid email address")
			}
		case "date":
			s, ok := value.(string)
			if !ok {
				return invalid("a YYYY-MM-DD date")
			}
			date, err := time.Parse("2006-01-02", s)
			if err != nil || date.Format("2006-01-02") != s {
				return invalid("a YYYY-MM-DD date")
			}
		case "enum":
			s, ok := value.(string)
			if !ok {
				return invalid("one of the declared values")
			}
			found := false
			for _, allowed := range input.Values {
				if s == allowed {
					found = true
					break
				}
			}
			if !found {
				return invalid("one of the declared values")
			}
		case "number":
			var n float64
			switch v := value.(type) {
			case float64:
				n = v
			case int64: // an integer beyond 2^53 (unmarshalJSONExact)
				n = float64(v)
			case json.Number:
				parsed, err := strconv.ParseFloat(string(v), 64)
				if err != nil {
					return invalid("a finite number")
				}
				n = parsed
			case string: // HTTP query and form values
				parsed, err := strconv.ParseFloat(v, 64)
				if err != nil {
					return invalid("a finite number")
				}
				n = parsed
			default:
				return invalid("a finite number")
			}
			if math.IsNaN(n) || math.IsInf(n, 0) || input.Min != nil && n < *input.Min || input.Max != nil && n > *input.Max {
				return invalid("a number within the declared range")
			}
		case "bool":
			switch v := value.(type) {
			case bool:
			case string: // HTTP query and form values
				if v != "true" && v != "false" {
					return invalid("a boolean")
				}
			default:
				return invalid("a boolean")
			}
		default:
			return fmt.Errorf("flow input %q has unsupported type", name)
		}
	}
	return nil
}

// bindFlowInputDefaults gives every declared input the caller left out (or
// sent as null, which validation also treats as not provided) its `default:`.
// The default was documented and drives FlowForm, but nothing bound it, so a
// step reading `${{ params.hours }}` for an omitted `hours: {default: 1}`
// failed with template_unresolved.
//
// The value is bound exactly where a request field lands: ctx.Data keeps its
// native YAML type (a number, true/false, text), ctx.Params its text, and the
// name is marked as request input. The value is the author's, but the caller
// decides on every call whether it applies, so taint analysis (sql_dynamic,
// credential-carrying URLs, sessionless realtime scope) treats the name the
// same on each run. Identity and reserved names are never bound: a request
// can't set them either (stripRequestIdentityKeys).
func bindFlowInputDefaults(ctx *FlowContext, inputs map[string]FlowInput, provided map[string]any) {
	for name, input := range inputs {
		if input.Default == nil || flowInputDefaultReserved(name) {
			continue
		}
		if value, present := provided[name]; present && value != nil {
			continue
		}
		value := flowInputDefaultValue(input.Default)
		var text string
		switch v := value.(type) {
		case string:
			text = v
		case bool, float64, int64:
			text = valueText(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				continue
			}
			text = string(b)
		}
		ctx.Data[name] = value
		ctx.Params[name] = text
		if ctx.NullParams != nil {
			delete(ctx.NullParams, name)
		}
		if ctx.RequestKeys == nil {
			ctx.RequestKeys = map[string]bool{}
		}
		ctx.RequestKeys[name] = true
	}
}

// flowInputDefaultReserved reports names no request value may set.
func flowInputDefaultReserved(name string) bool {
	for _, key := range flowIdentityKeys {
		if name == key {
			return true
		}
	}
	return strings.HasPrefix(name, "user.") || name == "env" || strings.HasPrefix(name, "env.") ||
		name == flowStepNamedParamsKey || strings.HasPrefix(name, flowStepNamedParamsKey+".")
}

// flowInputDefaultValue is a YAML `default:` as the value a JSON request
// body would have carried: YAML integers become float64 like JSON numbers
// (int64 beyond 2^53, as unmarshalJSONExact keeps them), so a default and a
// sent value of the same input read and bind alike.
func flowInputDefaultValue(v any) any {
	switch n := v.(type) {
	case int:
		return flowInputDefaultInteger(int64(n))
	case int64:
		return flowInputDefaultInteger(n)
	case uint64:
		if n <= math.MaxInt64 {
			return flowInputDefaultInteger(int64(n))
		}
		return float64(n)
	case float32:
		return float64(n)
	}
	return v
}

func flowInputDefaultInteger(n int64) any {
	if n > maxExactFloatInteger || n < -maxExactFloatInteger {
		return n
	}
	return float64(n)
}
