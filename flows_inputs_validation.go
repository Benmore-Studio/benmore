//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
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
