//go:build !cli

package main

// Minimal JSON path evaluator for the recipe engine's `extract:` step
// and the `json_path` pipe.
//
// Supports: `$.foo`, `$.foo.bar`, `$.foo[0]`, `$.foo.bar[2].baz`.
// Bare strings, numbers, bools, and null are stringified. Missing
// path returns "" with no error so optional extracts behave cleanly.
//
// Intentionally not a full JSONPath: no filters, no recursion, no
// wildcards. Adding any of these should come with a fuzz test —
// recipe input is partly user-controlled.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func evalJSONPath(path string, doc any) (string, error) {
	if !strings.HasPrefix(path, "$") {
		return "", fmt.Errorf("json_path must start with $: %q", path)
	}
	rest := path[1:]
	cur := doc
	for rest != "" {
		switch rest[0] {
		case '.':
			// Field access: $.field
			rest = rest[1:]
			end := indexOfAny(rest, ".[")
			var field string
			if end < 0 {
				field, rest = rest, ""
			} else {
				field, rest = rest[:end], rest[end:]
			}
			m, ok := cur.(map[string]any)
			if !ok {
				return "", nil
			}
			cur = m[field]
		case '[':
			// Index: [N]
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return "", fmt.Errorf("unterminated [ in path %q", path)
			}
			idxStr := rest[1:end]
			rest = rest[end+1:]
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return "", fmt.Errorf("bad index %q in path", idxStr)
			}
			arr, ok := cur.([]any)
			if !ok {
				return "", nil
			}
			if idx < 0 || idx >= len(arr) {
				return "", nil
			}
			cur = arr[idx]
		default:
			return "", fmt.Errorf("unexpected %q in path", rest[:1])
		}
	}
	return stringifyJSONValue(cur), nil
}

func evalJSONPathBytes(raw []byte, path string) (string, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("json_path: input not JSON: %w", err)
	}
	return evalJSONPath(path, doc)
}

func stringifyJSONValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		raw, _ := json.Marshal(v)
		return string(raw)
	}
}

func indexOfAny(s string, chars string) int {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return i
			}
		}
	}
	return -1
}
