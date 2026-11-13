//go:build !cli

package main

// A `run: respond` body is sent as its author wrote it.
//
// YAML reads an unquoted date or timestamp (`body: 2026-11-12`) as a time,
// not as text, and a respond step has no time body: the value was dropped
// and the step answered its status with an empty body. The step decoder
// puts the scalar's own source text back, so the step reads the value
// exactly as it reads the same text in quotes. Numbers and booleans are left
// alone: they are sent as that JSON value (respondScalarBody).

import (
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// respondBodyKeys are the `with:` keys that hold a respond step's body.
var respondBodyKeys = []string{"body", "json"}

// restoreRespondDateText replaces a `body`/`json` that decoded to a time
// with the text of its scalar in step, the step's own YAML node.
func restoreRespondDateText(step *yaml.Node, with map[string]any) {
	for _, key := range respondBodyKeys {
		if _, isTime := with[key].(time.Time); !isTime {
			continue
		}
		if value := ghaMappingValue(ghaMappingValue(step, "with"), key); value != nil && value.Kind == yaml.ScalarNode {
			with[key] = value.Value
		}
	}
}

// ghaMappingValue is the value node of key in a YAML mapping, read the way
// the decoder reads it: aliases are followed, an entry written in the
// mapping wins over a merged one (`<<: *base`), and of several merged
// mappings the first that has the key wins. nil when there is none.
func ghaMappingValue(node *yaml.Node, key string) *yaml.Node {
	active := map[*yaml.Node]bool{}
	var resolve func(n *yaml.Node) *yaml.Node
	resolve = func(n *yaml.Node) *yaml.Node {
		for n != nil && n.Kind == yaml.AliasNode {
			n = n.Alias
		}
		return n
	}
	var find func(n *yaml.Node) *yaml.Node
	find = func(n *yaml.Node) *yaml.Node {
		n = resolve(n)
		if n == nil || active[n] {
			return nil
		}
		active[n] = true
		defer delete(active, n)
		switch n.Kind {
		case yaml.SequenceNode: // `<<: [*a, *b]`
			for _, child := range n.Content {
				if found := find(child); found != nil {
					return found
				}
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Tag != "!!merge" && n.Content[i].Value == key {
					return resolve(n.Content[i+1])
				}
			}
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Tag == "!!merge" {
					if found := find(n.Content[i+1]); found != nil {
						return found
					}
				}
			}
		}
		return nil
	}
	return find(node)
}

// respondBodyValue is the `with.body` a respond step reads. Blank text
// beside a `json:` is no body: the step sends the JSON. It used to send the
// blank body, so `with: { status: 403, body: "", json: {...} }` answered 403
// with nothing. Text that is not blank is the body, with or without `json:`.
func respondBodyValue(with map[string]any) any {
	if text, isText := with["body"].(string); isText && strings.TrimSpace(text) == "" && with["json"] != nil {
		return nil
	}
	return with["body"]
}

// respondTimeText is the text sent for a body that is still a time: a
// `with:` map that did not come from a flow file, so there is no source
// text to send. A date is written as a date.
func respondTimeText(v any) string {
	t, isTime := v.(time.Time)
	if !isTime {
		return ""
	}
	if h, m, s := t.Clock(); h == 0 && m == 0 && s == 0 && t.Nanosecond() == 0 && t.Location() == time.UTC {
		return t.Format(time.DateOnly)
	}
	return t.Format(time.RFC3339Nano)
}
