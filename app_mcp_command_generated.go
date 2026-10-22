//go:build !cli

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// Server-generated command values. A command may declare
//
//	generated: [{name: invite_token, kind: token, bytes: 24}]
//
// Prepare draws each value once from crypto/rand and seals it into the prepared
// arguments (`arguments.generated.<name>`), so the approval digest, the commit
// and any retry or replay see exactly one value. Apply and readback bind it as
// `${{ params.generated.<name> }}`; the prepare response may reference it too,
// which is the only way it reaches the preview the model sees. Command SQL still
// may not call random() or randomblob(): that would differ between preview and
// apply.

const (
	commandGeneratedMaxEntries = 16
	commandGeneratedMinBytes   = 16
	commandGeneratedMaxBytes   = 64
	commandGeneratedKey        = "generated"
)

// FlowCommandGenerated is one `generated:` entry. Encoding is "base64url"
// (unpadded) or "hex"; the compiler fills the default.
type FlowCommandGenerated struct {
	Name, Kind, Encoding string
	Bytes                int
}

// length is the exact length of the encoded value.
func (g FlowCommandGenerated) length() int {
	if g.Encoding == "hex" {
		return 2 * g.Bytes
	}
	return base64.RawURLEncoding.EncodedLen(g.Bytes)
}

func compileCommandGenerated(n *yaml.Node) ([]FlowCommandGenerated, error) {
	if n.Kind != yaml.SequenceNode || len(n.Content) < 1 || len(n.Content) > commandGeneratedMaxEntries {
		return nil, fmt.Errorf("generated must list 1..%d entries", commandGeneratedMaxEntries)
	}
	var out []FlowCommandGenerated
	seen := map[string]bool{}
	for _, item := range n.Content {
		m, err := commandMap(item)
		if err != nil {
			return nil, err
		}
		if err = commandExact(m, []string{"name", "kind", "bytes"}, "encoding"); err != nil {
			return nil, fmt.Errorf("generated entry: %w", err)
		}
		var g FlowCommandGenerated
		if g.Name, err = commandScalar(m["name"], "!!str"); err != nil || !commandLocalName(g.Name) || seen[g.Name] {
			return nil, errors.New("generated name must be a unique lowercase identifier")
		}
		seen[g.Name] = true
		if g.Kind, err = commandScalar(m["kind"], "!!str"); err != nil || g.Kind != "token" {
			return nil, fmt.Errorf("generated %s kind must be token", g.Name)
		}
		if m["bytes"].Tag != "!!int" || yamlNodeDecode(m["bytes"], &g.Bytes) != nil || g.Bytes < commandGeneratedMinBytes || g.Bytes > commandGeneratedMaxBytes {
			return nil, fmt.Errorf("generated %s bytes must be an integer from %d to %d", g.Name, commandGeneratedMinBytes, commandGeneratedMaxBytes)
		}
		g.Encoding = "base64url"
		if m["encoding"] != nil {
			if g.Encoding, err = commandScalar(m["encoding"], "!!str"); err != nil || g.Encoding != "base64url" && g.Encoding != "hex" {
				return nil, fmt.Errorf("generated %s encoding must be base64url or hex", g.Name)
			}
		}
		out = append(out, g)
	}
	return out, nil
}

// addGeneratedToPreparedSchema declares `generated` as a closed, fixed-length
// object on the prepared schema, so the sealed arguments, apply and readback
// validate and bind it like any other prepared field.
func addGeneratedToPreparedSchema(schema *AppMCPSchema, generated []FlowCommandGenerated) error {
	if schema == nil || schema.Type != "object" {
		return nil // the caller's schema checks refuse it
	}
	if schema.Properties[commandGeneratedKey] != nil {
		return errors.New("prepared_schema cannot declare a property named generated when the command declares generated values")
	}
	object := &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Properties: map[string]*AppMCPSchema{}}
	for _, g := range generated {
		n := g.length()
		object.Properties[g.Name] = &AppMCPSchema{Type: "string", MinLength: &n, MaxLength: &n}
		object.Required = append(object.Required, g.Name)
	}
	sort.Strings(object.Required)
	if schema.Properties == nil {
		schema.Properties = map[string]*AppMCPSchema{}
	}
	schema.Properties[commandGeneratedKey] = object
	schema.Required = append(schema.Required, commandGeneratedKey)
	return nil
}

var commandGeneratedRef = regexp.MustCompile(`\bparams\.generated\b(?:\.([A-Za-z_][A-Za-z0-9_]*))?([.A-Za-z0-9_]?)`)

// validateCommandGeneratedRefs refuses any reference under params.generated
// that is not exactly one declared name, anywhere in the given YAML.
func validateCommandGeneratedRefs(n *yaml.Node, declared []FlowCommandGenerated) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!str" {
		for _, m := range commandGeneratedRef.FindAllStringSubmatch(n.Value, -1) {
			ok := false
			for _, g := range declared {
				ok = ok || g.Name == m[1]
			}
			if !ok || m[2] != "" {
				return fmt.Errorf("params.generated reference must name one declared generated value")
			}
		}
	}
	for _, c := range n.Content {
		if err := validateCommandGeneratedRefs(c, declared); err != nil {
			return err
		}
	}
	return nil
}

// appMCPGenerateCommandValues draws every declared value from crypto/rand.
func appMCPGenerateCommandValues(declared []FlowCommandGenerated) (map[string]any, error) {
	out := make(map[string]any, len(declared))
	for _, g := range declared {
		raw := make([]byte, g.Bytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		if g.Encoding == "hex" {
			out[g.Name] = hex.EncodeToString(raw)
		} else {
			out[g.Name] = base64.RawURLEncoding.EncodeToString(raw)
		}
	}
	return out, nil
}

// appMCPGeneratedDigests is what the audit log keeps of the values: a digest
// per name, never the value.
func appMCPGeneratedDigests(arguments map[string]any) map[string]any {
	values, _ := arguments[commandGeneratedKey].(map[string]any)
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for name, value := range values {
		text, _ := value.(string)
		out[name] = appMCPOperationDigest("benmore:mcp:generated:v1", []byte(name+"\x00"+text))
	}
	return out
}

// commandParamsWithoutGenerated is what a whole-`params` reference resolves to:
// the generated values only ever travel by their own explicit reference.
func commandParamsWithoutGenerated(values map[string]any) map[string]any {
	if _, ok := values[commandGeneratedKey]; !ok {
		return values
	}
	out := make(map[string]any, len(values))
	for k, v := range values {
		if k != commandGeneratedKey {
			out[k] = v
		}
	}
	return out
}
