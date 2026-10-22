//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

func nullableManifest(property string) string {
	return strings.Replace(appMCPManifestFixture(), "id: {type: integer}", "id: {type: integer}\n        label: "+property, 1)
}

func parseNullableLabel(t *testing.T, property string) *AppMCPSchema {
	t.Helper()
	manifest, err := parseAppMCPManifest([]byte(nullableManifest(property)))
	if err != nil {
		t.Fatalf("%s rejected: %v", property, err)
	}
	return manifest.Tools[0].OutputSchema.Properties["label"]
}

func TestAppMCPSchemaNullableSpellingsNormalizeToOneRepresentation(t *testing.T) {
	var encoded []string
	for _, property := range []string{
		`{type: [string, "null"], maxLength: 5}`,
		`{type: ["null", string], maxLength: 5}`,
		`{type: string, nullable: true, maxLength: 5}`,
		`{type: [string, "null"], nullable: true, maxLength: 5}`,
	} {
		label := parseNullableLabel(t, property)
		if label.Type != "string" || !label.Nullable || label.MaxLength == nil || *label.MaxLength != 5 {
			t.Fatalf("%s did not normalize to Type=string Nullable: %+v", property, label)
		}
		raw, err := json.Marshal(label)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, string(raw))
	}
	for _, raw := range encoded {
		if raw != encoded[0] || !strings.Contains(raw, `"type":["string","null"]`) {
			t.Fatalf("clients must see standard [X,\"null\"] identically for every spelling: %v", encoded)
		}
	}
	// Object and array types, and an explicit false, normalize the same way.
	object := parseNullableLabel(t, `{type: [object, "null"], additionalProperties: false, properties: {a: {type: integer}}}`)
	array := parseNullableLabel(t, `{type: [array, "null"], items: {type: integer}}`)
	plain := parseNullableLabel(t, `{type: string, nullable: false}`)
	if object.Type != "object" || !object.Nullable || array.Type != "array" || !array.Nullable || plain.Nullable {
		t.Fatalf("object=%+v array=%+v plain=%+v", object, array, plain)
	}
	if raw, _ := json.Marshal(plain); strings.Contains(string(raw), "null") {
		t.Fatalf("non-nullable schema must advertise a plain type: %s", raw)
	}
}

func TestAppMCPSchemaNullableRefusesUnionsAndUnknownKeywords(t *testing.T) {
	for _, property := range []string{
		`{type: [string, null]}`,
		`{type: [null, string]}`,
		`{type: [string, "null"], nullable: false}`,
		`{type: [string, integer]}`,
		`{type: [string]}`,
		`{type: ["null"]}`,
		`{type: ["null", "null"]}`,
		`{type: [string, "null", integer]}`,
		`{type: [[string], "null"]}`,
		`{type: {a: string}}`,
		`{type: string, nullable: "true"}`,
		`{type: string, nullable: [true]}`,
		`{type: "null", nullable: true}`,
		`{type: [bogus, "null"]}`,
		`{oneOf: [{type: string}, {type: "null"}]}`,
		`{anyOf: [{type: string}, {type: "null"}]}`,
		`{type: string, allOf: []}`,
	} {
		if _, err := parseAppMCPManifest([]byte(nullableManifest(property))); err == nil {
			t.Fatalf("%s was accepted", property)
		}
	}
}

func TestAppMCPSchemaNullableValueValidation(t *testing.T) {
	nullable := &AppMCPSchema{Type: "string", Nullable: true, MaxLength: intPointer(3)}
	strict := &AppMCPSchema{Type: "string", MaxLength: intPointer(3)}
	if err := validateAppMCPSchemaValue(nullable, nil); err != nil {
		t.Fatalf("nullable schema refused null: %v", err)
	}
	if err := validateAppMCPSchemaValue(nullable, "abc"); err != nil {
		t.Fatalf("nullable schema refused its own type: %v", err)
	}
	for _, value := range []any{"abcd", 1, true, map[string]any{}} {
		if validateAppMCPSchemaValue(nullable, value) == nil {
			t.Fatalf("nullable schema accepted %#v", value)
		}
	}
	if validateAppMCPSchemaValue(strict, nil) == nil {
		t.Fatal("non-nullable schema accepted null")
	}
	enum := &AppMCPSchema{Type: "string", Nullable: true, Enum: []any{"a"}}
	if validateAppMCPSchemaValue(enum, nil) == nil {
		t.Fatal("an enum that omits null must still refuse it")
	}
	enum.Enum = []any{"a", nil}
	if err := validateAppMCPSchemaValue(enum, nil); err != nil {
		t.Fatalf("enum listing null refused it: %v", err)
	}
	// Nullable members are looked up by property, and required still means present.
	object := &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Required: []string{"a"}, Properties: map[string]*AppMCPSchema{"a": nullable, "b": strict}}
	if err := validateAppMCPSchemaValue(object, map[string]any{"a": nil}); err != nil {
		t.Fatalf("required nullable member with null: %v", err)
	}
	if validateAppMCPSchemaValue(object, map[string]any{}) == nil || validateAppMCPSchemaValue(object, map[string]any{"a": nil, "b": nil}) == nil {
		t.Fatal("required presence or a non-nullable member was not enforced")
	}
	if validateAppMCPSchema(&AppMCPSchema{Type: "null", Nullable: true}, 0) == nil {
		t.Fatal("nullable null type accepted")
	}
}

func TestAppMCPSchemaNullabilityChangesContractDigest(t *testing.T) {
	digest := func(property string) string {
		manifest, err := parseAppMCPManifest([]byte(nullableManifest(property)))
		if err != nil {
			t.Fatal(err)
		}
		value, err := appMCPContractDigest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	plain, nullable := digest(`{type: string}`), digest(`{type: string, nullable: true}`)
	if plain == nullable {
		t.Fatal("making a field nullable did not change the reviewed contract digest")
	}
	if nullable != digest(`{type: [string, "null"]}`) || nullable != digest(`{type: ["null", string]}`) || nullable != digest(`{type: string, nullable: true}`) {
		t.Fatal("equivalent nullable spellings must produce one deterministic digest")
	}
	if plain != digest(`{type: string, nullable: false}`) {
		t.Fatal("explicit nullable:false changed the digest")
	}
}

func TestAppMCPSchemaNullableSurvivesYAMLRoundTrip(t *testing.T) {
	manifest, err := parseAppMCPManifest([]byte(nullableManifest(`{type: [string, "null"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	again, err := parseAppMCPManifest(raw)
	if err != nil {
		t.Fatalf("re-written manifest does not parse: %v\n%s", err, raw)
	}
	if label := again.Tools[0].OutputSchema.Properties["label"]; !label.Nullable || label.Type != "string" {
		t.Fatalf("nullability lost across yaml.Marshal: %+v", label)
	}
	if cloned := cloneAppMCPSchema(again.Tools[0].OutputSchema); !cloned.Properties["label"].Nullable {
		t.Fatal("cloned generation schema lost nullability")
	}
}

func TestAppMCPSchemaNullableIsAdvertisedToSDKClients(t *testing.T) {
	manifest, err := parseAppMCPManifest([]byte(strings.Replace(nullableManifest(`{type: [string, "null"]}`), "input_schema: {type: object, additionalProperties: false}",
		"input_schema: {type: object, additionalProperties: false, properties: {q: {type: string, nullable: true}}}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	tool := manifest.Tools[0]
	server := sdk.NewServer(&sdk.Implementation{Name: "fixture", Version: "1"}, nil)
	server.AddTool(&sdk.Tool{Name: tool.Name, InputSchema: tool.InputSchema, OutputSchema: tool.OutputSchema}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{}, nil
	})
	clientTransport, serverTransport := sdk.NewInMemoryTransports()
	ctx := context.Background()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	session, err := sdk.NewClient(&sdk.Implementation{Name: "client", Version: "1"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	listed, err := session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 1 {
		t.Fatalf("list tools: %+v %v", listed, err)
	}
	raw, err := json.Marshal(listed.Tools[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), `"type":["string","null"]`); got != 2 {
		t.Fatalf("expected both input and output nullable fields advertised as [string,null], found %d: %s", got, raw)
	}
}
