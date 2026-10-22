//go:build !cli

package main

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

func appMCPDeclaredScopes(manifest *AppMCPManifest) string {
	known := map[string]bool{}
	if manifest != nil {
		for _, tool := range manifest.Tools {
			for _, scope := range tool.Permissions {
				known[scope] = true
			}
		}
	}
	values := make([]string, 0, len(known))
	for scope := range known {
		values = append(values, scope)
	}
	sort.Strings(values)
	if len(values) == 0 {
		return "_none_:read"
	}
	return strings.Join(values, " ")
}

func appMCPUpdateTool(manifest *AppMCPManifest, name string) *AppMCPTool {
	if manifest == nil || name == "" {
		return nil
	}
	for i := range manifest.Tools {
		tool := &manifest.Tools[i]
		if tool.Name == name && tool.Handler.Kind == "native" && tool.Handler.Operation == "table.update" && tool.Effect == "write" {
			return tool
		}
	}
	return nil
}

func validateAppMCPUpdateDeclaration(tool AppMCPTool) error {
	input, output := tool.InputSchema, tool.OutputSchema
	if input == nil || input.Type != "object" || input.AdditionalProperties == nil || *input.AdditionalProperties ||
		len(input.Properties) != 2 || !sameStrings(input.Required, []string{"id", "data"}) {
		return errors.New("write input must be a closed object requiring exactly id and data")
	}
	id := input.Properties["id"]
	data := input.Properties["data"]
	if id == nil || data == nil || data.Type != "object" || data.AdditionalProperties == nil || *data.AdditionalProperties || len(data.Properties) == 0 {
		return errors.New("write input requires an id and a nonempty closed data object")
	}
	if !((id.Type == "integer" && id.Minimum != nil && *id.Minimum == 1 && id.Maximum != nil && *id.Maximum == 9007199254740991) ||
		(id.Type == "string" && id.MinLength != nil && *id.MinLength == 1 && id.MaxLength != nil && *id.MaxLength == 128)) {
		return errors.New("write id must use the bounded integer or string key schema")
	}
	// Canonical writes keep their own null handling (type "null" for a nullable
	// column); a nullable-typed field would widen what the SQL binding accepts.
	if appMCPSchemaAnyNullable(input) || appMCPSchemaAnyNullable(output) {
		return errors.New("canonical write schemas do not accept nullable types")
	}
	if err := validateBoundedUpdateSchema(data, 0); err != nil {
		return fmt.Errorf("data schema: %w", err)
	}
	for name, schema := range data.Properties {
		if name == "id" || strings.HasPrefix(name, "_") || schema == nil {
			return fmt.Errorf("data schema contains a non-writable field %q", name)
		}
		switch schema.Type {
		case "string", "boolean", "integer", "number", "null":
		default:
			return fmt.Errorf("data field %q must use a scalar SQL binding", name)
		}
	}
	if output == nil || output.Type != "object" || output.AdditionalProperties == nil || *output.AdditionalProperties ||
		len(output.Properties) == 0 || len(tool.Output.Include) != len(output.Properties) || len(output.Required) != len(output.Properties) {
		return errors.New("write output must be a closed, fully required projected row")
	}
	if !sameStrings(output.Required, tool.Output.Include) || !slices.Contains(tool.Output.Include, "id") {
		return errors.New("write output projection must exactly match required output fields and include id")
	}
	if !sameKeySchema(id, output.Properties["id"]) {
		return errors.New("write output id schema must match its input key schema")
	}
	for name, schema := range output.Properties {
		if !slices.Contains(tool.Output.Include, name) || schema == nil {
			return fmt.Errorf("output schema contains an unprojected field %q", name)
		}
		if err := validateBoundedUpdateSchema(schema, 0); err != nil {
			return fmt.Errorf("output schema field %q: %w", name, err)
		}
	}
	return nil
}

func appMCPSchemaAnyNullable(schema *AppMCPSchema) bool {
	if schema == nil {
		return false
	}
	if schema.Nullable || appMCPSchemaAnyNullable(schema.Items) {
		return true
	}
	for _, child := range schema.Properties {
		if appMCPSchemaAnyNullable(child) {
			return true
		}
	}
	return false
}

func validateBoundedUpdateSchema(schema *AppMCPSchema, depth int) error {
	if schema == nil || depth > 32 {
		return errors.New("missing schema or excessive nesting")
	}
	switch schema.Type {
	case "string":
		if schema.MaxLength == nil {
			return errors.New("strings require a finite maxLength")
		}
	case "number", "integer":
		if schema.Minimum == nil || schema.Maximum == nil {
			return errors.New("numbers require finite minimum and maximum")
		}
	case "array":
		if schema.MaxItems == nil || schema.Items == nil {
			return errors.New("arrays require finite maxItems and item schema")
		}
		return validateBoundedUpdateSchema(schema.Items, depth+1)
	case "object":
		if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
			return errors.New("objects must reject additional properties")
		}
		for _, child := range schema.Properties {
			if err := validateBoundedUpdateSchema(child, depth+1); err != nil {
				return err
			}
		}
	case "boolean", "null":
	default:
		return errors.New("unsupported schema type")
	}
	return nil
}

func sameKeySchema(input, output *AppMCPSchema) bool {
	if input == nil || output == nil || input.Type != output.Type {
		return false
	}
	if input.Type == "integer" {
		return input.Minimum != nil && input.Maximum != nil && output.Minimum != nil && output.Maximum != nil &&
			*input.Minimum == *output.Minimum && *input.Maximum == *output.Maximum
	}
	return input.Type == "string" && input.MinLength != nil && input.MaxLength != nil && output.MinLength != nil && output.MaxLength != nil &&
		*input.MinLength == *output.MinLength && *input.MaxLength == *output.MaxLength
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, value := range a {
		seen[value]++
	}
	for _, value := range b {
		seen[value]--
	}
	for _, count := range seen {
		if count != 0 {
			return false
		}
	}
	return true
}

func appMCPUpdateIDValue(tool *AppMCPTool, value any) (string, error) {
	if tool == nil || tool.InputSchema == nil || tool.InputSchema.Properties["id"] == nil || validateAppMCPSchemaValue(tool.InputSchema.Properties["id"], value) != nil {
		return "", errors.New("invalid update id")
	}
	switch tool.InputSchema.Properties["id"].Type {
	case "string":
		id, ok := value.(string)
		if !ok || strings.TrimSpace(id) == "" {
			return "", errors.New("invalid update id")
		}
		return id, nil
	case "integer":
		n, ok := appMCPExactNumber(value)
		if !ok || !n.IsInt() || !n.Num().IsInt64() || n.Sign() <= 0 {
			return "", errors.New("invalid update id")
		}
		return n.Num().String(), nil
	default:
		return "", errors.New("unsupported update id")
	}
}

func validateAppMCPUpdateInput(tool *AppMCPTool, input map[string]any) (string, map[string]any, error) {
	if tool == nil || input == nil || validateAppMCPSchemaValue(tool.InputSchema, input) != nil {
		return "", nil, errors.New("invalid update input")
	}
	data, ok := input["data"].(map[string]any)
	if !ok || len(data) == 0 {
		return "", nil, errors.New("update data must be a nonempty object")
	}
	id, err := appMCPUpdateIDValue(tool, input["id"])
	if err != nil {
		return "", nil, err
	}
	return id, data, nil
}
