//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Candidate files are deliberately not mcp.yaml: neither HTTP method nor a
// generated contract supplies permission, effects, projection or approval.
type appMCPOpenAPICandidate struct {
	Name           string         `json:"name"`
	OperationID    string         `json:"operation_id"`
	Method         string         `json:"method"`
	Path           string         `json:"path"`
	Enabled        bool           `json:"enabled"`
	State          string         `json:"state"`
	Reason         string         `json:"reason"`
	InputSchema    *AppMCPSchema  `json:"input_schema"`
	OutputSchema   *AppMCPSchema  `json:"output_schema"`
	Contract       map[string]any `json:"contract"`
	ReviewRequired []string       `json:"review_required"`
}
type appMCPOpenAPICandidates struct {
	CandidateVersion int                      `json:"mcp_candidate_version"`
	Enabled          bool                     `json:"enabled"`
	OpenAPI          string                   `json:"openapi"`
	Sources          []SourceManifestFile     `json:"sources"`
	Operations       []appMCPOpenAPICandidate `json:"operations"`
}
type appMCPOpenAPIReader struct {
	root          *os.Root
	documents     map[string]map[string]any
	sources       map[string]SourceManifestFile
	bytes         int64
	nodes         int
	expandedBytes int64
}

func generateAppMCPCandidates(dir, document, output string) error {
	if !utf8.ValidString(dir) || !utf8.ValidString(document) || !utf8.ValidString(output) {
		return fmt.Errorf("candidate file paths must be valid UTF-8")
	}
	appRoot, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("invalid appdir")
	}
	root, err := os.OpenRoot(appRoot)
	if err != nil {
		return fmt.Errorf("cannot open appdir")
	}
	defer root.Close()
	input, err := filepath.Abs(document)
	if err != nil {
		return fmt.Errorf("invalid OpenAPI file")
	}
	relative, err := filepath.Rel(appRoot, input)
	if err != nil || !filepath.IsLocal(relative) {
		return fmt.Errorf("OpenAPI file must be inside appdir")
	}
	reader := &appMCPOpenAPIReader{root: root, documents: map[string]map[string]any{}, sources: map[string]SourceManifestFile{}}
	candidates, err := reader.generate(filepath.ToSlash(relative))
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(candidates, "", "  ")
	if err != nil || len(data) > yamlMaxBytes {
		return fmt.Errorf("candidate output exceeds supported size")
	}
	data = append(data, '\n')
	if strings.EqualFold(filepath.Base(output), "mcp.yaml") {
		return fmt.Errorf("candidate output cannot be the live mcp.yaml")
	}
	// Open the existing parent only; no directories or other outputs are created.
	parent, err := os.OpenRoot(filepath.Dir(output))
	if err != nil {
		return fmt.Errorf("candidate output parent must exist")
	}
	defer parent.Close()
	file, err := parent.OpenFile(filepath.Base(output), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("candidate output must not already exist")
	}
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("candidate output write failed; inspect the explicit output before retrying")
	}
	return nil
}

func (reader *appMCPOpenAPIReader) load(path string) (map[string]any, error) {
	if document := reader.documents[path]; document != nil {
		return document, nil
	}
	if !utf8.ValidString(path) || !filepath.IsLocal(filepath.FromSlash(path)) || len(reader.documents) >= 64 {
		return nil, fmt.Errorf("OpenAPI reference path or file limit exceeded")
	}
	if appMCPOpenAPIUnreviewedSource(path) {
		return nil, fmt.Errorf("OpenAPI sources must be reviewed app source files, not secrets, runtime data or tool directories")
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".yaml", ".yml":
	default:
		return nil, fmt.Errorf("OpenAPI references require local JSON/YAML files")
	}
	sourceInfo, statErr := reader.root.Lstat(filepath.FromSlash(path))
	if statErr != nil || !sourceInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("OpenAPI source must be a regular file without symlink aliases")
	}
	file, err := reader.root.Open(filepath.FromSlash(path))
	if err != nil {
		return nil, fmt.Errorf("cannot open local OpenAPI source")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("OpenAPI source must be a regular file")
	}
	// ponytail: 8 MiB per file, 64 MiB total, 64 files and 100000 expanded nodes and 8 MiB of expanded strings;
	// raise these only for a reviewed contract that needs a larger bounded input.
	data, err := io.ReadAll(io.LimitReader(file, yamlMaxBytes+1))
	closeErr := file.Close()
	reader.bytes += int64(len(data))
	if err != nil || closeErr != nil || len(data) > yamlMaxBytes || reader.bytes > 64<<20 {
		return nil, fmt.Errorf("OpenAPI source byte limit exceeded")
	}
	if err := checkYAMLShape(data); err != nil {
		return nil, fmt.Errorf("unsupported OpenAPI document shape")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if decoder.Decode(&node) != nil || len(node.Content) != 1 || decoder.Decode(new(yaml.Node)) != io.EOF {
		return nil, fmt.Errorf("OpenAPI source must contain one document")
	}
	value, err := appMCPOpenAPIJSON(node.Content[0], 0)
	if err != nil {
		return nil, err
	}
	document, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenAPI source must be an object")
	}
	reader.documents[path] = document
	reader.sources[path] = SourceManifestFile{Path: path, SHA256: hashBytesSHA256(data), Size: int64(len(data))}
	return document, nil
}

// appMCPOpenAPIUnreviewedSource reports a path the execution digest never binds
// (env.yaml, secrets.yaml, keys, data.db, uploads/, .benmore/, .git/ and the
// other appMCPSourceDigests exclusions, plus mcp.yaml itself), so a pinned
// document cannot copy their bytes into a candidate or a validation pass.
func appMCPOpenAPIUnreviewedSource(path string) bool {
	if path == "mcp.yaml" {
		return true
	}
	if path == "static" || strings.HasPrefix(path, "static/") || path == "flows" || strings.HasPrefix(path, "flows/") {
		return false // digested whole, like the walk's executable trees
	}
	parts := strings.Split(path, "/")
	for i := range parts {
		if sourceManifestExcluded(strings.Join(parts[:i+1], "/"), i < len(parts)-1) {
			return true
		}
	}
	return false
}

// YAML supplies the existing bounded parser. Preserve JSON number lexemes and
// reject duplicate keys/aliases/non-JSON scalars before a map can discard them.
func appMCPOpenAPIJSON(node *yaml.Node, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("OpenAPI nesting limit exceeded")
	}
	switch node.Kind {
	case yaml.MappingNode:
		out := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Tag != "!!str" {
				return nil, fmt.Errorf("OpenAPI object keys must be strings")
			}
			if _, duplicate := out[key.Value]; duplicate {
				return nil, fmt.Errorf("duplicate OpenAPI object key")
			}
			value, err := appMCPOpenAPIJSON(node.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			out[key.Value] = value
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, len(node.Content))
		for i, child := range node.Content {
			value, err := appMCPOpenAPIJSON(child, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = value
		}
		return out, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			return node.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			if node.Value == "true" {
				return true, nil
			}
			if node.Value == "false" {
				return false, nil
			}
		case "!!int", "!!float":
			number := json.Number(node.Value)
			if json.Valid([]byte(node.Value)) {
				if _, ok := appMCPExactNumber(number); ok {
					return number, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("OpenAPI aliases or non-JSON scalar values are unsupported")
}

func (reader *appMCPOpenAPIReader) resolve(value any, current string, stack map[string]bool, depth int, kind string) (any, error) {
	reader.nodes++
	switch v := value.(type) {
	case string:
		reader.expandedBytes += int64(len(v))
	case json.Number:
		reader.expandedBytes += int64(len(v))
	case map[string]any:
		for key := range v {
			reader.expandedBytes += int64(len(key))
		}
	}
	if reader.expandedBytes > yamlMaxBytes {
		return nil, fmt.Errorf("OpenAPI expanded string byte limit exceeded")
	}
	if depth > 32 || reader.nodes > 100000 {
		return nil, fmt.Errorf("OpenAPI expanded reference limit exceeded")
	}
	switch v := value.(type) {
	case map[string]any:
		if kind == "schema" {
			for _, key := range []string{"$id", "$anchor", "$dynamicRef", "$dynamicAnchor"} {
				if _, ok := v[key]; ok {
					return nil, fmt.Errorf("OpenAPI schema base URI/dynamic anchors are unsupported")
				}
			}
		}
		if raw, ok := v["$ref"]; ok && (kind == "schema" || kind == "path_item" || kind == "parameter" || kind == "request_body" || kind == "response" || kind == "example" || kind == "header" || kind == "link" || kind == "callback") {
			ref, ok := raw.(string)
			if !ok || len(v) != 1 {
				return nil, fmt.Errorf("OpenAPI reference siblings are unsupported")
			}
			uri, err := url.Parse(ref)
			if err != nil || uri.IsAbs() || uri.Host != "" || uri.User != nil || uri.RawQuery != "" || strings.ContainsAny(uri.Path, "\\\x00") || strings.HasPrefix(uri.Path, "/") {
				return nil, fmt.Errorf("OpenAPI references must be local relative files or JSON pointers")
			}
			target := current
			if uri.Path != "" {
				target = filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(current), filepath.FromSlash(uri.Path))))
			}
			document, err := reader.load(target)
			if err != nil {
				return nil, err
			}
			identity := target + "#" + uri.Fragment
			if stack[identity] {
				return nil, fmt.Errorf("recursive OpenAPI references are unsupported")
			}
			selected, err := appMCPOpenAPIPointer(document, uri.Fragment, kind == "schema")
			if err != nil {
				return nil, err
			}
			stack[identity] = true
			result, err := reader.resolve(selected, target, stack, depth+1, kind)
			delete(stack, identity)
			return result, err
		}
		out := make(map[string]any, len(v))
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			item, err := reader.resolve(v[key], current, stack, depth+1, appMCPOpenAPIChildKind(kind, key))
			if err != nil {
				return nil, err
			}
			out[key] = item
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			resolved, err := reader.resolve(item, current, stack, depth+1, appMCPOpenAPIChildKind(kind, ""))
			if err != nil {
				return nil, err
			}
			out[i] = resolved
		}
		return out, nil
	default:
		return value, nil
	}
}

// Object position determines whether $ref is syntax or literal JSON data.
// Property-name maps, enum values and Example Object values must stay literal.
func appMCPOpenAPIChildKind(kind, key string) string {
	switch kind {
	case "document":
		switch key {
		case "components":
			return "components"
		case "paths", "webhooks":
			return "path_item_map"
		}
	case "components":
		switch key {
		case "schemas":
			return "schema_map"
		case "examples":
			return "example_map"
		case "responses":
			return "response_map"
		case "parameters":
			return "parameter_list"
		case "requestBodies":
			return "request_body_map"
		case "headers":
			return "header_map"
		case "links":
			return "link_map"
		case "callbacks":
			return "callback_map"
		case "pathItems":
			return "path_item_map"
		}
	case "path_item":
		switch key {
		case "get", "put", "post", "delete", "options", "head", "patch", "trace":
			return "operation"
		case "parameters":
			return "parameter_list"
		}
	case "operation":
		switch key {
		case "parameters":
			return "parameter_list"
		case "requestBody":
			return "request_body"
		case "responses":
			return "response_map"
		case "callbacks":
			return "callback_map"
		}
	case "schema":
		switch key {
		case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas":
			return "schema_map"
		case "items", "additionalProperties", "contains", "not", "if", "then", "else", "propertyNames", "unevaluatedProperties", "unevaluatedItems":
			return "schema"
		case "allOf", "anyOf", "oneOf", "prefixItems":
			return "schema_list"
		}
	case "parameter", "header":
		switch key {
		case "content":
			return "media_map"
		case "schema":
			return "schema"
		case "examples":
			return "example_map"
		}
	case "request_body":
		if key == "content" {
			return "media_map"
		}
	case "response":
		switch key {
		case "content":
			return "media_map"
		case "headers":
			return "header_map"
		case "links":
			return "link_map"
		}
	case "media_type":
		switch key {
		case "schema":
			return "schema"
		case "examples":
			return "example_map"
		}
	case "parameter_list":
		return "parameter"
	case "schema_map", "schema_list":
		return "schema"
	case "response_map":
		return "response"
	case "media_map":
		return "media_type"
	case "example_map":
		return "example"
	case "header_map":
		return "header"
	case "link_map":
		return "link"
	case "request_body_map":
		return "request_body"
	case "path_item_map", "callback":
		return "path_item"
	case "callback_map":
		return "callback"
	}
	return "literal"
}

func appMCPOpenAPIPointer(document map[string]any, pointer string, schemaBase bool) (any, error) {
	var value any = document
	kind := "schema"
	if _, openAPI := document["openapi"]; openAPI {
		kind = "document"
	}
	if pointer == "" {
		return value, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("OpenAPI reference requires a JSON pointer")
	}
	for _, part := range strings.Split(pointer[1:], "/") {
		if schemaBase && kind == "schema" {
			if ancestor, ok := value.(map[string]any); ok {
				for _, key := range []string{"$id", "$anchor", "$dynamicRef", "$dynamicAnchor"} {
					if _, isBase := ancestor[key].(string); isBase {
						return nil, fmt.Errorf("OpenAPI referenced schema has unsupported ancestor base URI/anchor")
					}
				}
			}
		}

		// Reject invalid escape sequences instead of interpreting a different key.
		for i := 0; i < len(part); i++ {
			if part[i] == '~' {
				if i+1 >= len(part) || (part[i+1] != '0' && part[i+1] != '1') {
					return nil, fmt.Errorf("invalid OpenAPI JSON pointer")
				}
				i++
			}
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		kind = appMCPOpenAPIChildKind(kind, part)
		switch object := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = object[part]
			if !ok {
				return nil, fmt.Errorf("unresolved OpenAPI JSON pointer")
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(object) || strconv.Itoa(index) != part {
				return nil, fmt.Errorf("unresolved OpenAPI array pointer")
			}
			value = object[index]
		default:
			return nil, fmt.Errorf("unresolved OpenAPI JSON pointer")
		}
	}
	return value, nil
}
func validateAppMCPOpenAPISchemaKeywords(value any, depth int) error {
	object, ok := value.(map[string]any)
	if !ok || depth > 32 {
		return fmt.Errorf("OpenAPI schema must be an object within the nesting limit")
	}
	for key := range object {
		switch key {
		case "type", "description", "properties", "required", "additionalProperties", "items", "enum", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems":
		default:
			return fmt.Errorf("unsupported exact OpenAPI schema keyword %q", key)
		}
	}
	if enum, present := object["enum"]; present {
		values, ok := enum.([]any)
		if !ok || len(values) == 0 {
			return fmt.Errorf("OpenAPI enum must be a nonempty array")
		}
	}
	if raw, present := object["properties"]; present {
		properties, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("OpenAPI properties must be an object")
		}
		for _, child := range properties {
			if err := validateAppMCPOpenAPISchemaKeywords(child, depth+1); err != nil {
				return err
			}
		}
	}
	if child, present := object["items"]; present {
		return validateAppMCPOpenAPISchemaKeywords(child, depth+1)
	}
	return nil
}

// Keywords that never change validation (JSON Schema 2020-12 annotations,
// format included); dropping them cannot weaken a generated schema.
var appMCPOpenAPIAnnotations = []string{"format", "title", "example", "examples", "deprecated", "readOnly", "writeOnly", "externalDocs", "xml", "$comment", "contentMediaType", "contentEncoding"}

// appMCPOpenAPINormalize returns a copy of an OpenAPI schema without
// annotations, and whether it was nullable (`nullable: true` or
// `type: [X, "null"]`, rewritten to `type: X`). Only an optional object
// property of an INPUT schema may be nullable (an omitted optional input is
// what null means there); a nullable output would reject the upstream's real
// null replies under strict output validation, so it is refused, as is any
// other placement or a non-boolean `nullable`.
func appMCPOpenAPINormalize(value any, depth int, input bool) (any, bool, error) {
	object, ok := value.(map[string]any)
	if !ok || depth > 32 {
		return value, false, nil // validateAppMCPOpenAPISchemaKeywords reports it
	}
	out := make(map[string]any, len(object))
	for key, v := range object {
		out[key] = v
	}
	for _, key := range appMCPOpenAPIAnnotations {
		delete(out, key)
	}
	if raw, present := out["nullable"]; present {
		if _, isBool := raw.(bool); !isBool {
			return nil, false, fmt.Errorf("OpenAPI nullable must be a boolean")
		}
	}
	nullable := out["nullable"] == true
	delete(out, "nullable")
	if types, isList := out["type"].([]any); isList && len(types) == 2 {
		for i, t := range types {
			if t == "null" && types[1-i] != "null" {
				out["type"], nullable = types[1-i], true
			}
		}
	}
	if properties, isMap := out["properties"].(map[string]any); isMap {
		required, _ := out["required"].([]any)
		children := make(map[string]any, len(properties))
		for name, raw := range properties {
			child, childNullable, err := appMCPOpenAPINormalize(raw, depth+1, input)
			if err != nil {
				return nil, false, err
			}
			if childNullable && !input {
				return nil, false, fmt.Errorf("OpenAPI response property %q is nullable; exact generation validates output strictly and cannot represent null", name)
			}
			if childNullable {
				for _, r := range required {
					if r == name {
						return nil, false, fmt.Errorf("OpenAPI property %q is required and nullable; exact generation cannot represent null, make it optional or non-null", name)
					}
				}
			}
			children[name] = child
		}
		out["properties"] = children
	}
	if raw, present := out["items"]; present {
		child, childNullable, err := appMCPOpenAPINormalize(raw, depth+1, input)
		if err != nil {
			return nil, false, err
		}
		if childNullable {
			return nil, false, fmt.Errorf("OpenAPI nullable array items are unsupported by exact generation")
		}
		out["items"] = child
	}
	return out, nullable, nil
}

func appMCPOpenAPISchema(value any) (*AppMCPSchema, error) {
	return appMCPOpenAPISchemaFor(value, true)
}

func appMCPOpenAPISchemaFor(value any, input bool) (*AppMCPSchema, error) {
	value, nullable, err := appMCPOpenAPINormalize(value, 0, input)
	if err != nil {
		return nil, err
	}
	if nullable {
		return nil, fmt.Errorf("OpenAPI nullable schema is only supported on an optional object property")
	}
	if err := validateAppMCPOpenAPISchemaKeywords(value, 0); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil || value == nil {
		return nil, fmt.Errorf("OpenAPI schema is missing")
	}
	var node yaml.Node
	if yaml.Unmarshal(raw, &node) != nil || validateAppMCPYAMLNode(node.Content[0], 0, false) != nil {
		return nil, fmt.Errorf("OpenAPI schema contains unsupported null or scalar keywords")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var schema AppMCPSchema
	if decoder.Decode(&schema) != nil {
		return nil, fmt.Errorf("OpenAPI schema uses unsupported keywords")
	}
	if err := validateAppMCPSchema(&schema, 0); err != nil {
		return nil, fmt.Errorf("unsupported OpenAPI schema: %w", err)
	}
	if err := appMCPOpenAPISchemaNumbers(&schema, value); err != nil {
		return nil, err
	}

	return &schema, nil
}
func appMCPOpenAPISchemaNumbers(schema *AppMCPSchema, value any) error {
	original, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("OpenAPI schema must be an object")
	}
	for key, bound := range map[string]*float64{"minimum": schema.Minimum, "maximum": schema.Maximum} {
		if bound != nil {
			before, valid := appMCPExactNumber(original[key])
			after, exact := appMCPExactNumber(*bound)
			if !valid || !exact || before.Cmp(after) != 0 {
				return fmt.Errorf("OpenAPI numeric bound cannot be represented exactly")
			}
		}
	}
	properties, _ := original["properties"].(map[string]any)
	for key, child := range schema.Properties {
		if err := appMCPOpenAPISchemaNumbers(child, properties[key]); err != nil {
			return err
		}
	}
	if schema.Items != nil {
		return appMCPOpenAPISchemaNumbers(schema.Items, original["items"])
	}
	return nil
}
func appMCPOpenAPIContent(value any) (*AppMCPSchema, error) {
	return appMCPOpenAPIContentFor(value, true)
}

func appMCPOpenAPIContentFor(value any, input bool) (*AppMCPSchema, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenAPI body/response must be an object")
	}
	content, ok := object["content"].(map[string]any)
	if !ok || len(content) != 1 {
		return nil, fmt.Errorf("OpenAPI candidate requires exactly application/json content")
	}
	media, ok := content["application/json"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenAPI candidate requires application/json schema")
	}
	return appMCPOpenAPISchemaFor(media["schema"], input)
}
func appMCPOpenAPIInputs(pathParameters any, operation map[string]any) (*AppMCPSchema, error) {
	reject := false
	input := &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{}, AdditionalProperties: &reject}
	parameters := map[string]map[string]any{}
	for _, group := range []any{pathParameters, operation["parameters"]} {
		if group == nil {
			continue
		}
		list, ok := group.([]any)
		if !ok {
			return nil, fmt.Errorf("OpenAPI parameters must be an array")
		}
		seen := map[string]bool{}
		for _, raw := range list {
			parameter, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("OpenAPI parameter must be an object")
			}
			name, _ := parameter["name"].(string)
			location, _ := parameter["in"].(string)
			key := location + ":" + name
			if name == "" || location == "" || seen[key] {
				return nil, fmt.Errorf("duplicate or unnamed OpenAPI parameter")
			}
			seen[key] = true
			parameters[key] = parameter
		}
	}
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parameter := parameters[key]
		name := parameter["name"].(string)
		location := parameter["in"].(string)
		switch location {
		case "path", "query", "header", "cookie":
		default:
			return nil, fmt.Errorf("unsupported OpenAPI parameter location")
		}
		if _, exists := parameter["content"]; exists {
			return nil, fmt.Errorf("OpenAPI parameter content encoding is unsupported")
		}
		if raw, exists := parameter["required"]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, fmt.Errorf("OpenAPI required must be boolean")
			}
		}
		schema, err := appMCPOpenAPISchema(parameter["schema"])
		if err != nil {
			return nil, err
		}
		required, _ := parameter["required"].(bool)
		if location == "path" && !required {
			return nil, fmt.Errorf("OpenAPI path parameter must be required")
		}
		object := input.Properties[location]
		if object == nil {
			object = &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{}, AdditionalProperties: &reject}
			input.Properties[location] = object
		}
		object.Properties[name] = schema
		if required {
			object.Required = append(object.Required, name)
		}
	}
	locations := make([]string, 0, len(input.Properties))
	for location, object := range input.Properties {
		if len(object.Required) > 0 {
			locations = append(locations, location)
		}
	}
	sort.Strings(locations)
	input.Required = locations
	if body, exists := operation["requestBody"]; exists {
		schema, err := appMCPOpenAPIContent(body)
		if err != nil {
			return nil, err
		}
		input.Properties["body"] = schema
		object := body.(map[string]any)
		if raw, exists := object["required"]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, fmt.Errorf("OpenAPI required must be boolean")
			}
		}
		required, _ := object["required"].(bool)
		if required {
			input.Required = append(input.Required, "body")
		}
	}
	return input, nil
}
func validateAppMCPOpenAPIPath(route string, input *AppMCPSchema) error {
	if !strings.HasPrefix(route, "/") || strings.ContainsAny(route, "?#\\\x00") {
		return fmt.Errorf("OpenAPI path must be a relative slash-prefixed path without query or fragment")
	}
	declared := map[string]bool{}
	for i := 0; i < len(route); i++ {
		if route[i] == '}' {
			return fmt.Errorf("invalid OpenAPI path template")
		}
		if route[i] != '{' {
			continue
		}
		end := strings.IndexByte(route[i+1:], '}')
		if end < 1 {
			return fmt.Errorf("invalid OpenAPI path template")
		}
		end += i + 1
		name := route[i+1 : end]
		if strings.ContainsAny(name, "{/") {
			return fmt.Errorf("invalid OpenAPI path template")
		}
		object := input.Properties["path"]
		if object == nil || object.Properties[name] == nil {
			return fmt.Errorf("OpenAPI path template needs a declared required parameter")
		}
		declared[name] = true
		i = end
	}
	if object := input.Properties["path"]; object != nil {
		for name := range object.Properties {
			if !declared[name] {
				return fmt.Errorf("OpenAPI path parameter is absent from the path template")
			}
		}
	}
	return nil
}
func (reader *appMCPOpenAPIReader) generate(path string) (*appMCPOpenAPICandidates, error) {
	document, err := reader.load(path)
	if err != nil {
		return nil, err
	}
	version, _ := document["openapi"].(string)
	parts := strings.Split(version, ".")
	if len(parts) != 3 || parts[0] != "3" || (parts[1] != "0" && parts[1] != "1") {
		return nil, fmt.Errorf("only OpenAPI 3.0/3.1 documents are supported")
	}
	if patch, err := strconv.ParseUint(parts[2], 10, 32); err != nil || strconv.FormatUint(patch, 10) != parts[2] {
		return nil, fmt.Errorf("invalid OpenAPI version")
	}
	if _, exists := document["webhooks"]; exists {
		return nil, fmt.Errorf("OpenAPI webhook candidates are unsupported")
	}
	if _, exists := document["jsonSchemaDialect"]; exists {
		return nil, fmt.Errorf("OpenAPI custom schema dialects are unsupported")
	}
	paths, ok := document["paths"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenAPI paths must be an object")
	}
	result := &appMCPOpenAPICandidates{CandidateVersion: 1, OpenAPI: version, Operations: []appMCPOpenAPICandidate{}}
	names := map[string]bool{}
	routes := make([]string, 0, len(paths))
	for route := range paths {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	for _, route := range routes {
		if !strings.HasPrefix(route, "/") {
			return nil, fmt.Errorf("OpenAPI path must start with slash")
		}
		raw, err := reader.resolve(paths[route], path, map[string]bool{}, 0, "path_item")
		if err != nil {
			return nil, err
		}
		item, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("OpenAPI path item must be an object")
		}
		for _, method := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"} {
			raw, exists := item[method]
			if !exists {
				continue
			}
			operation, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("OpenAPI operation must be an object")
			}
			if _, exists := operation["callbacks"]; exists {
				return nil, fmt.Errorf("OpenAPI callback candidates are unsupported")
			}
			id, _ := operation["operationId"].(string)
			name := strings.ToLower(id)
			if !appMCPName.MatchString(name) || names[name] {
				return nil, fmt.Errorf("OpenAPI operation needs a unique stable connector-compatible operationId")
			}
			names[name] = true
			input, err := appMCPOpenAPIInputs(item["parameters"], operation)
			if err != nil {
				return nil, err
			}
			if err := validateAppMCPOpenAPIPath(route, input); err != nil {
				return nil, err
			}
			responses, ok := operation["responses"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("OpenAPI operation requires responses")
			}
			codes := make([]string, 0, len(responses))
			for code := range responses {
				if len(code) == 3 && strings.ToUpper(code)[1:] == "XX" {
					return nil, fmt.Errorf("OpenAPI response ranges are unsupported")
				}
				if len(code) == 3 && code[0] == '2' {
					if status, err := strconv.Atoi(code); err == nil && status >= 200 && status <= 299 {
						codes = append(codes, code)
					}
				}
			}
			sort.Strings(codes)
			var output *AppMCPSchema
			var encoded []byte
			for _, code := range codes {
				schema, err := appMCPOpenAPIContentFor(responses[code], false)
				if err != nil {
					return nil, err
				}
				candidate, _ := json.Marshal(schema)
				if output != nil && !bytes.Equal(encoded, candidate) {
					return nil, fmt.Errorf("different success response schemas require unsupported union validation")
				}
				output = schema
				encoded = candidate
			}
			if output == nil {
				return nil, fmt.Errorf("OpenAPI candidate requires an explicit JSON success response")
			}
			contract := map[string]any{"operation": operation, "path_parameters": item["parameters"]}
			result.Operations = append(result.Operations, appMCPOpenAPICandidate{Name: name, OperationID: id, Method: strings.ToUpper(method), Path: route, State: "unresolved", Reason: "generated contract is not a reviewed or enabled handler", InputSchema: input, OutputSchema: output, Contract: contract, ReviewRequired: []string{"actual_handler_and_connection", "permissions", "effect", "approval", "idempotency", "reconciliation", "output_projection", "component"}})
		}
	}
	if len(result.Operations) == 0 {
		return nil, fmt.Errorf("OpenAPI document has no supported operations")
	}
	files := make([]string, 0, len(reader.sources))
	for file := range reader.sources {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		result.Sources = append(result.Sources, reader.sources[file])
	}
	return result, nil
}
