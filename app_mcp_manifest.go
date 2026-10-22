//go:build !cli

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// AppMCPManifest is an opt-in reviewed contract, not an exposure switch.
// No handler is enabled until registration and current grant checks succeed.
type AppMCPManifest struct {
	sourceHashes    map[string]string  // immutable fingerprints of bytes accepted during staging
	Version         int                `yaml:"version"`
	Connector       AppMCPIdentity     `yaml:"connector"`
	ContractDigest  string             `yaml:"contract_digest"`
	ExecutionDigest string             `yaml:"execution_digest"`
	Tools           []AppMCPTool       `yaml:"tools"`
	Resources       []AppMCPResource   `yaml:"resources"`
	Connections     []AppMCPConnection `yaml:"connections"`
	// external is the pinned OpenAPI operation of each external tool, captured
	// from the digested source bytes at load (validateAppMCPDeclaredSources).
	// Unexported: it is derived, never reviewed input, so digests are unchanged.
	external  map[string]*appMCPExternalOperation
	transfers map[string]*appMCPTransferOperations

	// ExecutionSources names what ExecutionDigest was made over: "runtime" (the
	// files the runtime can load, execute or serve) or empty (the whole tree,
	// the form of manifests reviewed before this field). Review writes "runtime".
	ExecutionSources string `yaml:"execution_sources,omitempty" json:",omitempty"`
}

// appMCPExternalConnectionsEnabled is the single gate for external OpenAPI-pinned
// tools. Read tools (effect: read) run through app_mcp_external.go; external
// write tools stay refused at load (validateAppMCPManifestGated).
const appMCPExternalConnectionsEnabled = true

// AppMCPConnection pins an external API: https base URL, an auth kind that names
// an environment variable (never a value), and the local OpenAPI file that
// defines every operation a tool may bind. New fields stay omitempty in JSON so
// manifests that do not use them keep their reviewed digests.
type AppMCPConnection struct {
	Name    string               `yaml:"name" json:"Name"`
	BaseURL string               `yaml:"base_url" json:"BaseURL"`
	Auth    AppMCPConnectionAuth `yaml:"auth" json:"Auth"`
	OpenAPI string               `yaml:"openapi" json:"OpenAPI"`
}
type AppMCPConnectionAuth struct {
	Kind   string `yaml:"kind" json:"Kind"`                         // none | bearer | header
	Env    string `yaml:"env,omitempty" json:"Env,omitempty"`       // environment variable NAME holding the credential
	Header string `yaml:"header,omitempty" json:"Header,omitempty"` // header name for kind: header
}
type AppMCPIdentity struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}
type AppMCPTool struct {
	Name           string           `yaml:"name"`
	Description    string           `yaml:"description"`
	Handler        AppMCPHandler    `yaml:"handler"`
	InputSchema    *AppMCPSchema    `yaml:"input_schema"`
	OutputSchema   *AppMCPSchema    `yaml:"output_schema"`
	Permissions    []string         `yaml:"permissions"`
	Effect         string           `yaml:"effect"`
	Approval       string           `yaml:"approval"`
	Idempotency    string           `yaml:"idempotency"`
	Reconciliation string           `yaml:"reconciliation"`
	Output         AppMCPProjection `yaml:"output"`
	Component      string           `yaml:"component"`
	Transfer       *AppMCPTransfer  `yaml:"transfer,omitempty" json:"Transfer,omitempty"`
	// Human-facing review text of a flow command tool (app_mcp_review_fields.go).
	// Reviewed content, so part of the contract digest; omitempty keeps the
	// digest of every manifest that declares none.
	Title         string             `yaml:"title,omitempty" json:",omitempty"`
	ReviewSummary string             `yaml:"review_summary,omitempty" json:",omitempty"`
	Labels        map[string]string  `yaml:"labels,omitempty" json:",omitempty"`
	ReviewChanges []AppMCPReviewPair `yaml:"review_changes,omitempty" json:",omitempty"`
	// Layout of the spreadsheet, report or PDF artifact.create may make from this
	// read tool's result (app_mcp_artifact_read.go). Reviewed content, so part of
	// the contract digest; a nil pointer is omitted, keeping every other digest.
	Artifact *AppMCPArtifactDecl `yaml:"artifact,omitempty" json:",omitempty"`
}

type AppMCPTransfer struct {
	Kind                    string `yaml:"kind" json:"Kind"`
	Connection              string `yaml:"connection" json:"Connection"`
	OperationID             string `yaml:"operation_id" json:"OperationID"`
	SelectorIntentPath      string `yaml:"selector_intent_path,omitempty" json:"SelectorIntentPath,omitempty"`
	SelectorParameter       string `yaml:"selector_parameter,omitempty" json:"SelectorParameter,omitempty"`
	ContentField            string `yaml:"content_field,omitempty" json:"ContentField,omitempty"`
	MIMEField               string `yaml:"mime_field,omitempty" json:"MIMEField,omitempty"`
	ExpectedMIME            string `yaml:"expected_mime,omitempty" json:"ExpectedMIME,omitempty"`
	RevisionField           string `yaml:"revision_field,omitempty" json:"RevisionField,omitempty"`
	ChecksumField           string `yaml:"checksum_field,omitempty" json:"ChecksumField,omitempty"`
	AttachTool              string `yaml:"attach_tool,omitempty" json:"AttachTool,omitempty"`
	RecordIDIntentPath      string `yaml:"record_id_intent_path,omitempty" json:"RecordIDIntentPath,omitempty"`
	FileColumn              string `yaml:"file_column,omitempty" json:"FileColumn,omitempty"`
	ArtifactIntentPath      string `yaml:"artifact_intent_path,omitempty" json:"ArtifactIntentPath,omitempty"`
	RequestContentField     string `yaml:"request_content_field,omitempty" json:"RequestContentField,omitempty"`
	RequestIdempotencyField string `yaml:"request_idempotency_field,omitempty" json:"RequestIdempotencyField,omitempty"`
	ReconcileOperationID    string `yaml:"reconcile_operation_id,omitempty" json:"ReconcileOperationID,omitempty"`
	ReconcileParameter      string `yaml:"reconcile_parameter,omitempty" json:"ReconcileParameter,omitempty"`
	ResultIDField           string `yaml:"result_id_field,omitempty" json:"ResultIDField,omitempty"`
	ResultChecksumField     string `yaml:"result_checksum_field,omitempty" json:"ResultChecksumField,omitempty"`
}
type AppMCPHandler struct {
	Kind      string `yaml:"kind"`
	Operation string `yaml:"operation"`
	Table     string `yaml:"table"`
	Flow      string `yaml:"flow"`
	// External read handler: kind: external, connection, operation_id.
	Connection  string `yaml:"connection,omitempty" json:",omitempty"`
	OperationID string `yaml:"operation_id,omitempty" json:",omitempty"`
}
type AppMCPProjection struct {
	Include []string `yaml:"include"`
}
type AppMCPResource struct {
	Name      string `yaml:"name"`
	URI       string `yaml:"uri"`
	MIMEType  string `yaml:"mime_type"`
	Component string `yaml:"component"`
	// Reviewed component declaration, published by app_mcp_resources.go.
	Entrypoint    string        `yaml:"entrypoint,omitempty" json:",omitempty"`     // path under static/
	Tools         []string      `yaml:"tools,omitempty" json:",omitempty"`          // permitted tool names
	DataSchema    *AppMCPSchema `yaml:"data_schema,omitempty" json:",omitempty"`    // shape of the data the component renders
	SchemaVersion int           `yaml:"schema_version,omitempty" json:",omitempty"` // version of data_schema
	DeepLink      string        `yaml:"deep_link,omitempty" json:",omitempty"`      // token-free app-relative template
}

// This is the supported v1 JSON Schema subset. Unknown keywords fail decoding;
// accepting a keyword we cannot enforce would silently weaken the contract.
type AppMCPSchema struct {
	Type string `yaml:"type" json:"type"`
	// Nullable is the one normalized form of both accepted spellings,
	// `type: [X, "null"]` and `nullable: true`. Clients are shown the standard
	// JSON Schema `type: [X, "null"]` (MarshalJSON); Type itself stays X.
	Nullable             bool                     `yaml:"nullable,omitempty" json:"-"`
	Description          string                   `yaml:"description,omitempty" json:"description,omitempty"`
	Properties           map[string]*AppMCPSchema `yaml:"properties,omitempty" json:"properties,omitempty"`
	Required             []string                 `yaml:"required,omitempty" json:"required,omitempty"`
	AdditionalProperties *bool                    `yaml:"additionalProperties,omitempty" json:"additionalProperties,omitempty"`
	Items                *AppMCPSchema            `yaml:"items,omitempty" json:"items,omitempty"`
	Enum                 []any                    `yaml:"enum,omitempty" json:"enum,omitempty"`
	Minimum              *float64                 `yaml:"minimum,omitempty" json:"minimum,omitempty"`
	Maximum              *float64                 `yaml:"maximum,omitempty" json:"maximum,omitempty"`
	MinLength            *int                     `yaml:"minLength,omitempty" json:"minLength,omitempty"`
	MaxLength            *int                     `yaml:"maxLength,omitempty" json:"maxLength,omitempty"`
	MinItems             *int                     `yaml:"minItems,omitempty" json:"minItems,omitempty"`
	MaxItems             *int                     `yaml:"maxItems,omitempty" json:"maxItems,omitempty"`
}

// appMCPSchemaYAMLKeys is derived from the struct tags so the strict unknown-key
// check in UnmarshalYAML cannot drift from the supported keyword set.
var appMCPSchemaYAMLKeys = func() map[string]bool {
	keys := map[string]bool{}
	t := reflect.TypeOf(AppMCPSchema{})
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		keys[name] = true
	}
	return keys
}()

// UnmarshalYAML keeps the decoder's strict-keyword contract (KnownFields does
// not reach a custom unmarshaler) and accepts exactly the two nullable
// spellings: `nullable: true` and `type: [X, "null"]` / `["null", X]`.
func (s *AppMCPSchema) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: schema must be a mapping", node.Line)
	}
	type plain AppMCPSchema
	rewritten := *node
	rewritten.Content = append([]*yaml.Node(nil), node.Content...)
	nullableType, nullableKey := false, false
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || !appMCPSchemaYAMLKeys[key.Value] {
			return fmt.Errorf("line %d: field %q not found in type main.AppMCPSchema", key.Line, key.Value)
		}
		if key.Value == "nullable" {
			nullableKey = true
		}
		if key.Value != "type" || value.Kind != yaml.SequenceNode {
			continue
		}
		union := fmt.Errorf("line %d: union types are unsupported; use [<type>, \"null\"]", value.Line)
		// Both members must be strings: an unquoted null is a !!null node whose
		// text also reads "null", and the contract spells it "null".
		if len(value.Content) != 2 || value.Content[0].Tag != "!!str" || value.Content[1].Tag != "!!str" {
			return union
		}
		first, second := value.Content[0].Value, value.Content[1].Value
		if first == "null" {
			first, second = second, first
		}
		if second != "null" || first == "null" {
			return union
		}
		rewritten.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: first, Line: value.Line, Column: value.Column}
		nullableType = true
	}
	var decoded plain
	if err := rewritten.Decode(&decoded); err != nil {
		return err
	}
	if nullableType && nullableKey && !decoded.Nullable {
		return fmt.Errorf("line %d: type [<type>, \"null\"] contradicts nullable: false", node.Line)
	}
	decoded.Nullable = decoded.Nullable || nullableType
	*s = AppMCPSchema(decoded)
	return nil
}

// MarshalJSON advertises nullability as standard JSON Schema `type: [X, "null"]`.
// The contract digest hashes this encoding, so it changes with nullability.
func (s AppMCPSchema) MarshalJSON() ([]byte, error) {
	type plain AppMCPSchema
	if !s.Nullable {
		return json.Marshal(plain(s))
	}
	return json.Marshal(struct {
		plain
		Type []string `json:"type"`
	}{plain(s), []string{s.Type, "null"}})
}

var appMCPName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

func parseAppMCPManifest(data []byte) (*AppMCPManifest, error) {
	return parseAppMCPManifestGated(data, appMCPExternalConnectionsEnabled)
}
func parseAppMCPManifestGated(data []byte, externalEnabled bool) (*AppMCPManifest, error) {
	manifest, err := decodeAppMCPManifest(data)
	if err != nil || manifest == nil {
		return manifest, err
	}
	if err := validateAppMCPManifestGated(manifest, externalEnabled); err != nil {
		return nil, fmt.Errorf("mcp.yaml: %w", err)
	}
	return manifest, nil
}

// Only explicit CLI source review may bootstrap missing or stale digests.
// Runtime and upload validation always use parseAppMCPManifestGated.
func parseAppMCPManifestForReview(data []byte) (*AppMCPManifest, error) {
	manifest, err := decodeAppMCPManifest(data)
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, fmt.Errorf("review requires a version 1 mcp.yaml")
	}
	manifest.ContractDigest, manifest.ExecutionDigest = strings.Repeat("0", 64), strings.Repeat("0", 64)
	if err := validateAppMCPManifestGated(manifest, appMCPExternalConnectionsEnabled); err != nil {
		return nil, fmt.Errorf("mcp.yaml: %w", err)
	}
	return manifest, nil
}

func decodeAppMCPManifest(data []byte) (*AppMCPManifest, error) {
	if data == nil {
		return nil, nil
	}
	if err := checkYAMLShape(data); err != nil {
		return nil, fmt.Errorf("mcp.yaml: %w", err)
	}
	var document yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&document); err != nil {
		return nil, fmt.Errorf("mcp.yaml: %w", err)
	}
	if err := validateAppMCPYAMLNode(&document, 0, false); err != nil {
		return nil, fmt.Errorf("mcp.yaml: %w", err)
	}
	var manifest *AppMCPManifest
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("mcp.yaml: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("mcp.yaml: expected exactly one document")
	}
	if manifest == nil {
		return nil, fmt.Errorf("mcp.yaml: expected a version 1 manifest")
	}
	return manifest, nil
}
func validateAppMCPManifestGated(m *AppMCPManifest, externalEnabled bool) error {
	if m.Version != 1 || !appMCPName.MatchString(m.Connector.ID) || strings.TrimSpace(m.Connector.Name) == "" || strings.TrimSpace(m.Connector.Version) == "" {
		return fmt.Errorf("version 1 and connector id/name/version are required")
	}
	for _, digest := range []string{m.ContractDigest, m.ExecutionDigest} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || digest != strings.ToLower(digest) {
			return fmt.Errorf("reviewed contract/execution digests must be lowercase SHA256 at top level; after reviewing app files, run benmore mcp review <appdir> --reviewed (CLI 0.1.37+); see benmore docs connector")
		}
	}
	if m.ExecutionSources != "" && m.ExecutionSources != appMCPExecutionSourcesRuntime {
		return fmt.Errorf("execution_sources must be %q or omitted", appMCPExecutionSourcesRuntime)
	}
	connections, err := validateAppMCPConnections(m.Connections)
	if err != nil {
		return err
	}
	names := map[string]bool{}
	resources := map[string]bool{}
	for _, resource := range m.Resources {
		if !appMCPName.MatchString(resource.Name) || names[resource.Name] || resource.URI == "" || resources[resource.URI] || resource.MIMEType == "" || resource.Component == "" {
			return fmt.Errorf("invalid or duplicate component resource %q", resource.Name)
		}
		if err := validateAppMCPResourceDeclaration(resource); err != nil {
			return fmt.Errorf("component resource %q: %w", resource.Name, err)
		}
		names[resource.Name] = true
		resources[resource.URI] = true
	}
	names = map[string]bool{}
	for _, tool := range m.Tools {
		if !appMCPName.MatchString(tool.Name) || names[tool.Name] || strings.TrimSpace(tool.Description) == "" {
			return fmt.Errorf("invalid or duplicate tool %q", tool.Name)
		}
		names[tool.Name] = true
		commandTool := tool.Handler.Kind == "flow" && tool.Handler.Operation == "command"
		externalTool := tool.Handler.Kind == "external"
		fileTool := tool.Handler.Kind == "file"
		if tool.Handler.Kind != "native" && !commandTool && !externalTool && !fileTool {
			return fmt.Errorf("tool %q has unsupported handler kind %q; native table reads use handler: {kind: native, table: notes, operation: table.list} or table.read; see benmore docs connector", tool.Name, tool.Handler.Kind)
		}
		if fileTool && (tool.Handler.Table == "" || tool.Handler.Flow != "" || tool.Handler.Connection != "" || tool.Handler.OperationID != "" || (tool.Handler.Operation != "ingest" && tool.Handler.Operation != "verify")) {
			return fmt.Errorf("tool %q file handler requires one table binding and a supported file operation", tool.Name)
		}
		if externalTool && tool.Effect != "read" {
			return fmt.Errorf("tool %q: external write tools are not enabled in this runtime; declare effect: read", tool.Name)
		}
		if transfer := tool.Transfer; transfer != nil {
			if !commandTool || !connections[transfer.Connection] || transfer.OperationID == "" {
				return fmt.Errorf("tool %q: transfer bindings require an approved flow command and declared connection", tool.Name)
			}
			switch transfer.Kind {
			case "pull":
				if transfer.SelectorIntentPath == "" || transfer.SelectorParameter == "" || transfer.ContentField == "" || transfer.MIMEField == "" || transfer.RevisionField == "" || transfer.ChecksumField == "" || transfer.AttachTool == "" || transfer.RecordIDIntentPath == "" || transfer.FileColumn == "" || transfer.ArtifactIntentPath != "" || transfer.RequestContentField != "" || transfer.RequestIdempotencyField != "" || transfer.ReconcileOperationID != "" {
					return fmt.Errorf("tool %q: pull transfer mapping is incomplete or contains push fields", tool.Name)
				}
			case "push":
				if transfer.ArtifactIntentPath == "" || transfer.RequestContentField == "" || transfer.RequestIdempotencyField == "" || transfer.ReconcileOperationID == "" || transfer.ReconcileParameter == "" || transfer.ResultIDField == "" || transfer.ResultChecksumField == "" || transfer.SelectorIntentPath != "" || transfer.SelectorParameter != "" || transfer.ContentField != "" || transfer.AttachTool != "" || transfer.FileColumn != "" {
					return fmt.Errorf("tool %q: push transfer mapping is incomplete or contains pull fields", tool.Name)
				}
			default:
				return fmt.Errorf("tool %q: unsupported transfer kind %q", tool.Name, transfer.Kind)
			}
		}
		if err := validateAppMCPReviewFields(tool, commandTool); err != nil {
			return fmt.Errorf("tool %q: %w", tool.Name, err)
		}
		writeUpdate := tool.Handler.Operation == "table.update"
		if writeUpdate || commandTool {
			// approval: grant (apply without a per-write browser approval while the
			// owner switch and the user's consent also allow it) is for commands
			// only; table.update keeps its first-party review. A transfer (push
			// sends app data to an external connection) always keeps per-write
			// review: it is the highest-impact write class.
			approval := tool.Approval == "first_party" || commandTool && tool.Approval == "grant" && tool.Transfer == nil
			if tool.Effect != "write" || !approval || tool.Idempotency != "operation" || tool.Reconciliation != "authoritative_readback" || tool.Component != "none" {
				return fmt.Errorf("tool %q has unsupported private write policy", tool.Name)
			}
		} else if tool.Effect != "read" || tool.Approval != "none" || tool.Idempotency != "none" || tool.Reconciliation != "none" {
			return fmt.Errorf("tool %q requires the read-only B1 effect policy", tool.Name)
		}
		if tool.Handler.Kind != "external" && (tool.Handler.Connection != "" || tool.Handler.OperationID != "") {
			return fmt.Errorf("tool %q declares external handler fields on a non-external handler", tool.Name)
		}
		switch tool.Handler.Operation {
		case "":
			if !externalTool || tool.Handler.Table != "" || tool.Handler.Flow != "" || !connections[tool.Handler.Connection] || tool.Handler.OperationID == "" {
				return fmt.Errorf("tool %q requires exactly one declared connection and operation_id", tool.Name)
			}
		case "table.list", "table.read":
			if tool.Handler.Table == "" || tool.Handler.Flow != "" {
				return fmt.Errorf("tool %q requires exactly one table binding", tool.Name)
			}
		case "flow.call":
			if tool.Handler.Flow == "" || tool.Handler.Table != "" {
				return fmt.Errorf("tool %q requires exactly one flow binding", tool.Name)
			}
		case "table.update":
			if tool.Handler.Table == "" || tool.Handler.Flow != "" {
				return fmt.Errorf("tool %q requires exactly one table binding", tool.Name)
			}
		case "command":
			if !commandTool || tool.Handler.Flow == "" || tool.Handler.Table != "" {
				return fmt.Errorf("tool %q requires exactly one flow command binding", tool.Name)
			}
		case "ingest", "verify":
			if !fileTool {
				return fmt.Errorf("tool %q file operation requires kind: file", tool.Name)
			}
		default:
			return fmt.Errorf("tool %q has unsupported native operation", tool.Name)
		}
		if len(tool.Permissions) == 0 {
			return fmt.Errorf("tool %q requires explicit permissions", tool.Name)
		}
		if err := validateFlowPermissions(tool.Permissions); err != nil {
			return fmt.Errorf("tool %q: %w", tool.Name, err)
		}
		if fileTool {
			if tool.InputSchema == nil {
				return fmt.Errorf("tool %q file handler requires an input schema", tool.Name)
			}
			for _, field := range []string{"file_ref", "record_id"} {
				if tool.InputSchema.Properties[field] == nil || tool.InputSchema.Properties[field].Type != "string" || tool.InputSchema.Properties[field].Nullable || !slices.Contains(tool.InputSchema.Required, field) {
					return fmt.Errorf("tool %q file handler requires string input %q", tool.Name, field)
				}
			}
			if !slices.Contains(tool.Permissions, "files:read") {
				return fmt.Errorf("tool %q file handler requires files:read permission", tool.Name)
			}
			if !scopesWithin(strings.Join(tool.Permissions, " "), tool.Handler.Table+":read") {
				return fmt.Errorf("tool %q file handler requires its canonical table read permission", tool.Name)
			}
			if tool.Handler.Operation == "verify" {
				processingIDSchema := tool.InputSchema.Properties["processing_id"]
				if processingIDSchema == nil || processingIDSchema.Type != "string" || processingIDSchema.Nullable || processingIDSchema.MinLength == nil || *processingIDSchema.MinLength != 32 || processingIDSchema.MaxLength == nil || *processingIDSchema.MaxLength != 32 || !slices.Contains(tool.InputSchema.Required, "processing_id") {
					return fmt.Errorf("tool %q verify operation requires processing_id as a required string of exactly 32 characters; pass the processing_id returned by ingest", tool.Name)
				}
				for _, field := range []string{"sheet", "ref", "expected"} {
					if tool.InputSchema.Properties[field] == nil || tool.InputSchema.Properties[field].Type != "string" || tool.InputSchema.Properties[field].Nullable || !slices.Contains(tool.InputSchema.Required, field) {
						return fmt.Errorf("tool %q verify operation requires string input %q", tool.Name, field)
					}
				}
			}
		}
		if writeUpdate {
			if len(tool.Permissions) != 1 || tool.Permissions[0] != tool.Handler.Table+":write" {
				return fmt.Errorf("tool %q requires its exact table write permission", tool.Name)
			}
			if err := validateAppMCPUpdateDeclaration(tool); err != nil {
				return fmt.Errorf("tool %q: %w", tool.Name, err)
			}
		} else if tool.Handler.Operation == "table.list" || tool.Handler.Operation == "table.read" {
			if !scopesWithin(strings.Join(tool.Permissions, " "), tool.Handler.Table+":read") {
				return fmt.Errorf("tool %q lacks canonical table read permission", tool.Name)
			}
		}
		for _, schema := range []*AppMCPSchema{tool.InputSchema, tool.OutputSchema} {
			if schema == nil || schema.Type != "object" {
				return fmt.Errorf("tool %q requires object input/output schemas", tool.Name)
			}
			if err := validateAppMCPSchema(schema, 0); err != nil {
				return fmt.Errorf("tool %q: %w", tool.Name, err)
			}
			if commandTool {
				if err := validateBoundedUpdateSchema(schema, 0); err != nil {
					return fmt.Errorf("tool %q: %w", tool.Name, err)
				}
			}
		}
		if commandTool {
			for _, field := range tool.InputSchema.Required {
				if field == "user" || field == "session" || field == "env" || field == "operation" || field == "request" {
					return fmt.Errorf("tool %q intent requires a reserved authority field", tool.Name)
				}
			}
		}
		if len(tool.Output.Include) == 0 {
			return fmt.Errorf("tool %q requires an explicit output projection", tool.Name)
		}
		seen := map[string]bool{}
		for _, field := range tool.Output.Include {
			if field == "" || seen[field] || field == "*" {
				return fmt.Errorf("tool %q has invalid output projection", tool.Name)
			}
			seen[field] = true
			if !commandTool && tool.OutputSchema.Properties[field] == nil {
				return fmt.Errorf("tool %q output projection field %q is absent from its output schema", tool.Name, field)
			}
			// A table tool refuses a column the hidden-column rule hides when it
			// runs; a flow returns whatever its SQL selects under these names, so
			// the same name rule applies here. With no table to consult, a
			// blind-index name (`*_blind`) counts as hidden too.
			if tool.Handler.Operation == "flow.call" && (apiHiddenColumn(nil, "", field) || strings.HasSuffix(field, blindColSuffix)) {
				return fmt.Errorf("tool %q output projection field %q is secret-shaped; API responses hide it, so a flow tool cannot return it", tool.Name, field)
			}
		}
		if tool.Component != "none" && !resources[tool.Component] {
			return fmt.Errorf("tool %q has unresolved component resource", tool.Name)
		}
		if tool.Artifact != nil {
			if err := validateAppMCPArtifactDecl(tool); err != nil {
				return fmt.Errorf("tool %q: artifact: %w", tool.Name, err)
			}
		}
	}
	for _, resource := range m.Resources {
		for _, name := range resource.Tools {
			if !names[name] {
				return fmt.Errorf("component resource %q permits undeclared tool %q", resource.Name, name)
			}
		}
	}
	return validateAppMCPExternalGate(m, externalEnabled)
}
func validateAppMCPSchema(s *AppMCPSchema, depth int) error {
	if s == nil || depth > 32 {
		return fmt.Errorf("schema is missing or exceeds depth limit")
	}
	switch s.Type {
	case "object", "array", "string", "number", "integer", "boolean", "null":
	default:
		return fmt.Errorf("unsupported schema type %q", s.Type)
	}
	if s.Nullable && s.Type == "null" {
		return fmt.Errorf("nullable cannot apply to the null type")
	}
	if _, err := json.Marshal(s.Enum); err != nil {
		return fmt.Errorf("schema enum must contain JSON-compatible values")
	}
	if s.Type != "object" && (len(s.Properties) > 0 || len(s.Required) > 0 || s.AdditionalProperties != nil) {
		return fmt.Errorf("object keywords on non-object schema")
	}
	if s.Type == "object" && (s.AdditionalProperties == nil || *s.AdditionalProperties) {
		return fmt.Errorf("object schema must explicitly reject additional properties")
	}
	seen := map[string]bool{}
	for _, name := range s.Required {
		if name == "" || seen[name] || s.Properties[name] == nil {
			return fmt.Errorf("invalid required schema property %q", name)
		}
		seen[name] = true
	}
	for name, property := range s.Properties {
		if name == "" {
			return fmt.Errorf("empty schema property")
		}
		if err := validateAppMCPSchema(property, depth+1); err != nil {
			return err
		}
	}
	if s.Type == "array" {
		if err := validateAppMCPSchema(s.Items, depth+1); err != nil {
			return err
		}
	} else if s.Items != nil || s.MinItems != nil || s.MaxItems != nil {
		return fmt.Errorf("array keywords on non-array schema")
	}
	if s.Type != "string" && (s.MinLength != nil || s.MaxLength != nil) {
		return fmt.Errorf("string keywords on non-string schema")
	}
	if s.Type != "number" && s.Type != "integer" && (s.Minimum != nil || s.Maximum != nil) {
		return fmt.Errorf("numeric keywords on non-number schema")
	}
	if s.Minimum != nil && (math.IsNaN(*s.Minimum) || math.IsInf(*s.Minimum, 0)) || s.Maximum != nil && (math.IsNaN(*s.Maximum) || math.IsInf(*s.Maximum, 0)) {
		return fmt.Errorf("nonfinite numeric bound")
	}
	if s.Minimum != nil && s.Maximum != nil && *s.Minimum > *s.Maximum {
		return fmt.Errorf("inverted numeric range")
	}
	for _, bounds := range [][2]*int{{s.MinLength, s.MaxLength}, {s.MinItems, s.MaxItems}} {
		if bounds[0] != nil && *bounds[0] < 0 || bounds[1] != nil && *bounds[1] < 0 || bounds[0] != nil && bounds[1] != nil && *bounds[0] > *bounds[1] {
			return fmt.Errorf("invalid schema size range")
		}
	}
	return nil
}

func validateAppMCPBindings(dir string, m *AppMCPManifest, flows []Flow) error {
	if m == nil {
		return nil
	}
	tables, err := appMCPSchemaTables(dir)
	if err != nil {
		return err
	}
	if err := validateAppMCPBindingsForTables(m, flows, tables, LoadRolesConfig(dir)); err != nil {
		return err
	}
	return validateAppMCPDeclaredSources(dir, m)
}
func validateAppMCPYAMLNode(node *yaml.Node, depth int, enumValue bool) error {
	if depth > 64 {
		return fmt.Errorf("manifest exceeds nesting limit")
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("manifest aliases are unsupported")
	}
	if enumValue && node.Kind == yaml.ScalarNode {
		switch node.Tag {
		case "!!str", "!!int", "!!float", "!!bool", "!!null":
		default:
			return fmt.Errorf("unsupported JSON enum scalar")
		}
	}
	if node.Kind == yaml.MappingNode {
		schema := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "type" && node.Content[i+1].Kind == yaml.ScalarNode {
				schema = true
			}
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Tag != "!!str" {
				return fmt.Errorf("manifest mapping keys must be strings")
			}
			if !enumValue {
				if value.Tag == "!!null" {
					return fmt.Errorf("manifest keyword %q cannot be null", key.Value)
				}
				if schema && (key.Value == "minLength" || key.Value == "maxLength" || key.Value == "minItems" || key.Value == "maxItems") || key.Value == "version" && depth == 1 {
					if value.Tag != "!!int" {
						return fmt.Errorf("manifest keyword %q requires an integer", key.Value)
					}
				}
			}
			if err := validateAppMCPYAMLNode(value, depth+1, enumValue || schema && key.Value == "enum"); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateAppMCPYAMLNode(child, depth+1, enumValue); err != nil {
			return err
		}
	}
	return nil
}

func appMCPSchemaTableDefinitions(dir string) ([]crudTableDefinition, error) {
	return appMCPSchemaTableDefinitionsWithReader(func(name string) ([]byte, error) { return readOptionalConfig(dir, name) })
}
func appMCPSchemaTableDefinitionsWithReader(readSource func(string) ([]byte, error)) ([]crudTableDefinition, error) {
	data, err := readSource("schema.prisma")
	if os.IsNotExist(err) {
		data, err = nil, nil
	}

	if err != nil {
		return nil, err
	}
	if data != nil {
		models, err := ParsePrismaSchema(string(data))
		if err != nil {
			return nil, fmt.Errorf("schema.prisma: %w", err)
		}
		data = []byte(EmitSQL(models))
	} else {
		data, err = readSource("schema.sql")
		if os.IsNotExist(err) {
			data, err = nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return appMCPSQLTableDefinitions(string(data))
}

func appMCPSQLTableDefinitions(source string) ([]crudTableDefinition, error) {
	var definitions []crudTableDefinition
	seen := map[string]bool{}
	err := splitSQLStatements(strings.NewReader(source), func(statement string) error {
		tokens := sqlTokenize(statement)
		if len(tokens) > 0 {
			switch strings.ToUpper(tokens[0].text) {
			case "ALTER", "DROP", "PRAGMA", "ATTACH", "DETACH", "VACUUM":
				return fmt.Errorf("mcp.yaml: unprojectable route-changing schema DDL")
			}
			for _, token := range tokens {
				if token.kind != sqlTokLiteral && (strings.EqualFold(token.text, "sqlite_master") || strings.EqualFold(token.text, "sqlite_schema")) {
					return fmt.Errorf("mcp.yaml: direct schema mutation is unsupported")
				}
			}
		}
		if len(tokens) < 4 || tokens[0].kind != sqlTokWord || !strings.EqualFold(tokens[0].text, "CREATE") {
			return nil
		}
		i := 1
		virtual := false
		if strings.EqualFold(tokens[i].text, "VIRTUAL") {
			virtual = true
			i++
		}
		if i >= len(tokens) || !strings.EqualFold(tokens[i].text, "TABLE") {
			return nil
		}
		i++
		if i+2 < len(tokens) && strings.EqualFold(tokens[i].text, "IF") && strings.EqualFold(tokens[i+1].text, "NOT") && strings.EqualFold(tokens[i+2].text, "EXISTS") {
			i += 3
		}
		if i+1 >= len(tokens) {
			return fmt.Errorf("mcp.yaml: unresolved table declaration")
		}
		definition := crudTableDefinition{name: tokens[i].text, virtual: virtual, columns: map[string]bool{}, allColumns: map[string]bool{}}
		i++
		if (!virtual && tokens[i].text != "(") || (virtual && !strings.EqualFold(tokens[i].text, "USING")) {
			return fmt.Errorf("mcp.yaml: unsupported table declaration")
		}
		depth := 0
		columnStart := false
		columnName := ""
		for index, token := range tokens[i:] {
			if token.kind == sqlTokPunct {
				switch token.text {
				case "(":
					depth++
					if depth == 1 {
						columnStart = true
					}
				case ")":
					depth--
					columnStart = false
				case ",":
					if depth == 1 {
						columnStart = true
					}
				}
				continue
			}
			if depth == 1 && columnStart {
				columnName = token.text
				definition.columns[columnName] = true
				definition.allColumns[columnName] = true
				columnStart = false
			} else if depth == 1 && token.kind == sqlTokWord && strings.EqualFold(token.text, "AS") && i+index+1 < len(tokens) && tokens[i+index+1].kind == sqlTokPunct && tokens[i+index+1].text == "(" {
				// pragma_table_info omits generated columns; xinfo retains their identity.
				delete(definition.columns, columnName)
			}
		}
		key := sqliteIdentifierFold(definition.name)
		if seen[key] {
			return fmt.Errorf("mcp.yaml: duplicate canonical table declaration %q", definition.name)
		}
		seen[key] = true
		definitions = append(definitions, definition)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return definitions, nil
}

func appMCPSchemaTables(dir string) (map[string]bool, error) {
	definitions, err := appMCPSchemaTableDefinitions(dir)
	if err != nil {
		return nil, err
	}
	return eligibleCRUDTables(definitions), nil
}
