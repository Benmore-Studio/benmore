//go:build !cli

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// FlowCommand is an inert compiled declaration. It contains no executable
// callback or authority; the approved operation adapter is responsible for use.
type FlowCommand struct {
	Version                       int
	PreparedSchema, PreviewSchema *AppMCPSchema
	Writes                        []string
	Owns                          []FlowCommandOwn
	Generated                     []FlowCommandGenerated
	AppTriggers                   []FlowCommandAppTrigger
	Dependencies                  []FlowCommandDependency
	Prepare, Apply, Readback      FlowCommandPhase
	Request                       *FlowCommandRequest
}

// FlowCommandOwn is one `owns:` entry: a column of a written table that generic
// CRUD must not set (see crud_owned_fields.go). It constrains generic CRUD only;
// other commands and ordinary flows can still write the column. Table is the
// canonical `writes` spelling and Column the schema spelling; generic CRUD
// matches both case-insensitively.
type FlowCommandOwn struct{ Table, Column string }

// FlowCommandAppTrigger is one `app_triggers:` entry: an app-authored SQLite
// trigger the reviewed source declares, so revision enrollment can accept it
// instead of refusing every trigger it did not generate itself. Its SQL is not
// stated here; it is read from the reviewed migrations (app_mcp_app_triggers.go).
type FlowCommandAppTrigger struct{ Table, Name string }
type FlowCommandRequest struct {
	Method, Path              string
	AuthRequired, Transaction bool
	RateLimit                 *FlowRateLimit
}
type FlowCommandDependency struct {
	Name, Table, Query string
	Params             map[string]FlowCommandParamRef
	MaxRows            int
}
type FlowCommandParamRef struct{ Kind, Path string }
type FlowCommandPhase struct {
	Steps                                   []FlowStep
	ReadTables, WriteTables, ComputeModules []string
}

var commandIdent = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var commandExport = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
var commandParam = regexp.MustCompile(`^\$\{\{\s*(params\.[A-Za-z_][A-Za-z0-9_.]*|user\.(id|group_id))\s*\}\}$`)
var commandRevokeUserRef = regexp.MustCompile(`^\$\{\{\s*params\.[A-Za-z_][A-Za-z0-9_.]*\s*\}\}$`)
var commandBindName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var commandForEachRef = regexp.MustCompile(`^\$\{\{\s*(params\.[A-Za-z_][A-Za-z0-9_.]*|steps\.[A-Za-z_][A-Za-z0-9_]*\.outputs(?:\.[A-Za-z_][A-Za-z0-9_.]*)?)\s*\}\}$`)
var commandStepOutputRef = regexp.MustCompile(`^\$\{\{\s*steps\.([A-Za-z_][A-Za-z0-9_]*)\.outputs\.(.+?)\s*\}\}$`)
var commandLoopPathRef = regexp.MustCompile(`^\$\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}$`)
var commandActorEmailRef = regexp.MustCompile(`^\$\{\{\s*user\.email\s*\}\}$`)

// commandActorIdentityRef names the actor's global framework role string and
// global-admin flag. Like user.email it is a SQL binding only, never a generic
// value (set/compute/respond/if) and never a dependency param.
var commandActorIdentityRef = regexp.MustCompile(`^\$\{\{\s*user\.(role|is_admin)\s*\}\}$`)

// commandActorIdentityKind maps the exact reference to its compiled kind.
func commandActorIdentityKind(raw string) string {
	if match := commandActorIdentityRef.FindStringSubmatch(raw); match != nil {
		return "actor_" + match[1]
	}
	return ""
}

func parseFlowCommandFile(filePath string, data []byte, tables map[string]bool) (Flow, error) {
	return parseFlowCommandFileColumns(filePath, data, tables, nil)
}

// parseFlowCommandFileColumns also receives the schema column inventory
// (commandColumnInventory) so `owns:` entries can be checked against real
// columns. A nil inventory refuses `owns:` rather than accepting unchecked names.
func parseFlowCommandFileColumns(filePath string, data []byte, tables map[string]bool, columns map[string]map[string]string) (Flow, error) {
	if err := checkYAMLShape(data); err != nil {
		return Flow{}, err
	}
	if !strings.HasPrefix(filePath, "flows/") || strings.Count(filePath, "/") != 1 || path.Clean(filePath) != filePath || path.Ext(filePath) != ".yaml" {
		return Flow{}, fmt.Errorf("command filename must be flows/<safe-name>.yaml")
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return Flow{}, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return Flow{}, fmt.Errorf("command files require exactly one YAML document")
	}
	if err := validateCommandNode(&doc, 0); err != nil {
		return Flow{}, err
	}
	root, err := commandMap(&doc)
	if err != nil {
		return Flow{}, err
	}
	for k := range root {
		if k != "on" && k != "command" && k != "jobs" {
			return Flow{}, fmt.Errorf("unknown command file key %q", k)
		}
	}
	if _, ok := root["command"]; !ok {
		return Flow{}, fmt.Errorf("command is required")
	}
	if _, ok := root["jobs"]; !ok {
		return Flow{}, fmt.Errorf("jobs is required")
	}
	stem := strings.TrimSuffix(path.Base(filePath), path.Ext(filePath))
	if !commandIdent.MatchString(stem) || stem == "flows" {
		return Flow{}, fmt.Errorf("command filename must be flows/<safe-name>.yaml")
	}
	cmd, err := compileFlowCommand(root["command"], root["jobs"], root["on"], tables, columns)
	if err != nil {
		return Flow{}, err
	}
	return Flow{Name: stem, Trigger: FlowTrigger{Type: "command"}, Command: cmd}, nil
}

func validateCommandNode(n *yaml.Node, depth int) error {
	if depth > 32 {
		return fmt.Errorf("command YAML exceeds nesting limit")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("command YAML aliases and anchors are unsupported")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return fmt.Errorf("command mapping keys must be strings")
			}
			if seen[k.Value] {
				return fmt.Errorf("duplicate key %q", k.Value)
			}
			seen[k.Value] = true
			if k.Value == "<<" {
				return fmt.Errorf("merge keys are unsupported")
			}
			if v.Tag == "!!null" {
				return fmt.Errorf("command key %q cannot be null", k.Value)
			}
			if err := validateCommandNode(v, depth+1); err != nil {
				return err
			}
			if err := validateCommandNode(k, depth+1); err != nil {
				return err
			}
		}
	} else {
		for _, c := range n.Content {
			if err := validateCommandNode(c, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
func commandMap(n *yaml.Node) (map[string]*yaml.Node, error) {
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping")
	}
	m := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		m[n.Content[i].Value] = n.Content[i+1]
	}
	return m, nil
}
func commandExact(m map[string]*yaml.Node, required []string, optional ...string) error {
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if m[k] == nil {
			return fmt.Errorf("missing %q", k)
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return nil
}
func commandScalar(n *yaml.Node, tag string) (string, error) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != tag {
		return "", fmt.Errorf("expected %s scalar", tag)
	}
	return n.Value, nil
}
func compileFlowCommand(cn, jn, on *yaml.Node, tables map[string]bool, columns map[string]map[string]string) (*FlowCommand, error) {
	cm, err := commandMap(cn)
	if err != nil {
		return nil, err
	}
	if err = commandExact(cm, []string{"version", "prepared_schema", "preview_schema", "writes", "dependencies"}, "owns", "generated", "app_triggers"); err != nil {
		return nil, err
	}
	var version int
	if cm["version"].Tag != "!!int" {
		return nil, fmt.Errorf("command version must be integer 1")
	}
	if err = yamlNodeDecode(cm["version"], &version); err != nil || version != 1 {
		return nil, fmt.Errorf("command version must be integer 1")
	}
	cmd := &FlowCommand{Version: 1}
	if err = yamlNodeDecode(cm["prepared_schema"], &cmd.PreparedSchema); err != nil {
		return nil, err
	}
	if err = validateCommandSchemaNode(cm["prepared_schema"]); err != nil {
		return nil, err
	}
	if err = validateCommandSchemaNode(cm["preview_schema"]); err != nil {
		return nil, err
	}
	if err = yamlNodeDecode(cm["preview_schema"], &cmd.PreviewSchema); err != nil {
		return nil, err
	}
	if cm["generated"] != nil {
		if cmd.Generated, err = compileCommandGenerated(cm["generated"]); err != nil {
			return nil, err
		}
		if err = addGeneratedToPreparedSchema(cmd.PreparedSchema, cmd.Generated); err != nil {
			return nil, err
		}
		for _, n := range []*yaml.Node{jn, cm["dependencies"]} {
			if err = validateCommandGeneratedRefs(n, cmd.Generated); err != nil {
				return nil, err
			}
		}
	}
	for _, s := range []*AppMCPSchema{cmd.PreparedSchema, cmd.PreviewSchema} {
		if s == nil || s.Type != "object" {
			return nil, fmt.Errorf("prepared and preview schemas must be objects")
		}
		if err := validateAppMCPSchema(s, 0); err != nil {
			return nil, err
		}
		if err := validateBoundedUpdateSchema(s, 0); err != nil {
			return nil, err
		}
	}
	if cm["writes"].Kind != yaml.SequenceNode || len(cm["writes"].Content) == 0 {
		return nil, fmt.Errorf("writes must be nonempty")
	}
	seen := map[string]bool{}
	for _, n := range cm["writes"].Content {
		v, e := commandScalar(n, "!!str")
		if e != nil || !tables[v] || strings.HasPrefix(v, "_") {
			return nil, fmt.Errorf("writes must name known business tables")
		}
		if seen[v] {
			return nil, fmt.Errorf("duplicate write table %q", v)
		}
		seen[v] = true
		cmd.Writes = append(cmd.Writes, v)
	}
	sort.Strings(cmd.Writes)
	if cm["owns"] != nil {
		if cmd.Owns, err = compileCommandOwns(cm["owns"], cmd.Writes, tables, columns); err != nil {
			return nil, err
		}
	}
	if cm["app_triggers"] != nil {
		if cmd.AppTriggers, err = compileCommandAppTriggers(cm["app_triggers"], tables); err != nil {
			return nil, err
		}
	}
	if cm["dependencies"].Kind != yaml.SequenceNode || len(cm["dependencies"].Content) < 1 || len(cm["dependencies"].Content) > 64 {
		return nil, fmt.Errorf("dependencies must contain 1..64 entries")
	}
	depNames := map[string]bool{}
	for _, n := range cm["dependencies"].Content {
		m, e := commandMap(n)
		if e != nil {
			return nil, e
		}
		if e = commandExact(m, []string{"name", "table", "query", "params", "max_rows"}); e != nil {
			return nil, e
		}
		var d FlowCommandDependency
		for _, key := range []string{"name", "table", "query"} {
			if m[key].Tag != "!!str" {
				return nil, fmt.Errorf("dependency %s must be a string", key)
			}
		}
		if m["max_rows"].Tag != "!!int" {
			return nil, fmt.Errorf("dependency max_rows must be an integer")
		}
		for key, target := range map[string]any{"name": &d.Name, "table": &d.Table, "query": &d.Query, "max_rows": &d.MaxRows} {
			if e = yamlNodeDecode(m[key], target); e != nil {
				return nil, e
			}
		}
		if !commandIdent.MatchString(d.Name) || depNames[d.Name] || !tables[d.Table] || strings.HasPrefix(d.Table, "_") || d.MaxRows < 1 || d.MaxRows > 256 {
			return nil, fmt.Errorf("invalid dependency %q", d.Name)
		}
		depNames[d.Name] = true
		d.Params = map[string]FlowCommandParamRef{}
		if m["params"].Kind != yaml.MappingNode {
			return nil, fmt.Errorf("dependency params must be a map")
		}
		var raw map[string]string
		for _, item := range m["params"].Content {
			if item.Tag != "!!str" {
				return nil, fmt.Errorf("dependency params must be reference strings")
			}
		}
		if e = yamlNodeDecode(m["params"], &raw); e != nil {
			return nil, e
		}
		for key, value := range raw {
			if !commandIdent.MatchString(key) {
				return nil, fmt.Errorf("invalid dependency param name")
			}
			match := commandParam.FindStringSubmatch(value)
			if match == nil {
				return nil, fmt.Errorf("dependency %s has unsupported param reference", d.Name)
			}
			ref := FlowCommandParamRef{}
			if strings.HasPrefix(match[1], "params.") {
				ref.Kind = "intent_path"
				ref.Path = strings.TrimPrefix(match[1], "params.")
			} else {
				ref.Kind = "actor_id"
				if match[1] == "user.group_id" {
					ref.Kind = "selected_tenant"
				}
			}
			d.Params[key] = ref
		}
		relations, relationErr := validateCommandSQLAdmission(d.Query, raw, "read", nil, tables)
		if relationErr != nil {
			return nil, fmt.Errorf("dependency %s: %w", d.Name, relationErr)
		}
		if !commandStringIn(relations, d.Table) {
			return nil, fmt.Errorf("dependency %s query does not select from its declared table", d.Name)
		}
		cmd.Dependencies = append(cmd.Dependencies, d)
	}
	dependencyTables := map[string]bool{}
	for i := range cmd.Dependencies {
		dep := &cmd.Dependencies[i]
		canonical, ok := commandCanonicalTable(tables, dep.Table)
		if !ok {
			return nil, fmt.Errorf("dependency %s references unresolved table %q", dep.Name, dep.Table)
		}
		dep.Table = canonical
		dependencyTables[canonical] = true
	}
	for _, dep := range cmd.Dependencies {
		relations, relationErr := commandSQLTableInventory(dep.Query)
		if relationErr != nil {
			return nil, fmt.Errorf("dependency %s: %w", dep.Name, relationErr)
		}
		for _, table := range relations {
			canonical, known := commandCanonicalTable(tables, table)
			if !known || !dependencyTables[canonical] {
				return nil, fmt.Errorf("dependency %s query references undeclared table %q", dep.Name, table)
			}
		}
	}
	jobs, e := commandMap(jn)
	if e != nil {
		return nil, e
	}
	if e = commandExact(jobs, []string{"prepare", "apply", "readback"}); e != nil {
		return nil, e
	}
	stepCount := 0
	for name, dst := range map[string]*FlowCommandPhase{"prepare": &cmd.Prepare, "apply": &cmd.Apply, "readback": &cmd.Readback} {
		p, e := compileCommandPhase(jobs[name], name, cmd.Writes, tables, &stepCount)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", name, e)
		}
		*dst = p
		reads, writesFound, modules := commandPhaseEffects(p.Steps)
		for table := range dependencyTables {
			reads[table] = true
		}
		for _, table := range cmd.Writes {
			writesFound[table] = true
		}
		canonicalize := func(inventory map[string]bool) {
			for table := range inventory {
				if canonical, ok := commandCanonicalTable(tables, table); ok && canonical != table {
					delete(inventory, table)
					inventory[canonical] = true
				}
			}
		}
		canonicalize(reads)
		canonicalize(writesFound)
		dst.ReadTables = sortedCommandSet(reads)
		dst.WriteTables = sortedCommandSet(writesFound)
		dst.ComputeModules = sortedCommandSet(modules)
	}
	if on != nil {
		cmd.Request, err = parseCommandRequest(on)
		if err != nil {
			return nil, err
		}
	}
	return cmd, nil
}

// compileCommandAppTriggers validates `app_triggers: [{table, name}, ...]`: a
// known business table and a plain trigger name that cannot be a framework
// object. Whether the trigger exists, and what it writes, is decided against the
// reviewed migrations at enrollment, never here.
func compileCommandAppTriggers(n *yaml.Node, tables map[string]bool) ([]FlowCommandAppTrigger, error) {
	if n.Kind != yaml.SequenceNode || len(n.Content) < 1 || len(n.Content) > 64 {
		return nil, fmt.Errorf("app_triggers must be a list of 1..64 {table, name} entries")
	}
	var out []FlowCommandAppTrigger
	seen := map[string]bool{}
	for _, item := range n.Content {
		m, err := commandMap(item)
		if err == nil {
			err = commandExact(m, []string{"table", "name"})
		}
		if err != nil {
			return nil, fmt.Errorf("app_triggers entries must be {table, name} maps")
		}
		table, terr := commandScalar(m["table"], "!!str")
		name, nerr := commandScalar(m["name"], "!!str")
		lower := strings.ToLower(name)
		if terr != nil || nerr != nil || !tables[table] || strings.HasPrefix(table, "_") ||
			!commandBindName.MatchString(name) || len(name) > 64 || strings.HasPrefix(lower, "_benmore_") || strings.HasPrefix(lower, "sqlite_") {
			return nil, fmt.Errorf("app_triggers entries must name a known business table and a plain trigger name")
		}
		if seen[lower] {
			return nil, fmt.Errorf("duplicate app trigger %q", name)
		}
		seen[lower] = true
		out = append(out, FlowCommandAppTrigger{Table: table, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// compileCommandOwns validates `owns: [table.column, ...]`: each entry names a
// table in the command's writes and a real column of it (SQLite folds ASCII
// case for both). Ownership is enforced at the generic CRUD boundary only; see
// crud_owned_fields.go.
func compileCommandOwns(n *yaml.Node, writes []string, tables map[string]bool, columns map[string]map[string]string) ([]FlowCommandOwn, error) {
	if n.Kind != yaml.SequenceNode || len(n.Content) < 1 || len(n.Content) > 64 {
		return nil, fmt.Errorf("owns must be a list of 1..64 table.column entries")
	}
	if columns == nil {
		return nil, fmt.Errorf("owns cannot be checked without the schema column inventory")
	}
	var owns []FlowCommandOwn
	seen := map[string]bool{}
	for _, item := range n.Content {
		v, err := commandScalar(item, "!!str")
		table, column, ok := strings.Cut(v, ".")
		if err != nil || !ok || table == "" || column == "" || strings.Contains(column, ".") {
			return nil, fmt.Errorf("owns entries must be table.column strings")
		}
		fold := sqliteIdentifierFold(table)
		known := false
		for name := range tables {
			if sqliteIdentifierFold(name) == fold {
				known = true
			}
		}
		if !known {
			return nil, fmt.Errorf("owns %q: unknown table %q", v, table)
		}
		canonical := ""
		for _, w := range writes {
			if sqliteIdentifierFold(w) == fold {
				canonical = w
			}
		}
		if canonical == "" {
			return nil, fmt.Errorf("owns %q: table %q is not in this command's writes", v, table)
		}
		actual, ok := columns[fold][sqliteIdentifierFold(column)]
		if !ok {
			return nil, fmt.Errorf("owns %q: %q is not a column of %q", v, column, canonical)
		}
		switch sqliteIdentifierFold(actual) {
		case "deleted_at":
			return nil, fmt.Errorf("owns %q: deleted_at is written by generic DELETE (and cascading soft delete); cannot be owned", v)
		case "updated_at":
			return nil, fmt.Errorf("owns %q: updated_at is written by every generic UPDATE; cannot be owned", v)
		}
		key := fold + "." + sqliteIdentifierFold(actual)
		if seen[key] {
			return nil, fmt.Errorf("duplicate owns entry %q", v)
		}
		seen[key] = true
		owns = append(owns, FlowCommandOwn{Table: canonical, Column: actual})
	}
	return owns, nil
}

// commandColumnInventory maps folded table name -> folded column -> schema
// spelling, from the same definitions that gate `writes`.
func commandColumnInventory(definitions []crudTableDefinition) map[string]map[string]string {
	out := make(map[string]map[string]string, len(definitions))
	for _, d := range definitions {
		cols := make(map[string]string, len(d.columns))
		for c := range d.columns {
			cols[sqliteIdentifierFold(c)] = c
		}
		out[sqliteIdentifierFold(d.name)] = cols
	}
	return out
}

func validateCommandSchemaNode(node *yaml.Node) error {
	m, err := commandMap(node)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"type": true, "description": true, "properties": true, "required": true, "additionalProperties": true, "items": true, "enum": true, "minimum": true, "maximum": true, "minLength": true, "maxLength": true, "minItems": true, "maxItems": true, "nullable": true}
	for key, value := range m {
		if !allowed[key] {
			return fmt.Errorf("unsupported command schema keyword %q", key)
		}
		switch key {
		case "type", "description":
			// type may also be the [X, "null"] spelling; AppMCPSchema.UnmarshalYAML
			// has already refused any other sequence shape.
			if value.Tag != "!!str" && !(key == "type" && value.Kind == yaml.SequenceNode) {
				return fmt.Errorf("command schema %s must be a string", key)
			}
		case "nullable":
			if value.Tag != "!!bool" {
				return fmt.Errorf("command schema nullable must be boolean")
			}
		case "minimum", "maximum":
			if value.Tag != "!!int" && value.Tag != "!!float" {
				return fmt.Errorf("command schema %s must be numeric", key)
			}
		case "minLength", "maxLength", "minItems", "maxItems":
			if value.Tag != "!!int" {
				return fmt.Errorf("command schema %s must be an integer", key)
			}
		case "additionalProperties":
			if value.Tag != "!!bool" {
				return fmt.Errorf("command schema additionalProperties must be boolean")
			}
		case "required":
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("command schema required must be a list")
			}
			for _, item := range value.Content {
				if item.Tag != "!!str" {
					return fmt.Errorf("command schema required fields must be strings")
				}
			}
		}
		if key == "properties" {
			properties, e := commandMap(value)
			if e != nil {
				return e
			}
			for name, child := range properties {
				if !commandLocalName(name) {
					return fmt.Errorf("command schema has unsafe property name %q", name)
				}
				if e = validateCommandSchemaNode(child); e != nil {
					return e
				}
			}
		}
		if key == "items" {
			if e := validateCommandSchemaNode(value); e != nil {
				return e
			}
		}
	}
	return nil
}
func commandPhaseEffects(steps []FlowStep) (map[string]bool, map[string]bool, map[string]bool) {
	reads, writes, modules := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, step := range steps {
		if step.Type == "sql" {
			relations, _ := commandSQLTableInventory(step.SQL)
			for _, table := range relations {
				reads[table] = true
			}
			targets, _ := sqlWriteTargets(step.SQL)
			for _, target := range targets {
				writes[target.Table] = true
			}
		}
		if step.Type == "compute" && step.Compute != nil {
			modules[step.Compute.Module] = true
		}
		for _, nested := range [][]FlowStep{step.Steps, step.ElseSteps} {
			r, w, m := commandPhaseEffects(nested)
			for k := range r {
				reads[k] = true
			}
			for k := range w {
				writes[k] = true
			}
			for k := range m {
				modules[k] = true
			}
		}
	}
	return reads, writes, modules
}
func sortedCommandSet(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func commandStringIn(values []string, want string) bool {
	for _, value := range values {
		if sqliteIdentifierFold(value) == sqliteIdentifierFold(want) {
			return true
		}
	}
	return false
}
func commandCanonicalTable(tables map[string]bool, name string) (string, bool) {
	for table, ok := range tables {
		if ok && sqliteIdentifierFold(table) == sqliteIdentifierFold(name) {
			return table, true
		}
	}
	return "", false
}
func yamlNodeDecode(n *yaml.Node, out any) error {
	if n == nil {
		return fmt.Errorf("missing value")
	}
	return n.Decode(out)
}
func validateCommandSelect(q string) error {
	if !isReadOnlyQuery(q) {
		return fmt.Errorf("requires one read-only SELECT/CTE")
	}
	_, count := sqlWriteTargets(q)
	if count != 1 {
		return fmt.Errorf("requires exactly one statement")
	}
	return nil
}
func validateCommandSQLAdmission(q string, params map[string]string, phase string, writes []string, tables map[string]bool) ([]string, error) {
	if err := validateCommandSQLText(q); err != nil {
		return nil, err
	}
	if err := validateCommandSQLBindings(q, params, true); err != nil {
		return nil, err
	}
	for _, value := range params {
		if commandActorEmailRef.MatchString(value) && phase != "apply" {
			return nil, fmt.Errorf("trusted actor email is available only to apply SQL")
		}
	}
	if phase == "apply" {
		if err := validateCommandApplySQL(q, writes); err != nil {
			return nil, err
		}
	} else if err := validateCommandSelect(q); err != nil {
		return nil, err
	}
	relations, err := commandSQLTableInventory(q)
	if err != nil {
		return nil, err
	}
	if tables != nil {
		for i, table := range relations {
			canonical, ok := commandCanonicalTable(tables, table)
			if !ok || strings.HasPrefix(canonical, "_") || strings.HasPrefix(strings.ToLower(canonical), "sqlite_") {
				return nil, fmt.Errorf("SQL references unknown or reserved table %q", table)
			}
			relations[i] = canonical
		}
	}
	return relations, nil
}
func validateCommandSQLBindings(q string, params map[string]string, requireTyped bool) error {
	if err := validateCommandSQLText(q); err != nil {
		return err
	}
	code := stripSQLLiterals(stripSQLComments(q))
	wanted := map[string]bool{}
	tokens := sqlTokenize(code)
	for i, token := range tokens {
		if token.kind == sqlTokWord && strings.HasPrefix(token.text, "$") {
			return fmt.Errorf("only :name SQL bindings are supported")
		}
		if token.kind != sqlTokPunct {
			continue
		}
		if token.text == "?" || token.text == "@" || token.text == "$" {
			return fmt.Errorf("only :name SQL bindings are supported")
		}
		if token.text == ":" {
			if i+1 >= len(tokens) || tokens[i+1].kind != sqlTokWord || tokens[i+1].start != token.end || !commandBindName.MatchString(tokens[i+1].text) {
				return fmt.Errorf("unsupported SQL placeholder")
			}
			wanted[tokens[i+1].text] = true
		}
	}
	if len(wanted) != len(params) {
		return fmt.Errorf("SQL bindings must exactly match named placeholders")
	}
	for name := range wanted {
		value, ok := params[name]
		if !ok {
			return fmt.Errorf("missing SQL binding %q", name)
		}
		if requireTyped && commandParam.FindStringSubmatch(value) == nil && !commandActorEmailRef.MatchString(value) && !commandActorIdentityRef.MatchString(value) {
			if commandStepOutputRef.FindStringSubmatch(value) == nil && commandLoopPathRef.FindStringSubmatch(value) == nil {
				return fmt.Errorf("SQL binding %q must be one typed reference", name)
			}
		}
	}
	for name := range params {
		if !wanted[name] {
			return fmt.Errorf("unused SQL binding %q", name)
		}
	}
	return nil
}
func validateCommandSQLText(q string) error {
	if strings.Contains(q, "${{") || strings.Contains(q, "{{") {
		return fmt.Errorf("SQL text interpolation is unsupported")
	}
	if commandSQLUnterminatedComment(q) {
		return fmt.Errorf("unterminated SQL block comment")
	}
	for _, token := range sqlTokenize(q) {
		if token.kind != sqlTokIdent && token.kind != sqlTokLiteral {
			continue
		}
		if token.start < 0 || token.end > len(q) || token.end-token.start < 2 {
			return fmt.Errorf("malformed SQL quoting")
		}
		raw := q[token.start:token.end]
		close := raw[0]
		if close == '[' {
			close = ']'
		}
		if raw[len(raw)-1] != close {
			return fmt.Errorf("malformed SQL quoting")
		}
	}
	return nil
}

// commandSQLUnterminatedComment reports a block comment that runs to the end of
// the statement. SQLite accepts one, but it would swallow any clause the runtime
// appends (the hook probe's RETURNING *): a hooked write would then derive no
// rows and run with no hooks, validators or workflow guards. The scanner's rule
// applies: the star that opens a comment cannot also close it.
func commandSQLUnterminatedComment(q string) bool {
	open, length := false, 0
	var prev byte
	_ = scanSQLBytes(q, func(c byte, kind sqlByteKind) error {
		if kind != sqlInBlockComment {
			open = false
			return nil
		}
		if !open {
			open, length = true, 0
		}
		length++
		if length >= 4 && prev == '*' && c == '/' {
			open = false
		}
		prev = c
		return nil
	})
	return open
}

// commandSQLTableInventory accepts only bounded FROM/JOIN relation syntax and
// returns every physical relation or an error; partial inventories are unsafe.
func commandSQLTableInventory(q string) ([]string, error) {
	tokens := sqlTokenize(stripSQLComments(q))
	seen := map[string]bool{}
	if err := commandSQLInventoryRange(tokens, seen); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for table := range seen {
		out = append(out, table)
	}
	sort.Strings(out)
	return out, nil
}

// commandSQLInventoryRange scans one SELECT/CTE scope. Nested SELECTs get
// their own CTE namespace and FROM-clause state; unsupported grouped relations
// fail closed instead of disappearing from the inventory.
func commandSQLInventoryRange(tokens []sqlToken, seen map[string]bool) error {
	return commandSQLInventoryRangeScoped(tokens, seen, nil)
}

func commandSQLInventoryRangeScoped(tokens []sqlToken, seen map[string]bool, inheritedCTEs map[string]bool) error {
	ctes := make(map[string]bool, len(inheritedCTEs))
	for name := range inheritedCTEs {
		ctes[name] = true
	}
	start := 0
	if len(tokens) > 0 && tokens[0].kind == sqlTokWord && strings.EqualFold(tokens[0].text, "WITH") {
		j := 1
		if j < len(tokens) && tokens[j].kind == sqlTokWord && strings.EqualFold(tokens[j].text, "RECURSIVE") {
			j++
		}
		for {
			if j >= len(tokens) || (tokens[j].kind != sqlTokWord && tokens[j].kind != sqlTokIdent) {
				return fmt.Errorf("unsupported CTE declaration")
			}
			ctes[sqliteIdentifierFold(tokens[j].text)] = true
			j++
			if j < len(tokens) && tokens[j].kind == sqlTokPunct && tokens[j].text == "(" {
				end := commandSQLSkipGroup(tokens, j)
				if end == len(tokens) && (len(tokens) == 0 || tokens[len(tokens)-1].text != ")") {
					return fmt.Errorf("unbalanced SQL parentheses")
				}
				j = end
			}
			if j+1 >= len(tokens) || tokens[j].kind != sqlTokWord || !strings.EqualFold(tokens[j].text, "AS") || tokens[j+1].kind != sqlTokPunct || tokens[j+1].text != "(" {
				return fmt.Errorf("unsupported CTE declaration")
			}
			end := commandSQLSkipGroup(tokens, j+1)
			if end == len(tokens) && tokens[len(tokens)-1].text != ")" {
				return fmt.Errorf("unbalanced SQL parentheses")
			}
			if err := commandSQLInventoryRangeScoped(tokens[j+2:end-1], seen, ctes); err != nil {
				return err
			}
			j = end
			if j < len(tokens) && tokens[j].kind == sqlTokPunct && tokens[j].text == "," {
				j++
				continue
			}
			start = j
			break
		}
	}
	from := false
	for i := start; i < len(tokens); i++ {
		t := tokens[i]
		if t.kind == sqlTokPunct && t.text == ")" {
			return fmt.Errorf("unbalanced SQL parentheses")
		}
		if t.kind == sqlTokPunct && t.text == "(" {
			end := commandSQLSkipGroup(tokens, i)
			if end == len(tokens) && tokens[len(tokens)-1].text != ")" {
				return fmt.Errorf("unbalanced SQL parentheses")
			}
			inner := tokens[i+1 : end-1]
			if len(inner) > 0 && inner[0].kind == sqlTokWord && (strings.EqualFold(inner[0].text, "SELECT") || strings.EqualFold(inner[0].text, "WITH")) {
				if err := commandSQLInventoryRangeScoped(inner, seen, ctes); err != nil {
					return err
				}
			} else if from {
				return fmt.Errorf("grouped SQL relations are unsupported")
			} else if err := commandSQLInventoryExpression(inner, seen, ctes); err != nil {
				return err
			}
			i = end - 1
			continue
		}
		if t.kind == sqlTokPunct && t.text == "," && from {
			return fmt.Errorf("comma joins are unsupported")
		}
		if t.kind != sqlTokWord {
			continue
		}
		word := strings.ToUpper(t.text)
		if word == "IN" && !commandSQLHasParenthesizedInRHS(tokens, i) {
			return fmt.Errorf("table-form IN sources are unsupported")
		}
		if word == "FROM" {
			from = true
		}
		if from && (word == "WHERE" || word == "GROUP" || word == "ORDER" || word == "HAVING" || word == "LIMIT" || word == "UNION" || word == "EXCEPT" || word == "INTERSECT" || word == "WINDOW") {
			from = false
		}
		if word != "FROM" && word != "JOIN" {
			continue
		}
		j := i + 1
		if j >= len(tokens) {
			return fmt.Errorf("incomplete SQL relation")
		}
		if tokens[j].kind == sqlTokPunct && tokens[j].text == "(" {
			end := commandSQLSkipGroup(tokens, j)
			if end == len(tokens) && tokens[len(tokens)-1].text != ")" {
				return fmt.Errorf("unbalanced SQL parentheses")
			}
			inner := tokens[j+1 : end-1]
			if len(inner) == 0 || inner[0].kind != sqlTokWord || (!strings.EqualFold(inner[0].text, "SELECT") && !strings.EqualFold(inner[0].text, "WITH")) {
				return fmt.Errorf("grouped SQL relations are unsupported")
			}
			if err := commandSQLInventoryRangeScoped(inner, seen, ctes); err != nil {
				return err
			}
			i = end - 1
			continue
		}
		if tokens[j].kind != sqlTokWord && tokens[j].kind != sqlTokIdent {
			return fmt.Errorf("unsupported SQL relation syntax")
		}
		name, qualified := tokens[j].text, false
		if j+1 < len(tokens) && tokens[j+1].kind == sqlTokPunct && tokens[j+1].text == "." {
			if !strings.EqualFold(name, "main") || j+2 >= len(tokens) || (tokens[j+2].kind != sqlTokWord && tokens[j+2].kind != sqlTokIdent) {
				return fmt.Errorf("only main-qualified relations are supported")
			}
			name, qualified = tokens[j+2].text, true
		} else if strings.EqualFold(name, "temp") {
			return fmt.Errorf("only main-qualified relations are supported")
		}
		if qualified || !ctes[sqliteIdentifierFold(name)] {
			seen[name] = true
		}
	}
	return nil
}

// commandSQLInventoryExpression finds reads nested inside scalar/grouped
// expressions without interpreting ordinary expression identifiers as tables.
// SQLite's table-form IN syntax is refused because it adds a relation without
// a FROM/JOIN token.
func commandSQLInventoryExpression(tokens []sqlToken, seen map[string]bool, inheritedCTEs map[string]bool) error {
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if t.kind == sqlTokWord && strings.EqualFold(t.text, "IN") && !commandSQLHasParenthesizedInRHS(tokens, i) {
			return fmt.Errorf("table-form IN sources are unsupported")
		}
		if t.kind != sqlTokPunct || t.text != "(" {
			continue
		}
		end := commandSQLSkipGroup(tokens, i)
		if end <= i+1 || end > len(tokens) || tokens[end-1].text != ")" {
			return fmt.Errorf("unbalanced SQL parentheses")
		}
		inner := tokens[i+1 : end-1]
		if len(inner) > 0 && inner[0].kind == sqlTokWord && (strings.EqualFold(inner[0].text, "SELECT") || strings.EqualFold(inner[0].text, "WITH")) {
			if err := commandSQLInventoryRangeScoped(inner, seen, inheritedCTEs); err != nil {
				return err
			}
		} else if err := commandSQLInventoryExpression(inner, seen, inheritedCTEs); err != nil {
			return err
		}
		i = end - 1
	}
	return nil
}

func commandSQLHasParenthesizedInRHS(tokens []sqlToken, index int) bool {
	return index+1 < len(tokens) && tokens[index+1].kind == sqlTokPunct && tokens[index+1].text == "("
}

func commandSQLSkipGroup(tokens []sqlToken, start int) int {
	depth := 0
	for i := start; i < len(tokens); i++ {
		if tokens[i].kind == sqlTokPunct {
			if tokens[i].text == "(" {
				depth++
			}
			if tokens[i].text == ")" {
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
	}
	return len(tokens)
}
func compileCommandPhase(n *yaml.Node, phase string, writes []string, tables map[string]bool, totalSteps *int) (FlowCommandPhase, error) {
	m, e := commandMap(n)
	if e != nil {
		return FlowCommandPhase{}, e
	}
	if e = commandExact(m, []string{"steps"}); e != nil {
		return FlowCommandPhase{}, e
	}
	if m["steps"].Kind != yaml.SequenceNode || len(m["steps"].Content) == 0 {
		return FlowCommandPhase{}, fmt.Errorf("steps must be nonempty")
	}
	var raw []FlowStepGHA
	if e = yamlNodeDecode(m["steps"], &raw); e != nil {
		return FlowCommandPhase{}, e
	}
	if len(raw) == 0 || raw[len(raw)-1].With == nil {
		return FlowCommandPhase{}, fmt.Errorf("command terminal JSON must be an object")
	}
	if _, ok := raw[len(raw)-1].With["json"].(map[string]any); !ok {
		return FlowCommandPhase{}, fmt.Errorf("command terminal JSON must be an object")
	}
	p := FlowCommandPhase{Steps: convertCommandGHASteps(raw)}
	if err := validateCommandActorEmailPlacement(raw, phase); err != nil {
		return FlowCommandPhase{}, err
	}
	if e = compileCommandPhaseRefs(m["steps"], p.Steps, phase); e != nil {
		return FlowCommandPhase{}, e
	}
	for i, n := range m["steps"].Content {
		if e = validateCommandStepNode(n, phase, 0, writes, tables); e != nil {
			return FlowCommandPhase{}, e
		}
		if i != len(raw)-1 && strings.TrimSpace(raw[i].Run) == "respond" {
			return FlowCommandPhase{}, fmt.Errorf("command response is only allowed as the final phase step")
		}
		if i == len(raw)-1 {
			if strings.TrimSpace(raw[i].Run) != "respond" {
				return FlowCommandPhase{}, fmt.Errorf("phase must end with success respond 200")
			}
			status, _ := raw[i].With["status"].(int)
			if status != 200 {
				return FlowCommandPhase{}, fmt.Errorf("phase must end with success respond 200")
			}
			shape := map[string]any{"prepare": map[string]any{"arguments": nil, "preview": nil}, "apply": map[string]any{"ok": true}}[phase]
			if phase != "readback" && !commandLiteralRespondShape(raw[i].With["json"], shape) {
				return FlowCommandPhase{}, fmt.Errorf("%s success response has the wrong shape", phase)
			}
		}
	}
	if err := validateCommandUniqueIDs(raw, totalSteps); err != nil {
		return FlowCommandPhase{}, err
	}
	return p, nil
}

// Command compilation keeps the authored dollar references intact. The
// compatibility converter intentionally normalizes them for ordinary flows;
// command phases instead use the same closed typed resolver at compile and
// execution time.
func convertCommandGHASteps(raw []FlowStepGHA) []FlowStep {
	steps := convertGHASteps(raw)
	var restore func([]FlowStepGHA, []FlowStep) error
	restore = func(source []FlowStepGHA, converted []FlowStep) error {
		if len(source) != len(converted) {
			return errors.New("command step/source capture is inconsistent")
		}
		for i := range source {
			raw, step := source[i], &converted[i]
			switch step.Type {
			case "sql":
				if raw.Query != "" {
					step.SQL = raw.Query
				} else if query, ok := raw.With["query"].(string); ok {
					step.SQL = query
				}
				if params, ok := raw.With["params"].(map[string]any); ok {
					step.SQLParams = commandStringParams(params)
				} else if params, ok := raw.RawParams.(map[string]any); ok {
					step.SQLParams = commandStringParams(params)
				}
			case "compute":
				if step.Compute != nil {
					step.Compute.Args = raw.With["args"]
				}
			case "set":
				step.Set = commandStringParams(raw.With)
			case "revoke_user_sessions":
				step.RevokeUserID, _ = raw.With["user_id"].(string)
			case "for_each":
				step.ForEach = raw.ForEach
			case "if":
				step.Condition = raw.If
			}
			if err := restore(raw.Steps, step.Steps); err != nil {
				return err
			}
			if err := restore(raw.Else, step.ElseSteps); err != nil {
				return err
			}
		}
		return nil
	}
	if err := restore(raw, steps); err != nil {
		return nil
	}
	// The terminal response has no step id, so take its exact captured YAML
	// tree from the final source step.
	if len(raw) > 0 && len(steps) > 0 && steps[len(steps)-1].Type == "respond" && steps[len(steps)-1].Respond != nil {
		if body, ok := raw[len(raw)-1].With["json"].(map[string]any); ok {
			steps[len(steps)-1].Respond.JSON = body
		}
	}
	return steps
}

func commandStringParams(values map[string]any) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, raw := range values {
		if text, ok := raw.(string); ok {
			out[key] = text
		} else {
			out[key] = fmt.Sprint(raw)
		}
	}
	return out
}

func validateCommandActorEmailPlacement(steps []FlowStepGHA, phase string) error {
	for _, step := range steps {
		if commandContainsActorEmail(step.If) || commandContainsActorEmail(step.ForEach) {
			return fmt.Errorf("trusted actor email cannot be used as a generic command value")
		}
		if step.Run == "sql" {
			if params, ok := step.With["params"].(map[string]any); ok {
				for _, raw := range params {
					value, ok := raw.(string)
					if ok && strings.Contains(value, "user.email") && (phase != "apply" || !commandActorEmailRef.MatchString(value)) {
						return fmt.Errorf("trusted actor email must be the exact apply SQL binding")
					}
				}
			}
		} else {
			for _, value := range step.With {
				if commandContainsActorEmail(value) {
					return fmt.Errorf("trusted actor email cannot be used outside apply SQL bindings")
				}
			}
		}
		if err := validateCommandActorEmailPlacement(step.Steps, phase); err != nil {
			return err
		}
		if err := validateCommandActorEmailPlacement(step.Else, phase); err != nil {
			return err
		}
	}
	return nil
}

func commandContainsActorEmail(value any) bool {
	switch value := value.(type) {
	case string:
		return strings.Contains(value, "user.email")
	case map[string]any:
		for _, child := range value {
			if commandContainsActorEmail(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if commandContainsActorEmail(child) {
				return true
			}
		}
	}
	return false
}
func validateCommandUniqueIDs(steps []FlowStepGHA, totalSteps *int) error {
	seen := map[string]bool{}
	var walk func([]FlowStepGHA) error
	walk = func(items []FlowStepGHA) error {
		for _, step := range items {
			*totalSteps++
			if *totalSteps > 256 {
				return fmt.Errorf("authored step limit exceeded")
			}
			if step.ID != "" {
				if !commandIdent.MatchString(step.ID) || seen[step.ID] {
					return fmt.Errorf("invalid or duplicate step id %q", step.ID)
				}
				seen[step.ID] = true
			}
			if err := walk(step.Steps); err != nil {
				return err
			}
			if err := walk(step.Else); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(steps)
}

func compileCommandPhaseRefs(nodes *yaml.Node, steps []FlowStep, phase string) error {
	return compileCommandPhaseRefsScoped(nodes, steps, phase, map[string]bool{}, map[string]string{})
}

func compileCommandPhaseRefsScoped(nodes *yaml.Node, steps []FlowStep, phase string, aliases map[string]bool, producers map[string]string) error {
	if nodes == nil || nodes.Kind != yaml.SequenceNode || len(nodes.Content) != len(steps) {
		return fmt.Errorf("command step/source capture is inconsistent")
	}
	available := make(map[string]string, len(producers))
	for name, kind := range producers {
		available[name] = kind
	}
	for i, node := range nodes.Content {
		mapping, err := commandMap(node)
		if err != nil {
			return err
		}
		run, _ := commandScalar(mapping["run"], "!!str")
		if run == "sql" {
			with, err := commandMap(mapping["with"])
			if err != nil {
				return err
			}
			params, err := commandMap(with["params"])
			if err != nil && with["params"] != nil {
				return err
			}
			steps[i].CommandSQLParams = make(map[string]FlowCommandParamRef, len(params))
			for name, valueNode := range params {
				value, err := commandScalar(valueNode, "!!str")
				if err != nil {
					return err
				}
				ref, err := compileCommandPhaseSQLRef(value, phase, aliases, available)
				if err != nil {
					return fmt.Errorf("SQL binding %q: %w", name, err)
				}
				steps[i].CommandSQLParams[name] = ref
			}
			if len(params) == 0 {
				steps[i].CommandSQLParams = nil
			}
		}
		if steps[i].Type == "revoke_user_sessions" {
			// A captured, non-loop intent value only: the target is fixed
			// before the apply starts (app_mcp_command_revoke.go).
			if len(aliases) != 0 {
				return fmt.Errorf("revoke_user_sessions cannot run inside a for_each loop")
			}
			with, err := commandMap(mapping["with"])
			if err != nil {
				return err
			}
			value, err := commandScalar(with["user_id"], "!!str")
			if err != nil {
				return err
			}
			ref, err := compileCommandSQLRef(value, aliases, available)
			if err != nil || ref.Kind != "phase_path" {
				return fmt.Errorf("revoke_user_sessions user_id must be a params reference to a captured intent value")
			}
			steps[i].CommandRevokeRef = ref
		}
		if steps[i].Type == "for_each" {
			loopPath, ok := commandLoopParameterPath(steps[i].ForEach)
			if !ok || !commandLocalName(steps[i].ForAs) {
				return fmt.Errorf("command loop source and alias must be explicit bounded parameter values")
			}
			if _, err := compileCommandPhaseSQLRef("${{ "+loopPath+" }}", phase, aliases, available); err != nil {
				return fmt.Errorf("command loop source is outside its captured scope")
			}
			nestedAliases := make(map[string]bool, len(aliases)+1)
			for name := range aliases {
				nestedAliases[name] = true
			}
			if nestedAliases[steps[i].ForAs] {
				return fmt.Errorf("nested command loop aliases must be distinct")
			}
			nestedAliases[steps[i].ForAs] = true
			if err := compileCommandPhaseRefsScoped(mapping["steps"], steps[i].Steps, phase, nestedAliases, available); err != nil {
				return err
			}
		} else if steps[i].Type == "if" {
			condition, err := commandScalar(mapping["if"], "!!str")
			if err != nil || validateCommandConditionRef(condition, phase, aliases, available) != nil {
				return fmt.Errorf("command condition contains a missing or out-of-scope reference")
			}
			if err := compileCommandPhaseRefsScoped(mapping["steps"], steps[i].Steps, phase, aliases, available); err != nil {
				return err
			}
			if mapping["else"] != nil {
				if err := compileCommandPhaseRefsScoped(mapping["else"], steps[i].ElseSteps, phase, aliases, available); err != nil {
					return err
				}
			}
		}
		if steps[i].Type == "set" || steps[i].Type == "compute" || steps[i].Type == "respond" {
			with, err := commandMap(mapping["with"])
			if err != nil {
				return err
			}
			var valueNode *yaml.Node
			switch steps[i].Type {
			case "set":
				valueNode = mapping["with"]
			case "compute":
				valueNode = with["args"]
			case "respond":
				valueNode = with["json"]
			}
			wholeOutput := steps[i].Type == "compute" || steps[i].Type == "respond"
			if err := validateCommandLexicalNode(valueNode, phase, aliases, available, wholeOutput); err != nil {
				return err
			}
		}
		if steps[i].Name != "" && (steps[i].Type == "sql" || steps[i].Type == "compute") {
			available[steps[i].Name] = steps[i].Type
		}
	}
	return nil
}

func commandLoopParameterPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if match := commandForEachRef.FindStringSubmatch(raw); match != nil {
		raw = match[1]
	}
	if !strings.HasPrefix(raw, "params.") {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(raw, "params."), ".")
	if len(parts) == 0 {
		return "", false
	}
	for _, part := range parts {
		if !commandLocalName(part) {
			return "", false
		}
	}
	return "params." + strings.Join(parts, "."), true
}

func commandCompileLexicalRef(raw, phase string, aliases map[string]bool, producers map[string]string, wholeOutput bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("empty command reference")
	}
	if commandActorEmailRef.MatchString(raw) {
		return errors.New("trusted actor email is restricted to an apply SQL binding")
	}
	if commandActorIdentityRef.MatchString(raw) {
		return errors.New("trusted actor role is restricted to a SQL binding")
	}
	if raw == "${{ params }}" || raw == "{{ params }}" {
		if wholeOutput {
			return nil
		}
		return errors.New("whole phase input is only valid as a structured value")
	}
	if whole, ok := commandWholeStepOutput(raw); ok {
		kind, found := producers[whole]
		if !wholeOutput || !found || (kind != "sql" && kind != "compute") {
			return errors.New("whole step output is outside its captured scope")
		}
		return nil
	}
	parts := strings.Split(raw, ".")
	if len(parts) > 1 && aliases[parts[0]] {
		valid := true
		for _, part := range parts {
			if !commandLocalName(part) {
				valid = false
				break
			}
		}
		if valid {
			raw = "${{ " + raw + " }}"
		}
	}
	if _, err := compileCommandPhaseSQLRef(raw, phase, aliases, producers); err == nil {
		return nil
	}
	return errors.New("command reference is missing, malformed, or outside its lexical scope")
}

func commandWholeStepOutput(raw string) (string, bool) {
	const prefix = "${{"
	if !strings.HasPrefix(strings.TrimSpace(raw), prefix) || !strings.HasSuffix(strings.TrimSpace(raw), "}}") {
		return "", false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(raw), prefix), "}}"))
	if !strings.HasPrefix(inner, "steps.") {
		return "", false
	}
	parts := strings.Split(inner, ".")
	if len(parts) != 3 || parts[0] != "steps" || parts[2] != "outputs" || !commandLocalName(parts[1]) {
		return "", false
	}
	return parts[1], true
}

func validateCommandConditionRef(raw, phase string, aliases map[string]bool, producers map[string]string) error {
	condition := strings.TrimSpace(raw)
	if strings.HasPrefix(condition, "${{") && strings.HasSuffix(condition, "}}") {
		condition = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(condition, "${{"), "}}"))
	}
	if conditionHasConnective(condition) || strings.ContainsAny(condition, "|&()") {
		return errors.New("condition is outside the closed scalar grammar")
	}
	lhs, _, rhs, hasOperator := splitConditionOperator(condition)
	if !hasOperator {
		lhs = condition
	} else if strings.Contains(rhs, "${{") || strings.Contains(rhs, "{{") || strings.HasPrefix(strings.TrimSpace(rhs), "params.") || strings.HasPrefix(strings.TrimSpace(rhs), "steps.") || strings.HasPrefix(strings.TrimSpace(rhs), "user.") {
		return errors.New("command condition rhs must be a literal")
	}
	lhs = strings.TrimSpace(strings.Trim(lhs, `"'`))
	if strings.HasPrefix(lhs, "params.") || strings.HasPrefix(lhs, "user.") {
		if !strings.HasPrefix(lhs, "params.") && lhs != "user.id" && lhs != "user.group_id" {
			return errors.New("unsupported command identity reference")
		}
		if !strings.HasPrefix(lhs, "${{") {
			lhs = "${{ " + lhs + " }}"
		}
	}
	if strings.HasPrefix(lhs, "steps.") && !strings.HasPrefix(lhs, "${{") {
		lhs = "${{ " + lhs + " }}"
	}
	return commandCompileLexicalRef(lhs, phase, aliases, producers, false)
}

func validateCommandLexicalNode(node *yaml.Node, phase string, aliases map[string]bool, producers map[string]string, wholeOutput bool) error {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != "!!str" {
			return nil
		}
		text := node.Value
		if !strings.Contains(text, "${{") && !strings.Contains(text, "{{") {
			return nil
		}
		if strings.Contains(text, "${{") && !strings.HasPrefix(strings.TrimSpace(text), "${{") {
			return errors.New("command references must be whole typed values")
		}
		return commandCompileLexicalRef(text, phase, aliases, producers, wholeOutput)
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := validateCommandLexicalNode(child, phase, aliases, producers, wholeOutput); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			if err := validateCommandLexicalNode(node.Content[i], phase, aliases, producers, wholeOutput); err != nil {
				return err
			}
		}
	}
	return nil
}

func compileCommandPhaseSQLRef(value, phase string, aliases map[string]bool, producers map[string]string) (FlowCommandParamRef, error) {
	if commandActorEmailRef.MatchString(value) {
		if phase != "apply" {
			return FlowCommandParamRef{}, fmt.Errorf("trusted actor email is available only to apply SQL")
		}
		return FlowCommandParamRef{Kind: "actor_email"}, nil
	}
	if kind := commandActorIdentityKind(value); kind != "" {
		return FlowCommandParamRef{Kind: kind}, nil
	}
	return compileCommandSQLRef(value, aliases, producers)
}

func compileCommandSQLRef(value string, aliases map[string]bool, producers map[string]string) (FlowCommandParamRef, error) {
	if match := commandParam.FindStringSubmatch(value); match != nil {
		if strings.HasPrefix(match[1], "params.") {
			return FlowCommandParamRef{Kind: "phase_path", Path: strings.TrimPrefix(match[1], "params.")}, nil
		}
		if match[1] == "user.group_id" {
			return FlowCommandParamRef{Kind: "selected_tenant"}, nil
		}
		if match[1] == "user.id" {
			return FlowCommandParamRef{Kind: "actor_id"}, nil
		}
		return FlowCommandParamRef{}, fmt.Errorf("command SQL binding references an unsupported identity field")
	}
	if match := commandStepOutputRef.FindStringSubmatch(value); match != nil {
		producer, path := match[1], match[2]
		kind, ok := producers[producer]
		if !ok {
			return FlowCommandParamRef{}, fmt.Errorf("step output %q is forward, branch-only, or outside this phase", producer)
		}
		parts := strings.Split(path, ".")
		if kind == "sql" && (len(parts) != 2 || parts[0] != "first" || !commandLocalName(parts[1])) {
			return FlowCommandParamRef{}, fmt.Errorf("SQL step output requires outputs.first.<column>")
		}
		if kind == "compute" {
			for _, part := range parts {
				if !commandLocalName(part) || part == "first" {
					return FlowCommandParamRef{}, fmt.Errorf("compute step output requires a fixed object path")
				}
			}
		}
		return FlowCommandParamRef{Kind: "step_output", Path: "steps." + producer + ".outputs." + path}, nil
	}
	if match := commandLoopPathRef.FindStringSubmatch(value); match != nil && aliases[match[1]] && commandLocalName(match[1]) {
		parts := strings.Split(match[2], ".")
		for _, part := range parts {
			if !commandLocalName(part) {
				return FlowCommandParamRef{}, fmt.Errorf("loop output path contains a reserved field")
			}
		}
		return FlowCommandParamRef{Kind: "loop_path", Path: match[1] + "." + match[2]}, nil
	}
	return FlowCommandParamRef{}, fmt.Errorf("SQL binding must use a captured intent, actor, tenant, loop item, or dominating producer")
}
func commandLiteralRespondShape(got, want any) bool {
	m, ok := got.(map[string]any)
	if !ok {
		return false
	}
	expected := want.(map[string]any)
	if len(m) != len(expected) {
		return false
	}
	for k, v := range expected {
		if actual, exists := m[k]; !exists || v != nil && actual != v {
			return false
		}
	}
	return true
}

// A prepare phase may refuse the request with a friendly message. The only
// shape admitted is an `if` branch holding exactly one `run: respond` with
// `status: <4xx>` and `json: {error: "<literal text>"}`. At run time it ends
// the prepare before any operation row, approval or write exists
// (appMCPCommandRefusal). It is prepare-only on purpose: apply runs in the
// write transaction, where a refusal must stay an expect_rows assertion that
// rolls the transaction back, and readback must always produce its result.
// 401 and 407 are authentication challenges the connector never issues, so
// they are not admitted.
const commandRefusalMessageMax = 500

func commandRefusalStatus(status int) bool {
	return status >= 400 && status <= 499 && status != 401 && status != 407
}

// commandRefusalMessage accepts printable literal text only: no template
// markers, no control characters, 1..500 characters.
func commandRefusalMessage(message string) bool {
	n := utf8.RuneCountInString(message)
	if n < 1 || n > commandRefusalMessageMax || !utf8.ValidString(message) || strings.Contains(message, "{{") || strings.Contains(message, "}}") {
		return false
	}
	return !strings.ContainsFunc(message, unicode.IsControl)
}

// commandRefusalCode maps the author's HTTP-style status onto the stable
// connector error codes: 400 and 422 are invalid_input, 409 is conflict, and
// everything else (403, 404, ...) is denied, which is also how a hidden record
// reads to a client.
func commandRefusalCode(status int) string {
	switch status {
	case 400, 422:
		return "invalid_input"
	case 409:
		return "conflict"
	}
	return "denied"
}

// commandRefusalStep reports the refusal a compiled respond step carries.
func commandRefusalStep(step *FlowStep) (status int, message string, ok bool) {
	if step == nil || step.Type != "respond" || step.Name != "" || step.Respond == nil || len(step.Steps) != 0 || len(step.ElseSteps) != 0 ||
		step.Retry != 0 || step.RetryDelay != 0 || len(step.OnError) != 0 || step.Condition != "" {
		return 0, "", false
	}
	r := step.Respond
	if r.StatusTemplate != "" || !commandRefusalStatus(r.Status) || r.JSONArray != nil || r.Body != "" || r.ContentType != "" || len(r.Headers) != 0 || len(r.JSON) != 1 {
		return 0, "", false
	}
	message, isString := r.JSON["error"].(string)
	if !isString || !commandRefusalMessage(message) {
		return 0, "", false
	}
	return r.Status, message, true
}

// commandRefusalBranch is true for the one step list a prepare `if` may hold
// besides ordinary steps: exactly one refusal respond.
func commandRefusalBranch(steps []FlowStep) bool {
	if len(steps) != 1 {
		return false
	}
	_, _, ok := commandRefusalStep(&steps[0])
	return ok
}

// commandRefusalNode is the authored-YAML twin of commandRefusalStep.
func commandRefusalNode(n *yaml.Node) bool {
	m, err := commandMap(n)
	if err != nil || len(m) != 2 || m["run"] == nil || m["with"] == nil {
		return false
	}
	if run, err := commandScalar(m["run"], "!!str"); err != nil || run != "respond" {
		return false
	}
	with, err := commandMap(m["with"])
	if err != nil || len(with) != 2 || with["status"] == nil || with["json"] == nil {
		return false
	}
	statusText, err := commandScalar(with["status"], "!!int")
	status, convErr := strconv.Atoi(statusText)
	if err != nil || convErr != nil || !commandRefusalStatus(status) {
		return false
	}
	body, err := commandMap(with["json"])
	if err != nil || len(body) != 1 || body["error"] == nil {
		return false
	}
	message, err := commandScalar(body["error"], "!!str")
	return err == nil && commandRefusalMessage(message)
}

// validateCommandNestedRespond admits a respond inside a wrapper only as the
// sole refusal step of a prepare `if` branch; every other nested respond is
// refused (the terminal respond is a top-level step and is never nested).
func validateCommandNestedRespond(wrapper map[string]*yaml.Node, branch *yaml.Node, phase string) error {
	for _, child := range branch.Content {
		cm, err := commandMap(child)
		if err != nil {
			return err
		}
		if run, _ := commandScalar(cm["run"], "!!str"); run != "respond" {
			continue
		}
		if phase != "prepare" || wrapper["if"] == nil || len(branch.Content) != 1 || !commandRefusalNode(child) {
			return fmt.Errorf("command response is only allowed as the final phase step, or as a literal 4xx refusal alone in a prepare if branch")
		}
	}
	return nil
}

// commandNodesHaveRespond reports a `run: respond` anywhere under a step list
// (through nested if/else/for_each wrappers). A loop body may hold none: a
// refusal belongs to the prepare phase as a whole, not to one iteration.
func commandNodesHaveRespond(list *yaml.Node) bool {
	if list == nil {
		return false
	}
	for _, n := range list.Content {
		m, err := commandMap(n)
		if err != nil {
			continue
		}
		if run, _ := commandScalar(m["run"], "!!str"); run == "respond" {
			return true
		}
		if commandNodesHaveRespond(m["steps"]) || commandNodesHaveRespond(m["else"]) {
			return true
		}
	}
	return false
}

func validateCommandStepNode(n *yaml.Node, phase string, depth int, writes []string, tables map[string]bool) error {
	m, e := commandMap(n)
	if e != nil {
		return e
	}
	allowed := map[string]bool{"id": true, "run": true, "with": true, "if": true, "for_each": true, "as": true, "steps": true, "else": true, "timeout": true, "expect_rows": true}
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("unsupported command step key %q", k)
		}
	}
	for _, key := range []string{"id", "run", "if", "for_each", "as", "timeout", "expect_rows"} {
		if value := m[key]; value != nil && value.Tag != "!!str" {
			return fmt.Errorf("command step %s must be a string", key)
		}
	}
	if value := m["with"]; value != nil && value.Kind != yaml.MappingNode {
		return fmt.Errorf("command step with must be a map")
	}
	if value := m["steps"]; value != nil && value.Kind != yaml.SequenceNode {
		return fmt.Errorf("command step steps must be a list")
	}
	if value := m["else"]; value != nil && value.Kind != yaml.SequenceNode {
		return fmt.Errorf("command step else must be a list")
	}
	var s FlowStepGHA
	if e = yamlNodeDecode(n, &s); e != nil {
		return e
	}
	if s.If != "" {
		for key := range m {
			if key != "id" && key != "if" && key != "steps" && key != "else" && key != "timeout" {
				return fmt.Errorf("unsupported if wrapper field %q", key)
			}
		}
	}
	if s.ForEach != "" {
		for key := range m {
			if key != "id" && key != "for_each" && key != "as" && key != "steps" && key != "timeout" {
				return fmt.Errorf("unsupported for_each wrapper field %q", key)
			}
		}
	}
	if s.ForEach != "" && commandNodesHaveRespond(m["steps"]) {
		return fmt.Errorf("a refusal respond is not allowed inside a for_each loop")
	}
	if s.Run != "" {
		for key := range m {
			allowedForRun := key == "id" || key == "run" || key == "with" || key == "timeout"
			if s.Run == "sql" && key == "expect_rows" {
				allowedForRun = true
			}
			if !allowedForRun {
				return fmt.Errorf("unsupported run step field %q", key)
			}
		}
	}
	if _, present := m["expect_rows"]; present && s.ExpectRows == "" {
		return fmt.Errorf("expect_rows must be a nonempty assertion")
	}
	if withNode := m["with"]; withNode != nil {
		with, mapErr := commandMap(withNode)
		if mapErr != nil {
			return mapErr
		}
		switch s.Run {
		case "sql":
			if query := with["query"]; query == nil || query.Tag != "!!str" {
				return fmt.Errorf("SQL query must be a literal string")
			}
			if params := with["params"]; params != nil {
				entries, err := commandMap(params)
				if err != nil {
					return fmt.Errorf("SQL params must be a map")
				}
				for _, value := range entries {
					if value.Tag != "!!str" {
						return fmt.Errorf("SQL params must be typed reference strings")
					}
				}
			}
		case "compute":
			for _, key := range []string{"module", "function"} {
				if value := with[key]; value == nil || value.Tag != "!!str" {
					return fmt.Errorf("compute %s must be a literal string", key)
				}
			}
		case "respond":
			if status := with["status"]; status == nil || status.Tag != "!!int" {
				return fmt.Errorf("respond status must be an integer")
			}
		case "revoke_user_sessions":
			if value := with["user_id"]; value == nil || value.Tag != "!!str" {
				return fmt.Errorf("revoke_user_sessions user_id must be a params reference string")
			}
		}
	}
	if e = validateCommandStep(s, phase, depth, writes, tables); e != nil {
		return e
	}
	for _, key := range []string{"steps", "else"} {
		if child := m[key]; child != nil {
			if child.Kind != yaml.SequenceNode {
				return fmt.Errorf("%s must be a list", key)
			}
			if e = validateCommandNestedRespond(m, child, phase); e != nil {
				return e
			}
			for _, cn := range child.Content {
				if e = validateCommandStepNode(cn, phase, depth+1, writes, tables); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func validateCommandStep(s FlowStepGHA, phase string, depth int, writes []string, tables map[string]bool) error {
	if depth > 32 {
		return fmt.Errorf("step nesting exceeds 32")
	}
	if s.OnError != nil || s.Retry != 0 || s.RetryDelay != "" || s.When != "" || s.Query != "" || s.RawParams != nil {
		return fmt.Errorf("unsupported step field")
	}
	if s.ExpectRows != "" && (phase != "apply" || s.Run != "sql") {
		return fmt.Errorf("expect_rows is apply SQL only")
	}
	if s.ExpectRows != "" {
		if _, err := evalExpectRows(s.ExpectRows, 0); err != nil {
			return err
		}
	}
	if s.Timeout != "" {
		d, e := time.ParseDuration(s.Timeout)
		if e != nil || d <= 0 || d > 30*time.Second {
			return fmt.Errorf("timeout must be positive and at most 30s")
		}
	}
	if s.Run != "" && s.If != "" || s.Run != "" && s.ForEach != "" || s.If != "" && s.ForEach != "" {
		return fmt.Errorf("ambiguous step wrapper")
	}
	allowed := map[string]bool{"sql": true, "compute": true, "set": true, "respond": true, "if": true, "for_each": true, "revoke_user_sessions": true, "": true}
	if !allowed[s.Run] {
		return fmt.Errorf("unsupported command step %q", s.Run)
	}
	if s.Run == "sql" {
		allowedWith := map[string]bool{"query": true, "params": true}
		for k := range s.With {
			if !allowedWith[k] {
				return fmt.Errorf("unsupported SQL field %q", k)
			}
		}
		q, _ := s.With["query"].(string)
		if q == "" {
			return fmt.Errorf("SQL query required")
		}
		params := map[string]string{}
		if value := s.With["params"]; value != nil {
			entries, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("SQL params must be a map")
			}
			for name, raw := range entries {
				ref, ok := raw.(string)
				if !ok {
					return fmt.Errorf("SQL param %q must be a typed reference", name)
				}
				params[name] = ref
			}
		}
		if _, err := validateCommandSQLAdmission(q, params, phase, writes, tables); err != nil {
			return err
		}
	} else if s.Run == "compute" {
		for _, key := range []string{"module", "function", "args"} {
			if s.With[key] == nil {
				return fmt.Errorf("compute requires module, function and args")
			}
		}
		for k := range s.With {
			if k != "module" && k != "function" && k != "args" {
				return fmt.Errorf("unsupported compute field")
			}
		}
		module, ok := s.With["module"].(string)
		if !ok || module == "" || strings.Contains(module, "..") || strings.HasPrefix(module, "/") || strings.ContainsAny(module, "\\\x00") {
			return fmt.Errorf("compute module required")
		}
		function, ok := s.With["function"].(string)
		if !ok || !commandExport.MatchString(function) {
			return fmt.Errorf("compute function required")
		}
		if _, ok := s.With["args"]; !ok {
			return fmt.Errorf("compute args required")
		}
	} else if s.Run == "respond" {
		if len(s.With) != 2 {
			return fmt.Errorf("respond requires exactly status and json")
		}
		status, ok := s.With["status"].(int)
		if !ok || status < 100 || status > 599 {
			return fmt.Errorf("respond status must be integer")
		}
		if _, ok := s.With["json"]; !ok {
			return fmt.Errorf("respond json required")
		}
	} else if s.Run == "revoke_user_sessions" {
		if phase != "apply" {
			return fmt.Errorf("revoke_user_sessions is available only in the apply phase")
		}
		ref, ok := s.With["user_id"].(string)
		if len(s.With) != 1 || !ok || !commandRevokeUserRef.MatchString(ref) {
			return fmt.Errorf("revoke_user_sessions takes exactly one `user_id: ${{ params.<path> }}` reference to a captured intent value")
		}
	} else if s.Run == "set" {
		if len(s.With) == 0 {
			return fmt.Errorf("set values required")
		}
		for k := range s.With {
			if !commandLocalName(k) {
				return fmt.Errorf("reserved set name")
			}
		}
		for k, v := range s.With {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("set value %q must be a scalar expression", k)
			}
		}
	} else {
		if s.With != nil {
			return fmt.Errorf("step wrappers cannot have with fields")
		}
		if s.If == "" && s.ForEach == "" {
			return fmt.Errorf("wrapper needs an if or for_each source")
		}
		if s.ForEach != "" {
			if _, ok := commandLoopParameterPath(s.ForEach); !ok {
				return fmt.Errorf("for_each needs an explicit bounded reference source")
			}
		}
		if s.ForEach != "" && len(s.Else) != 0 {
			return fmt.Errorf("for_each does not support else")
		}
		if s.As != "" && !commandLocalName(s.As) {
			return fmt.Errorf("reserved loop variable")
		}
		if len(s.Steps) == 0 {
			return fmt.Errorf("wrapper steps required")
		}
	}
	if s.ID != "" && !commandLocalName(s.ID) {
		return fmt.Errorf("reserved step id")
	}
	return nil
}
func reservedCommandName(s string) bool {
	v := strings.ToLower(s)
	return v == "params" || v == "user" || v == "session" || v == "env" || v == "operation" || v == "request" || v == "steps" || v == "internal" || v == "user_group_id" || v == "user_id" || v == "group_id" || v == "tenant_id" || strings.HasPrefix(v, "_")
}
func commandLocalName(s string) bool { return commandIdent.MatchString(s) && !reservedCommandName(s) }
func validateCommandApplySQL(q string, allowWrites []string) error {
	_, count := sqlWriteTargets(q)
	if count < 1 {
		return fmt.Errorf("empty SQL")
	}
	if strings.Contains(strings.TrimSpace(q), ";") && count > 1 {
		return fmt.Errorf("multi-statement apply SQL is unsupported")
	}
	if isReadOnlyQuery(q) {
		return nil
	}
	writes, count := sqlWriteTargets(q)
	if count != 1 || len(writes) == 0 {
		return fmt.Errorf("SQL effect cannot be classified")
	}
	allowed := map[string]bool{}
	for _, table := range allowWrites {
		allowed[sqliteIdentifierFold(table)] = true
	}
	for _, write := range writes {
		if !allowed[sqliteIdentifierFold(write.Table)] || strings.HasPrefix(write.Table, "_") || strings.HasPrefix(strings.ToLower(write.Table), "sqlite_") {
			return fmt.Errorf("SQL write target %q is outside the command inventory", write.Table)
		}
	}
	return nil
}
func parseCommandRequest(n *yaml.Node) (*FlowCommandRequest, error) {
	m, e := commandMap(n)
	if e != nil {
		return nil, e
	}
	if e = commandExact(m, []string{"request"}); e != nil {
		return nil, e
	}
	r, e := commandMap(m["request"])
	if e != nil {
		return nil, e
	}
	if e = commandExact(r, []string{"method", "path", "auth", "transaction"}, "rate_limit"); e != nil {
		return nil, e
	}
	req := &FlowCommandRequest{}
	if v, _ := commandScalar(r["method"], "!!str"); v != "POST" {
		return nil, fmt.Errorf("command route method must be POST")
	}
	req.Method = "POST"
	req.Path, _ = commandScalar(r["path"], "!!str")
	req.AuthRequired = true
	auth, _ := commandScalar(r["auth"], "!!str")
	if auth != "required" {
		return nil, fmt.Errorf("command route auth must be required")
	}
	if e = yamlNodeDecode(r["transaction"], &req.Transaction); e != nil || !req.Transaction {
		return nil, fmt.Errorf("command route transaction must be true")
	}
	u, err := url.ParseRequestURI(req.Path)
	if err != nil || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(req.Path, "/") || strings.Contains(req.Path, "%") || strings.ContainsAny(req.Path, "{}:*\\\x00") || path.Clean(req.Path) != req.Path {
		return nil, fmt.Errorf("invalid command route path")
	}
	if len(r) > 4 {
		v, _ := commandScalar(r["rate_limit"], "!!str")
		if v == "" {
			return nil, fmt.Errorf("invalid rate_limit")
		}
		req.RateLimit = parseRateLimit(v)
		if req.RateLimit == nil {
			return nil, fmt.Errorf("invalid rate_limit")
		}
	}
	return req, nil
}
