//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Missing optional files disable a feature. Unreadable files and malformed
// replacements must never be mistaken for intentional removal.
func readOptionalConfig(dir, name string) ([]byte, error) {
	var data []byte
	var err error
	if foreignAppDirs.Load() {
		data, err = readForeignAppFile(dir, name)
	} else {
		data, err = os.ReadFile(filepath.Join(dir, name))
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

// maxForeignConfigBytes bounds a configuration file the router reads from a
// tenant's directory into memory.
const maxForeignConfigBytes = 64 << 20

// readForeignAppFile reads the app file name (a slash path under dir) for a
// process that does not own dir: the hosted router, which can read every
// app's files. The file is reached by directory handle and read only as the
// regular file it is (treeDir), so an env.yaml or app.yaml that is a link to
// another app's file is refused instead of being taken for this app's.
func readForeignAppFile(dir, name string) ([]byte, error) {
	at, err := openTreeDir(dir)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(filepath.ToSlash(filepath.Clean(name)), "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := at.openDir(part)
		at.Close()
		if err != nil {
			return nil, err
		}
		at = next
	}
	defer at.Close()
	f, _, err := at.openRegular(parts[len(parts)-1])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxForeignConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxForeignConfigBytes {
		return nil, fmt.Errorf("larger than %d MiB", maxForeignConfigBytes>>20)
	}
	return data, nil
}

func decodeConfigYAML(data []byte, target any) error {
	if err := checkYAMLShape(data); err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("expected one YAML document")
	}
	return nil
}

func parseAppConfigDocument(data []byte) (map[string]any, *BackupConfig, error) {
	var raw map[string]any
	if err := decodeConfigYAML(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("app.yaml: %w", err)
	}
	if _, err := parseVersionedSection(raw["versioned"]); err != nil {
		return nil, nil, err
	}
	// All these sections are maps in the actual loaders. A list or scalar
	// otherwise silently discards auth, access, scoping, or worker settings.
	for _, key := range strings.Fields("colors typography spacing nav seo auth csp pwa recording table database features auto_memberships groups scopes access ws_rooms roles backup retention aggregates encrypted") {
		if value := raw[key]; value != nil {
			if _, ok := value.(map[string]any); !ok {
				return nil, nil, fmt.Errorf("app.yaml: %s must be a mapping", key)
			}
		}
	}
	for _, key := range strings.Fields("auth csp ws_rooms") {
		values, _ := raw[key].(map[string]any)
		for name, value := range values {
			switch value.(type) {
			case string, bool, int, float64:
			default:
				return nil, nil, fmt.Errorf("app.yaml: %s.%s must be a scalar", key, name)
			}
			if key == "ws_rooms" {
				s, ok := value.(string)
				if !ok || parseMemberOf("member-of:"+strings.ToLower(strings.TrimSpace(s))) == nil {
					return nil, nil, fmt.Errorf("app.yaml: ws_rooms.%s must be a membership rule", name)
				}
			}
		}
	}
	if groups, ok := raw["groups"].(map[string]any); ok && len(groups) > 0 {
		// table/key/user_field are spliced into the membership SQL on every
		// per-row surface: each must be a plain identifier, not just nonempty.
		for _, key := range []string{"table", "key", "user_field"} {
			s, ok := groups[key].(string)
			if !ok || strings.TrimSpace(s) == "" {
				return nil, nil, fmt.Errorf("app.yaml: groups.%s must be a nonempty string", key)
			}
			if err := configIdentError("app.yaml: groups."+key, strings.TrimSpace(s)); err != nil {
				return nil, nil, err
			}
		}
		// role_field, when set, joins the member's tenant role into the
		// session and is read by name in SQL; the same rule applies.
		if v, present := groups["role_field"]; present {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				if err := configIdentError("app.yaml: groups.role_field", strings.TrimSpace(s)); err != nil {
					return nil, nil, err
				}
			}
		}
		if b, ok := groups["bootstrap"].(map[string]any); ok {
			if v, present := b["org_table"]; present {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					if err := configIdentError("app.yaml: groups.bootstrap.org_table", strings.TrimSpace(s)); err != nil {
						return nil, nil, err
					}
				}
			}
		}
		// label is read by name in SQL for the connector's workspace picker.
		if v, present := groups["label"]; present {
			l, ok := v.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("app.yaml: groups.label must be a map with table, key and field")
			}
			for _, name := range []string{"table", "key", "field"} {
				s, _ := l[name].(string)
				s = strings.TrimSpace(s)
				if s == "" && name == "key" {
					continue // defaults to id
				}
				if err := configIdentError("app.yaml: groups.label."+name, s); err != nil {
					return nil, nil, err
				}
			}
		}
		if v, present := groups["active_field"]; present {
			if s, ok := v.(string); !ok || !membershipIdentRe.MatchString(strings.TrimSpace(s)) {
				return nil, nil, fmt.Errorf("app.yaml: groups.active_field must be a membership-table column name")
			}
		}
		if v, present := groups["shared"]; present {
			list, ok := v.([]any)
			if !ok {
				return nil, nil, fmt.Errorf("app.yaml: groups.shared must be a list of table names")
			}
			for _, item := range list {
				if s, ok := item.(string); !ok || !safeIdent(strings.TrimSpace(s)) {
					return nil, nil, fmt.Errorf("app.yaml: groups.shared must be a list of table names")
				}
			}
		}
	}
	access, _ := raw["access"].(map[string]any)
	for table, value := range access {
		switch rule := value.(type) {
		case string:
		case map[string]any:
			for op, mode := range rule {
				if _, ok := mode.(string); !ok {
					return nil, nil, fmt.Errorf("app.yaml: access.%s.%s must be a string", table, op)
				}
			}
		default:
			return nil, nil, fmt.Errorf("app.yaml: access.%s must be a string or mapping", table)
		}
	}
	roles, _ := raw["roles"].(map[string]any)
	for name, value := range roles {
		values := []any{value}
		if mapping, ok := value.(map[string]any); ok {
			values = nil
			for _, key := range []string{"scopes", "inherits"} {
				if v, exists := mapping[key]; exists {
					values = append(values, v)
				}
			}
		}
		for _, v := range values {
			switch v := v.(type) {
			case string:
			case []any:
				for _, entry := range v {
					if _, ok := entry.(string); !ok {
						return nil, nil, fmt.Errorf("app.yaml: roles.%s lists must contain strings", name)
					}
				}
			default:
				return nil, nil, fmt.Errorf("app.yaml: roles.%s scopes/inherits must be strings or lists", name)
			}
		}
	}
	var typed struct {
		Scopes    map[string]ScopeConfig             `yaml:"scopes"`
		Encrypted map[string][]EncryptedFieldDefYAML `yaml:"encrypted"`
	}
	if err := decodeConfigYAML(data, &typed); err != nil {
		return nil, nil, fmt.Errorf("app.yaml: %w", err)
	}
	for table, fields := range typed.Encrypted {
		for _, field := range fields {
			if strings.TrimSpace(field.Column) == "" {
				return nil, nil, fmt.Errorf("app.yaml: encrypted.%s requires column names", table)
			}
		}
	}
	// The typed decode above drops unknown item keys, so an item written in
	// the encrypted.yaml vocabulary ({column: ssn, unmask_roles: [admin]})
	// loaded with NO unmask roles - every reader saw plaintext. Refuse it,
	// as a malformed encrypted.yaml is refused.
	if err := appEncryptedSectionError(raw["encrypted"]); err != nil {
		return nil, nil, err
	}
	backup, err := parseBackupConfig(raw)
	return raw, backup, err
}

func parseBackupConfig(raw map[string]any) (*BackupConfig, error) {
	value := raw["backup"]
	if value == nil {
		return nil, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("app.yaml: backup must be a mapping")
	}
	for key := range m {
		if key != "interval" && key != "keep" {
			return nil, fmt.Errorf("app.yaml: unknown backup key %q", key)
		}
	}
	interval, ok := m["interval"].(string)
	duration, err := time.ParseDuration(interval)
	if !ok || err != nil || duration < time.Minute {
		return nil, fmt.Errorf("app.yaml: backup.interval must be a duration of at least 1m")
	}
	config := &BackupConfig{Interval: duration, Keep: 20}
	if value, exists := m["keep"]; exists {
		keep, ok := value.(int)
		if !ok || keep < 1 {
			return nil, fmt.Errorf("app.yaml: backup.keep must be a positive integer")
		}
		config.Keep = keep
	}
	return config, nil
}

type runtimeConfig struct {
	templateEnvSource []byte // private env.yaml snapshot; excluded from reviewed source digests
	i18n              *I18n
	wsRooms           []WSRoomRule
	validators        *ValidatorConfig
	admin             *AdminConfig
	computed          *ComputedFieldConfig
	sourceFiles       map[string][]byte // bounded reviewed source bytes; nil for ordinary loads
	migrations        map[string][]byte // nil for ordinary disk loads; empty captured set stays empty
	schemaSources     map[string][]byte // exact reviewed inputs; nil only for ordinary loads
	group             *GroupConfig
	scopes            map[string]ScopeConfig
	access            *AccessConfig
	roles             *RolesConfig
	encrypted         *EncryptedFieldConfig
	pages             map[string]*Page
	partials          map[string]string
	paths             *AuthPaths
	mcp               *AppMCPManifest
	mcpWithheld       string // why mcp.yaml's connector is off for this generation; "" when loaded or absent
	design            *DesignConfig
	backup            *BackupConfig
	hooks             *HookConfig
	flows             []Flow
	workflows         *WorkflowConfig
	cron              *CronConfig
}

// appMCPReviewStaleError: mcp.yaml's review does not bind the current source
// because the source changed since the review. A source set that can't be
// fingerprinted (ambiguous or non-regular authority files, the size bound) is
// not stale; it still refuses the load.
type appMCPReviewStaleError struct{ err error }

func (e *appMCPReviewStaleError) Error() string { return e.err.Error() }
func (e *appMCPReviewStaleError) Unwrap() error { return e.err }

// Stage fallible configuration before opening/migrating a DB or retiring the
// previous worker generation. Strict: a stale mcp.yaml review is an error.
// Checks and review use this; startup and reload use loadServedRuntimeConfig.
func loadRuntimeConfig(dir string) (*runtimeConfig, error) {
	data, err := readOptionalConfig(dir, "mcp.yaml")
	if err != nil {
		return nil, err
	}
	return loadRuntimeConfigWithManifest(dir, data)
}

// loadServedRuntimeConfig stages what startup and reload publish. A stale
// mcp.yaml review withholds only the connector: the app loads from disk like
// an app without mcp.yaml, its command flows stay loaded (they run only
// through the connector, and still guard the fields they own), and the
// connector stays off until the source is reviewed again. Any other mcp.yaml
// error, including a source set that can't be fingerprinted, still refuses
// the load. Returned values, including deliberate nils,
// are the ones published.
func loadServedRuntimeConfig(dir string) (*runtimeConfig, error) {
	data, err := readOptionalConfig(dir, "mcp.yaml")
	if err != nil {
		return nil, err
	}
	c, err := stageRuntimeConfig(dir, data, false)
	var stale *appMCPReviewStaleError
	if !errors.As(err, &stale) {
		return c, err
	}
	c, err = stageRuntimeConfig(dir, nil, true)
	if err != nil {
		return nil, err
	}
	c.mcpWithheld = stale.Error()
	return c, nil
}

// Stage a reviewed replacement without publishing it or opening app data.
func loadRuntimeConfigWithManifest(dir string, data []byte) (*runtimeConfig, error) {
	return stageRuntimeConfig(dir, data, false)
}

// stageRuntimeConfig stages configuration with data as the mcp.yaml bytes.
// withheld loads an app whose present mcp.yaml was set aside (data is nil).
func stageRuntimeConfig(dir string, data []byte, withheld bool) (*runtimeConfig, error) {
	c := &runtimeConfig{}
	var err error
	c.mcp, err = parseAppMCPManifest(data)
	if err != nil {
		return nil, err
	}
	var captured map[string][]byte
	if c.mcp != nil {
		captured = map[string][]byte{".": nil, "app.yaml": nil, "encrypted.yaml": nil, "schema.prisma": nil, "schema.sql": nil, "schema.yaml": nil, "migrations/": nil, "hooks.yaml": nil, "workflows.yaml": nil, "cron.yaml": nil, "flows.yaml": nil, "flows/": nil, "validators.yaml": nil, "admin.yaml": nil, "computed.yaml": nil, "retention.yaml": nil}
		contract, execution, sources, err := appMCPSourceDigests(dir, c.mcp, captured)
		if err != nil {
			return nil, err
		}
		if contract != c.mcp.ContractDigest || execution != c.mcp.ExecutionDigest {
			return nil, &appMCPReviewStaleError{fmt.Errorf("mcp.yaml: reviewed contract or execution digest mismatch (source changed since its last review; review it and run `benmore mcp review <appdir> --reviewed`, or delete mcp.yaml if the app serves no connector)")}
		}
		c.mcp.sourceHashes = sources
		c.sourceFiles = captured
	}
	readConfig := func(name string) ([]byte, error) {
		if c.mcp == nil {
			return readOptionalConfig(dir, name)
		}
		data, ok := captured[name]
		if !ok {
			return nil, fmt.Errorf("mcp.yaml: missing captured configuration input")
		}
		return data, nil
	}
	data, err = readConfig("app.yaml")
	if err != nil {
		return nil, err
	}
	appData := data
	raw, backup, err := parseAppConfigDocument(appData)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		c.design = designFromAppYAML(raw)
	}
	c.backup = backup
	data, err = readConfig("hooks.yaml")
	if err != nil {
		return nil, err
	}
	c.hooks, err = parseHooksYAML(data)
	if err != nil {
		return nil, err
	}
	c.flows, err = loadFlowsCheckedFromSourcesSkipping(dir, true, captured, withheld)
	var compileErr *appMCPCommandCompileError
	if errors.As(err, &compileErr) {
		// A command the runtime no longer compiles disables only the connector.
		return nil, &appMCPReviewStaleError{err}
	}
	if err != nil {
		return nil, err
	}
	if c.mcp == nil && !withheld {
		for _, flow := range c.flows {
			if flow.Command != nil || flow.Trigger.Type == "command" {
				return nil, fmt.Errorf("flows: command %q requires an mcp.yaml binding", flow.Name)
			}
		}
	}
	// Stage the page set for ordinary reloads too. A nil page set means
	// "keep the active pages" at publication, which otherwise leaves new,
	// removed and newly gated root pages at their boot-time definitions.
	// Reviewed connectors still parse only their captured source generation.
	c.pages, c.partials, err = loadPagesFromSources(dir, captured)
	if err != nil {
		return nil, fmt.Errorf("pages: %w", err)
	}
	c.paths = DiscoverAuthPaths(c.pages)
	if c.mcp != nil {
		for path, source := range captured {
			if !strings.HasPrefix(path, "i18n/") {
				continue
			}
			name := strings.TrimPrefix(path, "i18n/")
			if strings.Contains(name, "/") || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
				continue
			}
			var translations map[string]any
			if err := decodeConfigYAML(source, &translations); err != nil {
				return nil, fmt.Errorf("i18n: invalid translation document")
			}
		}
	}
	c.i18n = loadI18nFromSources(dir, captured)
	data, err = readConfig("workflows.yaml")
	if err != nil {
		return nil, err
	}
	c.workflows, err = parseWorkflowsYAML(data)
	if err != nil {
		return nil, err
	}
	data, err = readConfig("cron.yaml")
	if err != nil {
		return nil, err
	}
	c.cron, err = parseCronYAML(data)
	if err != nil {
		return nil, err
	}
	warnCronShape(data)
	data, err = readConfig("encrypted.yaml")
	if err != nil {
		return nil, err
	}
	encData := data
	if msg := validateEncryptedYAML(string(encData)); msg != "" {
		return nil, fmt.Errorf("%s", msg)
	}
	if c.mcp != nil {
		for _, flow := range c.flows {
			if c.mcp.sourceHashes[flow.Source] != flow.sourceHash {
				return nil, fmt.Errorf("mcp.yaml: parsed flow source does not match reviewed generation")
			}
		}
		c.migrations = map[string][]byte{}
		for path, data := range captured {
			if strings.HasPrefix(path, "migrations/") {
				name := strings.TrimPrefix(path, "migrations/")
				if name != "" && !strings.Contains(name, "/") {
					c.migrations[name] = data
				}
			}
		}
		c.schemaSources = map[string][]byte{"schema.prisma": captured["schema.prisma"], "schema.sql": captured["schema.sql"]}
		// Reviewed shorthand is an in-memory fallback: startup must not rewrite
		// the source generation it just approved. Prisma and raw SQL keep precedence.
		var document map[string]any
		if err := decodeConfigYAML(captured["schema.yaml"], &document); err != nil {
			return nil, fmt.Errorf("schema.yaml: %w", err)
		}
		shorthand := parseSchemaShorthand(captured["schema.yaml"])
		if shorthand == "" && len(captured["schema.yaml"]) != 0 {
			emptyModels, structured := document["models"].(map[string]any)
			if len(document) != 0 && !(len(document) == 1 && structured && len(emptyModels) == 0) {
				return nil, fmt.Errorf("schema.yaml: invalid shorthand models")
			}
		}
		if c.schemaSources["schema.prisma"] == nil && c.schemaSources["schema.sql"] == nil && shorthand != "" {
			c.schemaSources["schema.sql"] = []byte(shorthand)
		}
		definitions, err := appMCPSchemaTableDefinitionsWithReader(func(name string) ([]byte, error) { return c.schemaSource(dir, name) })
		if err != nil {
			return nil, err
		}
		if err := validateAppMCPBindingsForTables(c.mcp, c.flows, eligibleCRUDTables(definitions), parseRolesConfig(appData)); err != nil {
			return nil, err
		}
		if err := validateAppMCPDeclaredSources(dir, c.mcp); err != nil {
			return nil, err
		}
	}
	c.group = parseGroupConfig(appData)
	c.scopes = parseScopes(appData)
	c.roles = parseRolesConfig(appData)
	c.access, err = parseAccessConfig(appData)
	if err != nil {
		return nil, fmt.Errorf("app.yaml: %w", err)
	}
	c.wsRooms = parseWSRooms(appData)
	data, err = readConfig("validators.yaml")
	if err != nil {
		return nil, err
	}
	var validatorRules map[string][]ValidatorRule
	if err := decodeConfigYAML(data, &validatorRules); err != nil {
		return nil, fmt.Errorf("validators.yaml: %w", err)
	}
	c.validators = parseValidatorsYAML(data)
	data, err = readConfig("admin.yaml")
	if err != nil {
		return nil, err
	}
	var adminConfig AdminConfig
	if err := decodeConfigYAML(data, &adminConfig); err != nil {
		return nil, fmt.Errorf("admin.yaml: %w", err)
	}
	c.admin = parseAdminConfig(data)
	data, err = readConfig("computed.yaml")
	if err != nil {
		return nil, err
	}
	var computedDocument map[string]any
	if err := decodeConfigYAML(data, &computedDocument); err != nil {
		return nil, fmt.Errorf("computed.yaml: %w", err)
	}
	emptyComputedList := false
	if fields, present := computedDocument["fields"]; present {
		entries, ok := fields.([]any)
		if fields != nil && !ok {
			if _, nested := fields.(map[string]any); !nested {
				return nil, fmt.Errorf("computed.yaml: fields must be a list or nested mapping")
			}
		}
		emptyComputedList = (fields == nil || ok) && len(entries) == 0
		for _, entry := range entries {
			field, ok := entry.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("computed.yaml: field must be a mapping")
			}
			for _, key := range []string{"table", "column"} {
				value, ok := field[key].(string)
				if !ok || strings.TrimSpace(value) == "" {
					return nil, fmt.Errorf("computed.yaml: field requires %s", key)
				}
			}
		}
	}
	if !emptyComputedList {
		c.computed = parseComputedFieldsYAML(data)
		if len(computedDocument) != 0 && c.computed == nil {
			return nil, fmt.Errorf("computed.yaml: invalid computed fields")
		}
	}
	data, err = readConfig("retention.yaml")
	if err != nil {
		return nil, err
	}
	var retentionDocument retentionFileConfig
	if err := decodeConfigYAML(data, &retentionDocument); err != nil {
		return nil, fmt.Errorf("retention.yaml: %w", err)
	}
	for _, policy := range retentionDocument.Policies {
		if strings.TrimSpace(policy.Table) == "" || parseTTLDuration(policy.TTL) <= 0 {
			return nil, fmt.Errorf("retention.yaml: policy requires table and positive ttl")
		}
		// table and (when set) column are spliced into the DELETE the
		// retention worker runs; a plain identifier only.
		if err := configIdentError("retention.yaml: policy table", strings.TrimSpace(policy.Table)); err != nil {
			return nil, err
		}
		if col := strings.TrimSpace(policy.Column); col != "" {
			if err := configIdentError("retention.yaml: policy column", col); err != nil {
				return nil, err
			}
		}
	}
	c.encrypted = parseEncryptedFieldsConfig(encData, appData)
	return c, nil
}

// Schema reads use reviewed byte strings; generated migration and runtime paths
// still use the original app directory. Missing captured files stay missing.
func (c *runtimeConfig) schemaSource(dir, name string) ([]byte, error) {
	if c.mcp == nil {
		return os.ReadFile(filepath.Join(dir, name))
	}
	data, captured := c.schemaSources[name]
	if !captured {
		return nil, fmt.Errorf("mcp.yaml: missing captured schema input")
	}
	if data == nil {
		return nil, os.ErrNotExist
	}
	return data, nil
}
func (c *runtimeConfig) loadSchema(db *sql.DB, dir string) ([]Table, []string, error) {
	return loadSchemaWithReader(db, dir, func(name string) ([]byte, error) { return c.schemaSource(dir, name) }, c.mcp != nil)
}
func (c *runtimeConfig) annotateFullText(dir string, tables []Table) {
	data, err := c.schemaSource(dir, "schema.prisma")
	if err == nil {
		annotateFullTextFromSource(data, tables)
	}
}

func (c *runtimeConfig) runUserMigrations(ctx context.Context, db *sql.DB, dir string, checkOnly bool) error {
	if c.mcp != nil && c.migrations == nil {
		return fmt.Errorf("mcp.yaml: missing captured migration inputs")
	}
	return runUserMigrationsFromSources(ctx, db, dir, checkOnly, c.migrations)
}
