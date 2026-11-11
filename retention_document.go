//go:build !cli

package main

// retention.yaml as the framework reads it.
//
// One reader (parseRetentionDocument) serves the load, the sweep and the
// write gate, so the three cannot disagree about a file. It used to be three
// readers: the load's check accepted any table and dropped keys it did not
// know, the sweep's parser fell back to created_at, and the write gate only
// checked that the file was YAML. A policy naming _benmore_users deleted
// accounts, `col: updated_at` deleted by created_at, and `ttl: "2w"` passed a
// push and then failed the reload.
//
// A retention policy takes only the app's own tables. Framework tables and
// SQLite's own are refused by name here (frameworkOwnedTableName, the rule
// GetTableNames applies to the live tables) and again by the sweep against
// GetTableNames itself, before any DELETE (retention.go). The framework's
// clean-up of its own tables is separate code and is not a policy: audit rows
// (BENMORE_AUDIT_RETENTION, audit_retention.go), expired sessions
// (auth_sessions.go) and finished jobs (jobs.go pruneOldJobs).

import (
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// retentionPolicyYAML is one entry of retention.yaml's policies: list. Its
// tags are the keys a policy takes (retentionPolicyKeys).
type retentionPolicyYAML struct {
	Table  string `yaml:"table"`
	TTL    string `yaml:"ttl"`
	Column string `yaml:"column"`
}

type retentionFileConfig struct {
	Policies []retentionPolicyYAML `yaml:"policies"`
}

var (
	retentionFileKeys   = yamlStructKeys(retentionFileConfig{})
	retentionPolicyKeys = yamlStructKeys(retentionPolicyYAML{})
)

// retentionKeyHints name the key an author most likely meant.
var retentionKeyHints = map[string]string{
	"col":              "use `column:`",
	"field":            "use `column:`",
	"timestamp":        "use `column:`",
	"timestamp_column": "use `column:`",
	"date_column":      "use `column:`",
	"by":               "use `column:`",
	"name":             "use `table:`",
	"model":            "use `table:` with the table name",
	"days":             "use `ttl:` with a unit, e.g. `ttl: \"90d\"`",
	"ttl_days":         "use `ttl:` with a unit, e.g. `ttl: \"90d\"`",
	"max_age":          "use `ttl:`",
	"after":            "use `ttl:`",
	"keep":             "use `ttl:`",
	"duration":         "use `ttl:`",
}

// retentionProblem is one thing wrong with retention.yaml.
//
// Fatal problems are the ones the load has always refused the app for (a
// policy without a table or a readable positive ttl, a table or column name
// that is not a plain identifier). Any other problem leaves the app loading:
// the policy it concerns does not run and the load logs it, so a deployed
// file never takes an app down and never deletes by a guess. The write gate
// refuses every problem.
type retentionProblem struct {
	Message string
	Fatal   bool
}

// retentionDocument is a parsed retention.yaml: the policies that run, and
// everything wrong with the rest of the file.
type retentionDocument struct {
	Policies []RetentionPolicy
	Problems []retentionProblem
	// Legacy is set for a file keyed by table name instead of a policies:
	// list (retentionLegacy). Such a file has no Policies and no Problems:
	// it is read as no policy, and warned about instead of refused.
	Legacy *retentionLegacy
}

// loadError is the first problem the load refuses the app for, or nil.
func (d retentionDocument) loadError() error {
	for _, p := range d.Problems {
		if p.Fatal {
			return fmt.Errorf("%s", p.Message)
		}
	}
	return nil
}

// frameworkOwnedTableName reports a table name the framework or SQLite owns:
// the name rule GetTableNames applies to the live tables (eligibleCRUDTables).
// Config that deletes or rewrites rows by table name uses it where no
// database is open; with one, GetTableNames is the authority.
func frameworkOwnedTableName(name string) bool {
	return crudInternalName.MatchString(sqliteIdentifierFold(strings.TrimSpace(name)))
}

const retentionOwnTablesRule = "A retention policy takes only the app's own tables: a policy never deletes from a framework table (_benmore_*) or one of SQLite's own (sqlite_*)."

const retentionExample = "policies:\n  - table: events\n    ttl: \"90d\"\n    column: created_at   # optional; the default"

// parseRetentionDocument reads retention.yaml. The error is a file that is
// not readable as one (YAML syntax, a second document, policies: that is not
// a list of mappings); the load refuses the app for it.
func parseRetentionDocument(data []byte) (retentionDocument, error) {
	var doc retentionDocument
	var typed retentionFileConfig
	if err := decodeConfigYAML(data, &typed); err != nil {
		return doc, err
	}
	// The typed decode drops every key its structs do not bind; the same
	// document as plain maps says which keys were written.
	var raw map[string]any
	if err := decodeConfigYAML(data, &raw); err != nil {
		return doc, err
	}
	if legacy := readRetentionLegacy(data); legacy != nil {
		doc.Legacy = legacy
		return doc, nil
	}
	for _, key := range slices.Sorted(maps.Keys(raw)) {
		if retentionFileKeys[key] {
			continue
		}
		doc.Problems = append(doc.Problems, retentionProblem{Message: fmt.Sprintf(
			"retention.yaml: top-level key %q is not read, so nothing is deleted for it. Policies are a list under `policies:`, one entry per table:\n%s",
			key, retentionExample)})
	}
	entries, _ := raw["policies"].([]any)
	for i, policy := range typed.Policies {
		n := i + 1
		table, column := strings.TrimSpace(policy.Table), strings.TrimSpace(policy.Column)
		ttl := parseTTLDuration(policy.TTL)
		// The load's own refusals, in the order it has always made them.
		fatal := func(err error) {
			doc.Problems = append(doc.Problems, retentionProblem{Message: err.Error(), Fatal: true})
		}
		if table == "" || ttl <= 0 {
			fatal(fmt.Errorf("retention.yaml: policy requires table and positive ttl"))
			continue
		}
		// table and column are spliced into the DELETE the sweep runs.
		if err := configIdentError("retention.yaml: policy table", table); err != nil {
			fatal(err)
			continue
		}
		if column != "" {
			if err := configIdentError("retention.yaml: policy column", column); err != nil {
				fatal(err)
				continue
			}
		}
		skipped := false
		skip := func(format string, args ...any) {
			doc.Problems = append(doc.Problems, retentionProblem{Message: fmt.Sprintf(format, args...)})
			skipped = true
		}
		var written map[string]any
		if i < len(entries) {
			written, _ = entries[i].(map[string]any)
		}
		for _, key := range slices.Sorted(maps.Keys(written)) {
			if retentionPolicyKeys[key] {
				continue
			}
			hint := ""
			if h := retentionKeyHints[strings.ToLower(key)]; h != "" {
				hint = " (" + h + ")"
			}
			skip("retention.yaml: policy %d (table %s) has the key %q, which a policy does not take%s; its keys are %s. The policy does not run: with a misspelled `column:` it would delete by created_at instead.",
				n, table, key, hint, sortedKeyList(retentionPolicyKeys))
		}
		if _, present := written["column"]; present && column == "" {
			skip("retention.yaml: policy %d (table %s) has an empty `column:`. Name the timestamp column to delete by, or remove the key (the default is created_at). The policy does not run.", n, table)
		}
		if frameworkOwnedTableName(table) {
			skip("retention.yaml: policy %d names %s. %s The policy does not run; remove it. Audit rows are kept or deleted by BENMORE_AUDIT_RETENTION, and the framework cleans up expired sessions and finished jobs itself.",
				n, table, retentionOwnTablesRule)
		}
		if skipped {
			continue
		}
		if column == "" {
			column = "created_at"
		}
		doc.Policies = append(doc.Policies, RetentionPolicy{Table: table, TTL: ttl, Column: column})
	}
	return doc, nil
}

// inlineRetentionProblem is the message for an app.yaml that carries the
// retired inline `retention:` section, or "" when it has none. The write gate
// has always refused the key while the runtime ran it; now neither does.
func inlineRetentionProblem(appData []byte) string {
	var raw map[string]any
	if yamlUnmarshal(appData, &raw) != nil {
		return ""
	}
	section, present := raw["retention"]
	if !present || section == nil {
		return ""
	}
	tables, _ := section.(map[string]any)
	return fmt.Sprintf("app.yaml: `retention:` is not read (%d table(s) named there are not swept). Retention policies go in retention.yaml:\n%s",
		len(tables), retentionExample)
}

// retentionLegacy is a retention.yaml keyed by table name:
//
//	messages:            tables:
//	  ttl: 90d             access_logs:
//	  column: created_at     ttl_days: 90
//	                         timestamp_column: created_at
//
// No scaffold or recipe writes it; authors guessed it, and every
// retention.yaml in the fleet (18 instances, November 2026) had one of these
// two forms. The file has only ever been read as no policy. It stays that
// way (honouring it would begin deleting rows in apps whose owners have never
// seen a sweep), but it is not refused like other unreadable files: the write
// gate, `benmore check`, the load and the admin health report say that no
// policy is running and print the same tables, ttl and column in the form
// that is read. Only a file that converts cleanly counts: a framework table,
// a key an entry does not take or an unreadable ttl is refused as before.
type retentionLegacy struct {
	Policies []retentionPolicyYAML // as the author wrote them, in file order
}

// retentionLegacyEntryKeys are the keys an entry of the table-keyed form
// takes: the two the fleet's files use for the ttl and the two for the column.
var retentionLegacyEntryKeys = map[string]bool{"ttl": true, "ttl_days": true, "column": true, "timestamp_column": true}

// readRetentionLegacy returns the table-keyed form of data, or nil when data
// is anything else (a policies: list included).
func readRetentionLegacy(data []byte) *retentionLegacy {
	var root yaml.Node
	if decodeConfigYAML(data, &root) != nil {
		return nil
	}
	doc := &root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode || len(doc.Content) == 0 {
		return nil
	}
	entries := doc
	// A single `tables:` key that holds the entries, unless `tables` is
	// itself a table with a ttl.
	if len(doc.Content) == 2 && doc.Content[0].Value == "tables" && doc.Content[1].Kind == yaml.MappingNode {
		if _, ok := retentionLegacyEntry("tables", doc.Content[1]); !ok {
			entries = doc.Content[1]
		}
	}
	legacy := &retentionLegacy{}
	for i := 0; i+1 < len(entries.Content); i += 2 {
		policy, ok := retentionLegacyEntry(entries.Content[i].Value, entries.Content[i+1])
		if !ok {
			return nil
		}
		legacy.Policies = append(legacy.Policies, policy)
	}
	if len(legacy.Policies) == 0 {
		return nil
	}
	return legacy
}

// retentionLegacyEntry reads one `<table>: ...` entry of the table-keyed
// form: a ttl string, or a mapping with a ttl (or ttl_days) and optionally a
// column (or timestamp_column). ok is false for anything that would not be a
// valid policy on one of the app's own tables.
func retentionLegacyEntry(table string, value *yaml.Node) (retentionPolicyYAML, bool) {
	policy := retentionPolicyYAML{Table: strings.TrimSpace(table)}
	if policy.Table == "policies" || configIdentError("table", policy.Table) != nil || frameworkOwnedTableName(policy.Table) {
		return policy, false
	}
	if value.Kind == yaml.AliasNode && value.Alias != nil {
		value = value.Alias
	}
	switch value.Kind {
	case yaml.ScalarNode:
		policy.TTL = strings.TrimSpace(value.Value)
	case yaml.MappingNode:
		seen := map[string]bool{}
		for i := 0; i+1 < len(value.Content); i += 2 {
			key, v := value.Content[i].Value, value.Content[i+1]
			if !retentionLegacyEntryKeys[key] || seen[key] || v.Kind != yaml.ScalarNode {
				return policy, false
			}
			seen[key] = true
			text := strings.TrimSpace(v.Value)
			switch key {
			case "ttl":
				policy.TTL = text
			case "ttl_days":
				days, err := strconv.Atoi(text)
				if err != nil || days <= 0 {
					return policy, false
				}
				policy.TTL = strconv.Itoa(days) + "d"
			default: // column, timestamp_column
				policy.Column = text
			}
		}
		if seen["ttl"] && seen["ttl_days"] || seen["column"] && seen["timestamp_column"] {
			return policy, false
		}
		if (seen["column"] || seen["timestamp_column"]) && configIdentError("column", policy.Column) != nil {
			return policy, false
		}
	default:
		return policy, false
	}
	if parseTTLDuration(policy.TTL) <= 0 {
		return policy, false
	}
	return policy, true
}

// correctedFile is the same tables, ttl and column as a policies: list, the
// form the app reads. parseRetentionDocument accepts it without a problem.
func (l *retentionLegacy) correctedFile() string {
	var b strings.Builder
	b.WriteString("policies:\n")
	for _, p := range l.Policies {
		fmt.Fprintf(&b, "  - table: %s\n    ttl: %q\n", p.Table, p.TTL)
		if p.Column != "" {
			fmt.Fprintf(&b, "    column: %s\n", p.Column)
		}
	}
	return b.String()
}

// retentionNoPolicyNote is the one-line state of an app whose retention.yaml
// is in the table-keyed form (the admin health report shows it).
const retentionNoPolicyNote = "retention.yaml: no policy is running"

// warning is what the write gate, `benmore check` and the load say about a
// table-keyed file.
func (l *retentionLegacy) warning() string {
	return retentionNoPolicyNote + ". This file names its tables at the top level, a form the app does not read: it has never run and nothing has been deleted for it. " +
		"Retention policies are a list under `policies:`. The same tables, ttl and column in that form:\n\n" + l.correctedFile() +
		"\nWith that file the app deletes the rows older than each ttl, about 5 seconds after its next start or reload and then every hour, " +
		"so check each ttl and column before you push it. To keep every row, delete retention.yaml."
}

// retentionLegacyWarning is the warning for a retention.yaml in the
// table-keyed form, or "" for any other file. With appDir it also names the
// tables and columns of the corrected file that the schema does not have.
func retentionLegacyWarning(appDir, content string) string {
	legacy := readRetentionLegacy([]byte(content))
	if legacy == nil {
		return ""
	}
	msg := legacy.warning()
	if doc, err := parseRetentionDocument([]byte(legacy.correctedFile())); err == nil {
		for _, line := range retentionSchemaProblems(appDir, doc.Policies) {
			msg += "\n" + line
		}
	}
	return msg
}

// retentionLegacyFindings is the `benmore check` and post-write finding for a
// table-keyed retention.yaml: a warning, never an error, so a push or deploy
// of an app that carries one is not refused.
func retentionLegacyFindings(dir string) []CheckFinding {
	data, err := readFileInRoot(dir, "retention.yaml")
	if err != nil {
		return nil
	}
	msg := retentionLegacyWarning(dir, string(data))
	if msg == "" {
		return nil
	}
	return []CheckFinding{{Severity: "warning", Source: "retention", File: "retention.yaml", Message: msg}}
}

// retentionProblemsFor lists what a load says about the app's retention
// sources: every problem of retention.yaml and an app.yaml that still carries
// `retention:`.
func retentionProblemsFor(retentionData, appData []byte) []string {
	var out []string
	doc, err := parseRetentionDocument(retentionData)
	if err != nil {
		out = append(out, "retention.yaml: "+err.Error())
	}
	for _, p := range doc.Problems {
		out = append(out, p.Message)
	}
	if msg := inlineRetentionProblem(appData); msg != "" {
		out = append(out, msg)
	}
	return out
}

// retentionLegacyLogged holds the table-keyed warnings already logged, by app
// directory and text: the corrected file is long, and an app reloads at every
// push.
var retentionLegacyLogged sync.Map

// logRetentionProblems logs, at every start and reload, each retention policy
// that does not run and why. A hosted app does not run the source check at
// start, so this is where the owner of a deployed file hears about it. The
// table-keyed warning is logged once per process for the same file.
func logRetentionProblems(app *App) {
	retentionData, appData := app.retentionSources()
	for _, msg := range retentionProblemsFor(retentionData, appData) {
		log.Printf("RETENTION NOT RUNNING: %s", msg)
	}
	if legacy := readRetentionLegacy(retentionData); legacy != nil {
		msg := legacy.warning()
		if _, logged := retentionLegacyLogged.LoadOrStore(app.Dir+"\x00"+msg, true); !logged {
			log.Printf("RETENTION NOT RUNNING: %s", msg)
		}
	}
}

// retentionHealth is the admin health report's `retention` check: how many
// policies run and what does not. ok is false for an app that declares no
// retention at all.
func retentionHealth(app *App) (map[string]any, bool) {
	retentionData, appData := app.retentionSources()
	doc, err := parseRetentionDocument(retentionData)
	problems := retentionProblemsFor(retentionData, appData)
	if err != nil {
		doc = retentionDocument{}
	}
	if doc.Legacy == nil && len(doc.Policies) == 0 && len(problems) == 0 {
		return nil, false
	}
	check := map[string]any{"status": "ok", "policies_running": len(doc.Policies)}
	switch {
	case doc.Legacy != nil:
		check["status"] = "not_running"
		check["note"] = retentionNoPolicyNote
		check["detail"] = doc.Legacy.warning()
	case len(problems) > 0:
		check["status"] = "degraded"
		if len(doc.Policies) == 0 {
			check["status"] = "not_running"
			check["note"] = retentionNoPolicyNote
		}
		check["not_running"] = problems
	}
	return check, true
}

// retentionYAMLViolation is the write gate for retention.yaml (write_file,
// push, deploy and `benmore check`): everything parseRetentionDocument
// reports, then each policy's table and column against the schema as the load
// will find it. "" when the file is clean, and for a file in the table-keyed
// form, which is warned about instead (retentionLegacyFindings).
func retentionYAMLViolation(appDir, content string) string {
	doc, err := parseRetentionDocument([]byte(content))
	if err != nil {
		return "retention.yaml: " + err.Error()
	}
	var lines []string
	for _, p := range doc.Problems {
		lines = append(lines, p.Message)
	}
	lines = append(lines, retentionSchemaProblems(appDir, doc.Policies)...)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

// retentionSchemaProblems names the tables and columns of policies that the
// app's schema does not have (nothing when no schema can be read).
func retentionSchemaProblems(appDir string, policies []RetentionPolicy) []string {
	if appDir == "" {
		return nil
	}
	schema := readLoadRefSchema(loadRefSource{dir: appDir})
	if schema == nil {
		return nil
	}
	var lines []string
	for _, p := range policies {
		switch {
		case !schema.declared[sqliteIdentifierFold(p.Table)] && !schema.migrated[sqliteIdentifierFold(p.Table)]:
			lines = append(lines, fmt.Sprintf("retention.yaml: a policy names the table %q, which is not a table of this app (tables in schema.prisma: %s). The policy does not run.", p.Table, schema.tableList))
		case schema.missingColumn(p.Table, p.Column):
			lines = append(lines, fmt.Sprintf("retention.yaml: the policy on %s deletes by %q, but %s has no column %q (columns in schema.prisma: %s). The policy does not run.", p.Table, p.Column, p.Table, p.Column, schema.columnList(p.Table)))
		}
	}
	return lines
}
