//go:build !cli

package main

// Prisma-shaped schema input. The agent writes a `schema.prisma` file
// using a constrained subset of Prisma's DSL - `model`, fields, basic
// scalar types, `@id`, `@default`, `@unique`, `@relation`, `@map`,
// `@@index`, `@@unique`, `@@id`, `@@map`. Output is plain SQLite SQL
// which the existing LoadSchema executes.
//
// Why a subset, not full Prisma:
//   - We don't run Prisma's Rust engine - this is a hand-written Go
//     parser, kept small enough to maintain in-tree (~400 LOC).
//   - The corpus density of "Prisma model files" in training data is
//     enormous; the agent writes the constrained subset naturally
//     without ever needing the parts we drop (enums, JSON columns,
//     generators, datasources - all things the runtime supplies).
//   - SQLite is the only target. `datasource db { provider = ... }`
//     is implicit and not honored.
//
// Compilation strategy:
//   - Pluralize + snake-case the model name → table name. `Note` → `notes`.
//     Override with `@@map("custom_name")`.
//   - Snake-case the field name → column name. `userId` → `user_id`.
//     Override with `@map("custom_name")`.
//   - `Int @id @default(autoincrement())` → `INTEGER PRIMARY KEY AUTOINCREMENT`.
//   - `DateTime @default(now())` → `DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP`.
//   - `@relation(fields: [a], references: [b])` → `FOREIGN KEY (a) REFERENCES other(b)`.
//   - `?` suffix on type → nullable (omit NOT NULL).
//   - `[]` suffix on type → reverse relation, skipped (Prisma's convention
//     is that the FK lives only on the owning side).
//
// What the agent writes:
//
//   model User {
//     id        Int      @id @default(autoincrement())
//     email     String   @unique
//     firstName String   @map("first_name")
//     notes     Note[]
//     createdAt DateTime @default(now()) @map("created_at")
//   }
//
//   model Note {
//     id        Int      @id @default(autoincrement())
//     title     String
//     body      String   @default("")
//     userId    Int      @map("user_id")
//     user      User     @relation(fields: [userId], references: [id])
//     createdAt DateTime @default(now()) @map("created_at")
//
//     @@index([userId, createdAt])
//   }
//
// What we emit:
//
//   CREATE TABLE IF NOT EXISTS users (
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     email TEXT NOT NULL UNIQUE,
//     first_name TEXT NOT NULL,
//     created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
//   );
//   CREATE TABLE IF NOT EXISTS notes (
//     id INTEGER PRIMARY KEY AUTOINCREMENT,
//     title TEXT NOT NULL,
//     body TEXT NOT NULL DEFAULT '',
//     user_id INTEGER NOT NULL,
//     created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
//     FOREIGN KEY (user_id) REFERENCES users(id)
//   );
//   CREATE INDEX IF NOT EXISTS idx_notes_user_id_created_at ON notes(user_id, created_at);

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PrismaModel is one `model X { ... }` block, partially resolved into
// the bits we need to emit SQL.
type PrismaModel struct {
	Name       string        // PascalCase from the .prisma file
	Table      string        // snake-cased, pluralized, or @@map override
	Fields     []PrismaField // scalar + FK-owning fields, in declaration order
	Indexes    []PrismaIndex // @@index entries
	Uniques    []PrismaIndex // @@unique entries (same shape, different emit)
	CompoundID []string      // @@id([a, b]) columns; empty when single-field @id
	FullText   []PrismaIndex // @@fulltext([title, body]) - backed by SQLite FTS5
}

// PrismaField is one line inside a model block. Reverse-relation list
// fields (`notes Note[]`) are recognized and excluded - they have no
// column.
type PrismaField struct {
	Name      string // original PascalCase/camelCase
	Column    string // snake-cased or @map override
	Type      string // SQLite type (INTEGER/TEXT/REAL/DATETIME/BLOB)
	Optional  bool   // `?` suffix
	IsID      bool   // @id
	IsUnique  bool   // @unique
	Default   string // SQL default expression, already quoted/literal
	Autoincr  bool   // @default(autoincrement()) on @id Int
	UpdatedAt bool   // @updatedAt - emit AFTER UPDATE trigger
	FKTable   string // FOREIGN KEY target table (snake-cased)
	FKColumn  string // FOREIGN KEY target column
}

// PrismaIndex is `@@index([a, b])` or `@@unique([a, b])` - columns
// already mapped to their snake_case names. Sorts is parallel to
// Columns: "" (default/ASC) or "DESC", from a per-column qualifier
// like `occurredAt(sort: Desc)`.
type PrismaIndex struct {
	Columns []string
	Sorts   []string
}

// ParsePrismaSchema turns `.prisma` source into a list of models.
// Errors are aggregated and returned as one - we want the agent to see
// every problem at once, not fix-iterate one at a time.
//
// Reserved-model rejection: declaring `model User` (or any other model
// that overlaps with a framework-managed table) is flagged with a
// prescriptive error. The framework owns `_benmore_users` for auth;
// a user-declared `User` model creates a parallel empty `users` table
// that breaks every FK pointing at it. This was the exact rabbit hole
// the Haiku May-17 to-do app went down for ~20 turns.
func ParsePrismaSchema(src string) ([]PrismaModel, error) {
	src = stripPrismaComments(src)

	var models []PrismaModel
	var errs []string

	// Reserved model names. The framework owns these tables internally
	// (auth, sessions, audit log, etc.). The agent declaring them
	// creates an empty parallel table the runtime ignores.
	reservedModels := map[string]string{
		"User":     "the framework manages users via the internal `_benmore_users` table. Don't declare `model User { ... }` - your model would create a parallel empty `users` table and any FK pointing at it breaks every INSERT. To reference the logged-in user in your tables, just add `userId Int @map(\"user_id\")` with NO `@relation` attribute. The auto-CRUD POST handler auto-injects `user_id` from the session.",
		"Session":  "sessions are managed internally in `_benmore_sessions`. You can't declare a `model Session`.",
		"AuditLog": "audit history is managed in `_benmore_audit_log`. You can't declare `model AuditLog`.",
	}

	// Find each `model Name { ... }` block. The body is matched with a
	// balanced-brace scan rather than a regex so nested braces in
	// defaults like `@default("{ \"k\": 1 }")` don't trip the parser.
	for i := 0; i < len(src); {
		idx := strings.Index(src[i:], "model ")
		if idx < 0 {
			break
		}
		modelKeywordPos := i + idx
		start := modelKeywordPos + len("model ")
		// Line number of the `model X {` declaration.
		modelStartLine := strings.Count(src[:modelKeywordPos], "\n") + 1
		// Read the model name.
		nameEnd := start
		for nameEnd < len(src) && (isIdentRune(src[nameEnd])) {
			nameEnd++
		}
		name := src[start:nameEnd]
		// Find the opening brace.
		bracePos := strings.Index(src[nameEnd:], "{")
		if bracePos < 0 {
			errs = append(errs, fmt.Sprintf("schema.prisma line %d, model %s: no opening brace", modelStartLine, name))
			break
		}
		bodyStart := nameEnd + bracePos + 1
		// Match braces to find the body end.
		depth := 1
		j := bodyStart
		for j < len(src) && depth > 0 {
			switch src[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
			j++
		}
		if depth != 0 {
			errs = append(errs, fmt.Sprintf("schema.prisma line %d, model %s: unclosed brace", modelStartLine, name))
			break
		}
		body := src[bodyStart : j-1]
		i = j

		// Reject reserved model names with a prescriptive message.
		if explanation, reserved := reservedModels[name]; reserved {
			errs = append(errs, fmt.Sprintf(
				"schema.prisma line %d: model %q is reserved - %s",
				modelStartLine, name, explanation))
			continue
		}

		model, mErrs := parsePrismaModel(name, body, modelStartLine)
		if len(mErrs) > 0 {
			errs = append(errs, mErrs...)
		}
		models = append(models, model)
	}

	// Resolve relation targets - `@relation(fields: [userId], references: [id])`
	// only names the column on this side and the column on the *related*
	// model. The related model's table name comes from the field's
	// declared type, which we know is another model in this file.
	//
	// Reserved-target handling: if the @relation points at a reserved
	// model name (User, Session, AuditLog), we DROP the FK entirely.
	// Emitting FOREIGN KEY (user_id) REFERENCES users(id) would target
	// a non-existent / empty table and break every INSERT. The
	// framework's auth ensures user_id is always a valid
	// _benmore_users.id, so the FK is redundant anyway.
	modelByName := map[string]string{}
	for _, m := range models {
		modelByName[m.Name] = m.Table
	}
	for mi := range models {
		for fi := range models[mi].Fields {
			f := &models[mi].Fields[fi]
			if f.FKTable != "" {
				if _, reserved := reservedModels[f.FKTable]; reserved {
					// Silently drop - the agent's intent (link to the
					// authenticated user) is satisfied by the
					// framework's auto-CRUD user_id injection.
					f.FKTable = ""
					f.FKColumn = ""
					continue
				}
				if t, ok := modelByName[f.FKTable]; ok {
					f.FKTable = t
				}
				// If the related model isn't in this file we just trust
				// the user's spelling; SQLite will error at execute time
				// if the table really doesn't exist.
			}
		}
	}

	if len(errs) > 0 {
		return models, fmt.Errorf("prisma schema:\n  %s", strings.Join(errs, "\n  "))
	}
	return models, nil
}

// parsePrismaModel parses one model body. The body is tokenized into
// "statements" - each is either a field declaration or a block-level
// `@@`-prefixed attribute, with the line number of where it started.
// Errors reference that line so the agent jumps to the offending row.
//
// Relation pointer fields like `user User @relation(fields: [userId],
// references: [id])` are NOT emitted as columns - they're metadata
// describing the foreign key on the scalar field named in `fields: [...]`.
func parsePrismaModel(name, body string, modelStartLine int) (PrismaModel, []string) {
	m := PrismaModel{Name: name, Table: pluralizeSnake(name)}
	var errs []string

	fkPending := map[string]struct{ table, column string }{}

	for _, stmt := range tokenizePrismaStatements(body) {
		line := strings.TrimSpace(stmt.text)
		if line == "" {
			continue
		}
		absLine := modelStartLine + stmt.line
		// Block-level: @@id, @@index, @@unique, @@map.
		if strings.HasPrefix(line, "@@") {
			if err := applyBlockAttr(&m, line); err != nil {
				errs = append(errs, fmt.Sprintf("schema.prisma line %d, model %s: %s", absLine, name, err))
			}
			continue
		}
		f, isField, fkSourceField, err := parsePrismaField(line)
		if err != nil {
			errs = append(errs, fmt.Sprintf("schema.prisma line %d, model %s: %s", absLine, name, err))
			continue
		}
		if fkSourceField != "" {
			fkPending[fkSourceField] = struct{ table, column string }{f.FKTable, f.FKColumn}
			continue
		}
		if !isField {
			continue
		}
		m.Fields = append(m.Fields, f)
	}

	// Attach pending FKs to their scalar columns. The pending key is
	// already snake-cased (parsePrismaRelation lowercased the source
	// field name), so we look up by Column not Name.
	for i := range m.Fields {
		f := &m.Fields[i]
		if pend, ok := fkPending[f.Column]; ok {
			f.FKTable = pend.table
			f.FKColumn = pend.column
			delete(fkPending, f.Column)
		}
	}
	// Any leftover pending FKs reference scalar fields that weren't
	// declared - that's user error; flag it so the linter catches it
	// before they hit a SQL error at runtime.
	for srcField := range fkPending {
		errs = append(errs, fmt.Sprintf(
			"model %s: @relation references field %q which isn't declared on this model. Add `%s Int` (or the matching type) alongside the relation pointer.",
			name, srcField, srcField))
	}
	return m, errs
}

// prismaStatement carries the source text of one parsed statement
// plus the 1-based line number where it started. The line number
// lets parsePrismaModel report errors like "model Note (line 7): ..."
// so the agent jumps straight to the offending row.
type prismaStatement struct {
	text string
	line int // 1-based line within the model body
}

// tokenizePrismaStatements walks a model body and emits one statement
// per field declaration or `@@` block attribute. Statement bounds:
// newline at paren-depth-0, `;` at paren-depth-0, OR the next
// identifier-at-start-of-statement when the buffer already holds a
// complete field tail (handles single-line model bodies).
//
// Each statement carries its starting line number (1-based, relative
// to the start of the body) for error reporting.
func tokenizePrismaStatements(body string) []prismaStatement {
	var out []prismaStatement
	var cur strings.Builder
	depth := 0
	inString := false
	currentLine := 1
	statementStartLine := 1

	flush := func() {
		s := strings.TrimSpace(cur.String())
		if s != "" {
			out = append(out, prismaStatement{text: s, line: statementStartLine})
		}
		cur.Reset()
		statementStartLine = currentLine
	}

	for i := 0; i < len(body); i++ {
		c := body[i]

		// Track newlines for line counting even inside string literals
		// so the next statement gets the right line number.
		if c == '\n' {
			currentLine++
		}

		// String literal tracking - Prisma uses double quotes. Escape
		// paren counting inside strings so @default("Hello (world)")
		// doesn't open a fake paren.
		if c == '"' && (i == 0 || body[i-1] != '\\') {
			inString = !inString
			cur.WriteByte(c)
			continue
		}
		if inString {
			cur.WriteByte(c)
			continue
		}

		switch c {
		case '(', '[':
			depth++
			cur.WriteByte(c)
		case ')', ']':
			if depth > 0 {
				depth--
			}
			cur.WriteByte(c)
		case '\n', ';':
			if depth == 0 {
				flush()
			} else {
				cur.WriteByte(c)
			}
		default:
			// New statement starting mid-line. At depth 0 when we see
			// a letter at the start of a token AND the buffer already
			// has a complete field tail, treat as a boundary.
			if depth == 0 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '@') {
				if c != '@' && isFieldBoundary(cur.String()) {
					flush()
				}
			}
			cur.WriteByte(c)
		}
	}
	flush()
	// Empty-buffer leading whitespace can leave statementStartLine
	// pointing one line ahead of the first real token; not fatal.
	return out
}

// isFieldBoundary reports whether the buffer so far looks like a
// complete field declaration that's followed by whitespace and now a
// new identifier-starting character. The heuristic is conservative:
// the buffer must already contain at least one whitespace boundary
// after the field name AND a recognized closing token (paren-balanced
// attr, scalar type word, `?`, `]`).
func isFieldBoundary(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	tokens := strings.Fields(trimmed)
	if len(tokens) < 2 {
		// Only the field name has been seen so far. Not a boundary.
		return false
	}
	// The buffer also must end in actual whitespace - otherwise we're
	// still mid-token (e.g. we just saw `@` before the next letter
	// lands) and the buffer's last token is half-formed. A boundary
	// only makes sense at a real whitespace gap between tokens.
	last := s[len(s)-1]
	if last != ' ' && last != '\t' {
		return false
	}
	lastTok := tokens[len(tokens)-1]
	// Boundary if the trailing token is one of:
	//   - a complete `@attr(...)` (ends in `)`)
	//   - a bare attr without parens (starts with `@`, has a name
	//     after the `@`, and has no `(`)
	//   - a scalar type word (Int/String/...)
	//   - a `?`-suffixed type or `[]`-suffixed list
	switch {
	case strings.HasSuffix(lastTok, ")"):
		return true
	case strings.HasPrefix(lastTok, "@") && !strings.Contains(lastTok, "(") && len(lastTok) > 1:
		// `@` alone is half-formed - don't count it. `@id` (2+ chars)
		// is a complete bare attr.
		return true
	case strings.HasSuffix(lastTok, "?") || strings.HasSuffix(lastTok, "[]"):
		return true
	}
	// Bare type word as the 2nd token of a field - e.g. `id Int` -
	// is itself a complete field with no attrs.
	if len(tokens) == 2 {
		switch lastTok {
		case "Int", "BigInt", "String", "Boolean", "Float", "Decimal", "DateTime", "Bytes":
			return true
		}
		// Or a custom Type referencing another model (relation pointer
		// with no @relation attr - typically a reverse single relation).
		if isCapitalIdent(lastTok) {
			return true
		}
	}
	return false
}

func isCapitalIdent(s string) bool {
	if s == "" {
		return false
	}
	if s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// fieldLineRe pulls out the leading `name Type[modifier]` tokens. The
// attribute soup that follows is parsed separately so multi-arg attrs
// like @default(now()) can carry parens.
var fieldLineRe = regexp.MustCompile(`^(\w+)\s+(\w+)(\??\[?\]?)(.*)$`)

// parsePrismaField returns (field, isColumnField, fkSourceFieldName, err).
//   - When the line is a normal scalar field, returns the populated
//     PrismaField with isColumnField=true and fkSourceFieldName="".
//   - When the line is an object-pointer relation field (e.g.
//     `user User @relation(fields: [userId], references: [id])`),
//     returns isColumnField=false and fkSourceFieldName="userId" so
//     the caller can attach the FK to that scalar field.
//   - When the line is a reverse-list relation (`notes Note[]`),
//     returns isColumnField=false, fkSourceFieldName="".
func parsePrismaField(line string) (PrismaField, bool, string, error) {
	m := fieldLineRe.FindStringSubmatch(line)
	if m == nil {
		return PrismaField{}, false, "", fmt.Errorf("unrecognized line: %q", line)
	}
	name, prismaType, mods, attrs := m[1], m[2], m[3], strings.TrimSpace(m[4])

	// Reverse relations like `notes Note[]` carry no SQL column.
	if strings.Contains(mods, "[]") {
		return PrismaField{}, false, "", nil
	}

	// Boolean → BOOLEAN (SQLite stores as integer 0/1 but reports the
	// declared type, which lets scanRows() coerce values back to
	// real Go bools so JSON responses emit `true`/`false` instead of
	// `0`/`1`. Without that round-trip, React patterns like
	// `{flag && <Comp/>}` render "0" on the page when flag is falsy.
	scalarMap := map[string]string{
		"Int": "INTEGER", "BigInt": "INTEGER",
		"String": "TEXT", "Boolean": "BOOLEAN",
		"Float": "REAL", "Decimal": "REAL",
		"DateTime": "DATETIME", "Bytes": "BLOB",
	}
	sqlType, isScalar := scalarMap[prismaType]

	f := PrismaField{
		Name:     name,
		Column:   camelToSnake(name),
		Optional: strings.HasPrefix(mods, "?"),
		Type:     sqlType,
	}

	// Walk the attributes.
	var (
		relSourceField string
		relRefColumn   string
		relTargetModel string
	)
	for _, a := range splitAttrs(attrs) {
		switch {
		case a == "@id":
			f.IsID = true
		case a == "@unique":
			f.IsUnique = true
		case a == "@updatedAt":
			// Flag for trigger emission. Also set CURRENT_TIMESTAMP as
			// the insert-time default so the column always has a value;
			// the trigger handles subsequent UPDATEs.
			f.UpdatedAt = true
			if f.Default == "" {
				f.Default = "CURRENT_TIMESTAMP"
			}
		case strings.HasPrefix(a, "@default("):
			f.Default, f.Autoincr = parsePrismaDefault(a)
		case strings.HasPrefix(a, "@map("):
			f.Column = parsePrismaStringArg(a)
		case strings.HasPrefix(a, "@relation("):
			src, ref, target, err := parsePrismaRelation(a, prismaType)
			if err != nil {
				return f, false, "", err
			}
			relSourceField = src
			relRefColumn = ref
			relTargetModel = target
		}
	}

	// Object-pointer relation field: hand the FK metadata back so the
	// caller attaches it to the scalar field named in `fields: [...]`.
	if !isScalar && relSourceField != "" {
		return PrismaField{FKTable: relTargetModel, FKColumn: relRefColumn}, false, relSourceField, nil
	}

	// Non-scalar field with no FK metadata. Two cases:
	//   (a) It's a Type that IS the name of another model in this
	//       file - a reverse-relation single pointer (`profile Profile`).
	//       Convention: capitalized identifier referring to another model.
	//       No SQL column, parser accepts silently.
	//   (b) It's a typo'd type (`Strng`, `intger`, `missing_type_keyword`).
	//       We can't reliably tell these apart at THIS point in the
	//       parse (we don't have the full model list yet), so we mark
	//       this as a "non-scalar reference" - ParsePrismaSchema's
	//       post-parse pass validates against the model list and
	//       emits an error if the type doesn't resolve.
	if !isScalar {
		// Capitalized → tentatively a relation pointer. Lowercase or
		// otherwise non-Pascal → definitely a typo'd type, emit now.
		if !isCapitalIdent(prismaType) {
			return PrismaField{}, false, "", fmt.Errorf("unknown field type %q (field %s). Known scalar types: Int, BigInt, String, Boolean, Float, Decimal, DateTime, Bytes. For relations, reference another model by its PascalCase name", prismaType, name)
		}
		return PrismaField{}, false, "", nil
	}

	// Scalar field that ALSO carries @relation (FK declared inline on
	// the column) - apply directly.
	if relSourceField != "" {
		f.FKTable = relTargetModel
		f.FKColumn = relRefColumn
	}

	return f, true, "", nil
}

// applyBlockAttr handles @@id / @@index / @@unique / @@map.
func applyBlockAttr(m *PrismaModel, line string) error {
	switch {
	case strings.HasPrefix(line, "@@map("):
		m.Table = parsePrismaStringArg(line)
	case strings.HasPrefix(line, "@@id(["):
		cols := parsePrismaColumnList(line)
		// Translate to the column-renamed names - we don't know them
		// yet at parse time, so store the raw field names and resolve
		// later in Emit when we have the field list.
		m.CompoundID = cols
	case strings.HasPrefix(line, "@@index(["):
		cols, sorts := parsePrismaColumnListSorts(line)
		m.Indexes = append(m.Indexes, PrismaIndex{Columns: cols, Sorts: sorts})
	case strings.HasPrefix(line, "@@unique(["):
		cols, sorts := parsePrismaColumnListSorts(line)
		m.Uniques = append(m.Uniques, PrismaIndex{Columns: cols, Sorts: sorts})
	case strings.HasPrefix(line, "@@fulltext(["):
		// Backed by SQLite FTS5 - the framework creates a
		// <table>_fts virtual table + sync triggers at app load
		// (see fts.go). /api/<table>?q=foo routes queries through
		// it for ranked full-text search.
		cols := parsePrismaColumnList(line)
		m.FullText = append(m.FullText, PrismaIndex{Columns: cols})
	default:
		// Other @@ attrs we don't support are silently ignored - they're
		// often Prisma-Studio hints (e.g. @@ignore) with no SQL meaning.
	}
	return nil
}

// splitAttrs splits the attribute soup `@foo @bar(x, y) @baz` into
// individual attribute tokens, respecting parens.
func splitAttrs(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		case ' ', '\t':
			if depth == 0 {
				if i > start {
					out = append(out, strings.TrimSpace(s[start:i]))
				}
				start = i + 1
			}
		}
	}
	if start < len(s) {
		out = append(out, strings.TrimSpace(s[start:]))
	}
	// Filter empties.
	var filtered []string
	for _, a := range out {
		if a != "" {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

func parsePrismaDefault(a string) (sqlDefault string, autoincr bool) {
	inner := strings.TrimSuffix(strings.TrimPrefix(a, "@default("), ")")
	inner = strings.TrimSpace(inner)
	switch {
	case inner == "autoincrement()":
		return "", true
	case inner == "now()":
		return "CURRENT_TIMESTAMP", false
	case inner == "uuid()":
		// SQLite doesn't have native UUID generation, but we can emit
		// a portable equivalent using lower(hex(randomblob(N))) with
		// the canonical 8-4-4-4-12 hex layout. The trailing variant +
		// version bits are NOT set (so these aren't RFC 4122-strict
		// UUIDs), but for app-level row IDs the format match is what
		// matters.
		return "(lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))))", false
	case inner == "cuid()":
		// CUIDs sort lexicographically and embed a timestamp. SQLite
		// has no direct equivalent; we emit a (sortable) timestamp +
		// random suffix that approximates the property the agent
		// usually wants from cuid().
		return "(strftime('%Y%m%d%H%M%S', 'now') || lower(hex(randomblob(6))))", false
	case inner == "true":
		return "1", false
	case inner == "false":
		return "0", false
	case strings.HasPrefix(inner, `"`) && strings.HasSuffix(inner, `"`):
		// String literal - wrap in SQL single quotes, escaping any '.
		stripped := inner[1 : len(inner)-1]
		stripped = strings.ReplaceAll(stripped, "'", "''")
		return "'" + stripped + "'", false
	default:
		// Numeric literal or expression we don't normalize - pass
		// through verbatim and trust SQLite to parse.
		return inner, false
	}
}

// parsePrismaStringArg extracts the first string literal from an attr
// like `@map("user_id")` or `@@map("notes")`.
func parsePrismaStringArg(a string) string {
	start := strings.Index(a, `"`)
	end := strings.LastIndex(a, `"`)
	if start < 0 || end <= start {
		return ""
	}
	return a[start+1 : end]
}

// parsePrismaColumnList extracts `[a, b, c]` from a block attribute.
func parsePrismaColumnList(a string) []string {
	cols, _ := parsePrismaColumnListSorts(a)
	return cols
}

// parsePrismaColumnListSorts parses a bracketed column list where each
// entry may carry a Prisma per-column qualifier - `occurredAt(sort: Desc)`,
// `name(length: 10)`, etc. Splitting is paren-aware (a qualifier can
// contain commas) and the qualifier is STRIPPED from the column name;
// only `sort: Desc` survives, as "DESC" in the parallel sorts slice.
// Pre-fix, the whole entry was camelToSnake'd verbatim, so the emitted
// SQL contained the literal identifier `occurred_at(sort: _desc)` -
// invalid SQLite that failed the migration on every boot.
func parsePrismaColumnListSorts(a string) ([]string, []string) {
	open := strings.Index(a, "[")
	close := strings.LastIndex(a, "]")
	if open < 0 || close <= open {
		return nil, nil
	}
	inner := a[open+1 : close]
	var parts []string
	depth, start := 0, 0
	for i, c := range inner {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, inner[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, inner[start:])
	var cols, sorts []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		sortKw := ""
		if i := strings.Index(p, "("); i >= 0 {
			qual := strings.ToLower(p[i:])
			p = strings.TrimSpace(p[:i])
			if strings.Contains(qual, "sort") && strings.Contains(qual, "desc") {
				sortKw = "DESC"
			}
		}
		if p == "" {
			continue
		}
		cols = append(cols, camelToSnake(p))
		sorts = append(sorts, sortKw)
	}
	return cols, sorts
}

// indexColumnSQL renders the column list for CREATE INDEX, applying
// per-column sort keywords ("col DESC") when present.
func indexColumnSQL(idx PrismaIndex) string {
	parts := make([]string, len(idx.Columns))
	for i, c := range idx.Columns {
		if i < len(idx.Sorts) && idx.Sorts[i] != "" {
			parts[i] = c + " " + idx.Sorts[i]
		} else {
			parts[i] = c
		}
	}
	return strings.Join(parts, ", ")
}

// parsePrismaRelation pulls fields/references columns from a relation
// attribute like `@relation(fields: [userId], references: [id])`. The
// returned (fkColumn, refColumn, refTable) tuple is the FK metadata.
// refTable is initially the related model's name; the post-parse pass
// in ParsePrismaSchema swaps in the snake_cased table name.
func parsePrismaRelation(a, relatedModel string) (string, string, string, error) {
	fieldsRe := regexp.MustCompile(`fields:\s*\[\s*(\w+)\s*\]`)
	refsRe := regexp.MustCompile(`references:\s*\[\s*(\w+)\s*\]`)
	fm := fieldsRe.FindStringSubmatch(a)
	rm := refsRe.FindStringSubmatch(a)
	if fm == nil || rm == nil {
		return "", "", "", fmt.Errorf("@relation missing fields or references: %q", a)
	}
	return camelToSnake(fm[1]), camelToSnake(rm[1]), relatedModel, nil
}

// stripPrismaComments removes `//` line comments. Block comments
// (`/* ... */`) are rare in real Prisma files and we don't support them.
func stripPrismaComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// EmitSQL turns the parsed models into a CREATE TABLE + CREATE INDEX
// stream that LoadSchema can execute directly.
func EmitSQL(models []PrismaModel) string {
	var out strings.Builder
	// Sort models by name for stable output (helps tests + diff review).
	sortedModels := make([]PrismaModel, len(models))
	copy(sortedModels, models)
	sort.SliceStable(sortedModels, func(i, j int) bool {
		return sortedModels[i].Name < sortedModels[j].Name
	})

	for _, m := range sortedModels {
		writeCreateTable(&out, m)
		out.WriteByte('\n')
	}
	// Indexes after all tables - FK targets are guaranteed to exist by
	// then. Same for @@unique compound indexes.
	for _, m := range sortedModels {
		for _, idx := range m.Indexes {
			fmt.Fprintf(&out, "CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s(%s);\n",
				m.Table, strings.Join(idx.Columns, "_"),
				m.Table, indexColumnSQL(idx))
		}
		for _, u := range m.Uniques {
			fmt.Fprintf(&out, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_%s_%s ON %s(%s);\n",
				m.Table, strings.Join(u.Columns, "_"),
				m.Table, indexColumnSQL(u))
		}
	}
	// AFTER UPDATE triggers for @updatedAt fields. SQLite doesn't
	// auto-update DEFAULT CURRENT_TIMESTAMP on UPDATE the way some
	// other engines do - without a trigger, an @updatedAt column
	// silently stays at its insert-time value. The trigger writes
	// the current timestamp on every row change.
	for _, m := range sortedModels {
		for _, f := range m.Fields {
			if !f.UpdatedAt {
				continue
			}
			fmt.Fprintf(&out,
				"CREATE TRIGGER IF NOT EXISTS trg_%s_%s_updated\n"+
					"AFTER UPDATE ON %s\n"+
					"FOR EACH ROW BEGIN\n"+
					"  UPDATE %s SET %s = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;\n"+
					"END;\n",
				m.Table, f.Column, m.Table, m.Table, f.Column)
		}
	}
	return out.String()
}

func writeCreateTable(out *strings.Builder, m PrismaModel) {
	fmt.Fprintf(out, "CREATE TABLE IF NOT EXISTS %s (\n", m.Table)
	var lines []string
	var fks []string

	for _, f := range m.Fields {
		parts := []string{"    " + f.Column, f.Type}
		if f.IsID && f.Type == "INTEGER" && f.Autoincr {
			parts = append(parts, "PRIMARY KEY AUTOINCREMENT")
		} else if f.IsID && len(m.CompoundID) == 0 {
			parts = append(parts, "PRIMARY KEY")
		}
		if !f.Optional && !f.IsID {
			parts = append(parts, "NOT NULL")
		}
		if f.IsUnique {
			parts = append(parts, "UNIQUE")
		}
		if f.Default != "" {
			parts = append(parts, "DEFAULT "+f.Default)
		}
		lines = append(lines, strings.Join(parts, " "))

		if f.FKTable != "" {
			refCol := f.FKColumn
			if refCol == "" {
				refCol = "id"
			}
			fks = append(fks, fmt.Sprintf("    FOREIGN KEY (%s) REFERENCES %s(%s)",
				f.Column, f.FKTable, refCol))
		}
	}

	if len(m.CompoundID) > 0 {
		lines = append(lines, fmt.Sprintf("    PRIMARY KEY (%s)", strings.Join(m.CompoundID, ", ")))
	}

	all := append(lines, fks...)
	out.WriteString(strings.Join(all, ",\n"))
	out.WriteString("\n);\n")
}

// ===== helpers =====

func isIdentRune(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// camelToSnake converts userIdField → user_id_field. Handles
// consecutive uppercase runs sensibly so `HTTPHeaders` → `http_headers`
// (not `h_t_t_p_headers`) and `userID` → `user_id` (not `user_i_d`).
// The rule: insert an underscore before an uppercase letter ONLY when
// the previous char is lowercase, OR when the previous char is
// uppercase but the next char is lowercase (so the upper-run is
// ending and a word boundary belongs there).
func camelToSnake(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		isUpper := r >= 'A' && r <= 'Z'
		if i > 0 && isUpper {
			prev := runes[i-1]
			prevLower := prev >= 'a' && prev <= 'z'
			nextLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
			if prevLower || nextLower {
				b.WriteByte('_')
			}
		}
		if isUpper {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// pluralizeSnake takes a PascalCase model name and returns a
// snake_case plural table name. Rails-style heuristic: handle the
// common English-suffix endings and fall back to appending 's'.
//
// Note: we apply pluralization to the FINAL camel-case word only.
// `UserSession` → `user_sessions` (not `users_sessions`).
func pluralizeSnake(s string) string {
	snake := camelToSnake(s)
	parts := strings.Split(snake, "_")
	last := parts[len(parts)-1]
	parts[len(parts)-1] = pluralizeWord(last)
	return strings.Join(parts, "_")
}

func pluralizeWord(w string) string {
	if w == "" {
		return w
	}
	// y → ies (consonant + y). "category" → "categories", "boy" → "boys".
	if strings.HasSuffix(w, "y") && len(w) > 1 && !isVowel(w[len(w)-2]) {
		return w[:len(w)-1] + "ies"
	}
	// ch, sh, x, s, z → +es. "box" → "boxes".
	for _, suf := range []string{"ch", "sh", "ss", "x", "z"} {
		if strings.HasSuffix(w, suf) {
			return w + "es"
		}
	}
	// Default: +s.
	return w + "s"
}

func isVowel(b byte) bool {
	return b == 'a' || b == 'e' || b == 'i' || b == 'o' || b == 'u'
}
