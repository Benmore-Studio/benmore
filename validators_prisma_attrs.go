//go:build !cli

package main

// schema.prisma declarations the compiler skips. Unsupported field types
// and scalar lists must not silently omit intended columns. parsePrismaField and
// applyBlockAttr apply a fixed set of attributes and pass over every other
// one, so `@uniqe`, `@unique(map: "x")` or `@@unique(fields: [a, b])`
// compiled to a column with no constraint while the schema read as if it
// had one. The write gate and `benmore check` refuse them; the parser (and
// so the loader) is unchanged and a deployed schema keeps loading.

import (
	"fmt"
	"strings"
)

// prismaIgnoredSchemaProblems lists declarations the compiler would not
// apply. Call it only on a schema ParsePrismaSchema accepts, passing its
// complete model list so forward and reverse relations resolve equally.
func prismaIgnoredSchemaProblems(src string, models []PrismaModel) []string {
	knownModels := map[string]bool{"User": true, "Session": true, "AuditLog": true}
	for _, model := range models {
		knownModels[model.Name] = true
	}
	src = stripPrismaComments(src)
	var problems []string
	for i := 0; i < len(src); {
		idx := strings.Index(src[i:], "model ")
		if idx < 0 {
			break
		}
		modelPos := i + idx
		start := modelPos + len("model ")
		nameEnd := start
		for nameEnd < len(src) && isIdentRune(src[nameEnd]) {
			nameEnd++
		}
		name := src[start:nameEnd]
		brace := strings.Index(src[nameEnd:], "{")
		if brace < 0 {
			break
		}
		bodyStart := nameEnd + brace + 1
		bodyLine := strings.Count(src[:bodyStart], "\n") + 1
		depth, j := 1, bodyStart
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
			break
		}
		i = j
		for _, stmt := range tokenizePrismaStatements(src[bodyStart : j-1]) {
			line := strings.TrimSpace(stmt.text)
			where := fmt.Sprintf("schema.prisma line %d, model %s", bodyLine+stmt.line-1, name)
			if strings.HasPrefix(line, "@@") {
				if msg := prismaBlockAttrProblem(line); msg != "" {
					problems = append(problems, where+": "+msg)
				}
				continue
			}
			m := fieldLineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			fieldWhere := fmt.Sprintf("%s, field %s", where, m[1])
			scalar := prismaScalarSQLType(m[2]) != ""
			list := strings.Contains(m[3], "[]")
			if scalar && list {
				problems = append(problems, fmt.Sprintf("%s: scalar list type %q is not supported and creates no column. Use a related child model for multiple values, or a String column with explicit serialization; [] is only supported for model relations.", fieldWhere, m[2]+m[3]))
			} else if !scalar && !knownModels[m[2]] {
				problems = append(problems, fmt.Sprintf("%s: unsupported or undefined type %q is not a scalar or a declared model. An unsupported field creates no column; an undefined relation may leave an invalid foreign-key target. Declare the related model, or use a supported scalar: Int, BigInt, String, Boolean, Float, Decimal, DateTime, Bytes. Json and enum types are not supported; store serialized JSON explicitly in String or use related models.", fieldWhere, m[2]+m[3]))
			}
			if list {
				// A reverse relation has no column, but an ignored action
				// still promises behavior the emitted foreign key lacks.
				for _, a := range splitAttrs(strings.TrimSpace(m[4])) {
					if msg := prismaRelationActionProblem(a); msg != "" {
						problems = append(problems, fieldWhere+": "+msg)
					}
				}
				continue
			}
			for _, a := range splitAttrs(strings.TrimSpace(m[4])) {
				if msg := prismaFieldAttrProblem(a); msg != "" {
					problems = append(problems, fmt.Sprintf("%s, field %s: %s", where, m[1], msg))
				}
			}
		}
	}
	return problems
}

// prismaFieldAttrProblem mirrors the switch in parsePrismaField. @db.*
// native types and @ignore have no SQLite meaning and are accepted.
func prismaFieldAttrProblem(a string) string {
	switch {
	case strings.HasPrefix(a, "@relation("):
		return prismaRelationActionProblem(a)
	case a == "@id", a == "@unique", a == "@updatedAt",
		strings.HasPrefix(a, "@default("), strings.HasPrefix(a, "@map("),
		strings.HasPrefix(a, "@db."), a == "@ignore":
		return ""
	case strings.HasPrefix(a, "@unique("), strings.HasPrefix(a, "@id("):
		bare := a[:strings.Index(a, "(")]
		return fmt.Sprintf("`%s` is not applied: the compiler reads %s only without arguments, so this column gets no %s constraint. Write `%s`.", a, bare, strings.TrimPrefix(bare, "@"), bare)
	}
	return fmt.Sprintf("`%s` is not applied by the schema compiler, so it does nothing. Field attributes it applies: @id, @unique, @default(...), @map(\"...\"), @relation(fields: [...], references: [...]), @updatedAt (@db.* and @ignore are accepted and have no effect).", a)
}

// Match named arguments, not words inside a quoted relation name. Leave the
// loader untouched: it reads fields/references and emits a bare foreign key.
func prismaRelationActionProblem(a string) string {
	if !strings.HasPrefix(a, "@relation(") {
		return ""
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(a, "@relation("), ")")
	argumentProblem := func(arg string) string {
		name, _, named := strings.Cut(strings.TrimSpace(arg), ":")
		name = strings.TrimSpace(name)
		if named && (name == "onDelete" || name == "onUpdate") {
			return fmt.Sprintf("@relation argument %s is not applied by the schema compiler. Referential actions are unsupported; remove this argument. Related rows must be handled explicitly (for deletion, delete child rows before the parent through native CRUD or a native transaction).", name)
		}
		return ""
	}
	start, depth := 0, 0
	quoted, escaped := false, false
	for i, c := range inner {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				if msg := argumentProblem(inner[start:i]); msg != "" {
					return msg
				}
				start = i + 1
			}
		}
	}
	return argumentProblem(inner[start:])
}

// prismaBlockAttrProblem mirrors applyBlockAttr. @@ignore and @@schema
// have no SQLite meaning and are accepted.
func prismaBlockAttrProblem(line string) string {
	for _, p := range []string{"@@map(", "@@id([", "@@index([", "@@unique([", "@@fulltext([", "@@schema("} {
		if strings.HasPrefix(line, p) {
			return ""
		}
	}
	if line == "@@ignore" {
		return ""
	}
	return fmt.Sprintf("`%s` is not applied by the schema compiler, so it does nothing. Block attributes it applies: @@id([a, b]), @@index([a, b]), @@unique([a, b]), @@fulltext([a, b]), @@map(\"table\") - columns as a positional list, not `fields: [...]`.", line)
}
