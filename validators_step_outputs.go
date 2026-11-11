//go:build !cli

package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// A `${{ steps.<id>.outputs.<name> }}` that names no output of a `run: sql`
// step resolves to nothing, and nothing compares as empty: `if: ${{
// steps.me.outputs.count }} == 0` against `SELECT member_role ...` never
// matched, so an owner-only invite flow let every member invite. The runtime
// cannot tell a missing column from an empty one, so the write gate compares
// each reference with the columns the step's query returns whenever those are
// known from its text (an explicit SELECT list or RETURNING list; any `*`, or a
// column it cannot name, leaves that step unchecked). A write without
// RETURNING outputs only rows_affected.

var stepOutputRefRe = regexp.MustCompile(`steps\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.(?:first\.([A-Za-z_]\w*)|rows\[\d+\]\.([A-Za-z_]\w*)|([A-Za-z_]\w*))`)

// stepOutputRef is one reference found in a flow: where it is, the step it
// names and the column (or output key) it reads.
type stepOutputRef struct {
	where, step, name string
	guard             bool // in an if: condition
}

// stepOutputRefProblems returns one message per reference to a column the
// referenced SQL step does not return.
func stepOutputRefProblems(file FlowFileGHA) (guards, others []string) {
	outputs := map[string][]string{} // step id -> known output names
	seen := map[string]int{}
	var refs []stepOutputRef
	var walk func(job, path string, steps []FlowStepGHA)
	walk = func(job, path string, steps []FlowStepGHA) {
		for i, s := range steps {
			here := fmt.Sprintf("job %q step %s[%d]", job, path, i)
			if s.ID != "" {
				seen[s.ID]++
				if names, ok := sqlStepOutputNames(s); ok {
					outputs[s.ID] = names
				}
			}
			collect := func(text string, guard bool) {
				for _, m := range stepOutputRefRe.FindAllStringSubmatch(text, -1) {
					name := m[2] + m[3] + m[4]
					refs = append(refs, stepOutputRef{where: here, step: m[1], name: name, guard: guard})
				}
			}
			collect(s.If, true)
			collect(s.ForEach, false)
			collect(s.Query, false)
			collect(flowStepWithText(s.With), false)
			walk(job, path+fmt.Sprintf("[%d].steps", i), s.Steps)
			walk(job, path+fmt.Sprintf("[%d].else", i), s.Else)
			walk(job, path+fmt.Sprintf("[%d].on_error", i), s.OnError)
		}
	}
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		walk(job, "steps", file.Jobs[job].Steps)
	}
	reported := map[string]bool{}
	for _, ref := range refs {
		names, known := outputs[ref.step]
		if !known || seen[ref.step] != 1 || ref.name == "rows" || ref.name == "first" {
			continue
		}
		if slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, ref.name) }) {
			continue
		}
		key := ref.where + "\x00" + ref.step + "\x00" + ref.name
		if reported[key] {
			continue
		}
		reported[key] = true
		returns := "returns the columns " + strings.Join(names, ", ")
		if len(names) == 1 && names[0] == "rows_affected" {
			returns = "is a write without RETURNING, whose only output is rows_affected"
		}
		msg := fmt.Sprintf("%s reads `steps.%s.outputs.%s`, but step %q %s. A missing output reads as empty", ref.where, ref.step, ref.name, ref.step, returns)
		if ref.guard {
			guards = append(guards, msg+", so this condition never sees the value it tests and a guard on it does not guard. Select the column (e.g. `SELECT COUNT(*) AS n ...` and `steps."+ref.step+".outputs.n`), or test for rows with `${{ steps."+ref.step+".outputs.rows }}`.")
		} else {
			others = append(others, msg+". Select the column, or reference one the query returns.")
		}
	}
	return guards, others
}

// stepOutputRefWarnings reports the non-guard references of the flow file just
// written, or of every flow file on a full check.
func stepOutputRefWarnings(dir, writtenPath string) []CheckFinding {
	var findings []CheckFinding
	for _, rel := range flowFilesFor(dir, writtenPath) {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil {
			continue
		}
		_, others := stepOutputRefProblems(file)
		for _, msg := range others {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "step_outputs", File: filepath.ToSlash(rel), Message: filepath.ToSlash(rel) + ": " + msg})
		}
	}
	return findings
}

// flowFilesFor lists the flow files a check covers: the one written, or all.
func flowFilesFor(dir, writtenPath string) []string {
	var files []string
	switch {
	case writtenPath == "":
		if _, err := os.Stat(filepath.Join(dir, "flows.yaml")); err == nil {
			files = append(files, "flows.yaml")
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "flows", "*.yaml"))
		for _, m := range matches {
			files = append(files, filepath.Join("flows", filepath.Base(m)))
		}
	case filepath.Base(writtenPath) == "flows.yaml" || isFlowsSubdirFile(writtenPath):
		files = []string{writtenPath}
	}
	return files
}

// flowStepWithText flattens a step's with: values to text for reference
// scanning.
func flowStepWithText(with map[string]any) string {
	var b strings.Builder
	var add func(v any)
	add = func(v any) {
		switch t := v.(type) {
		case string:
			b.WriteString(t)
			b.WriteByte('\n')
		case map[string]any:
			for _, k := range slices.Sorted(maps.Keys(t)) {
				add(t[k])
			}
		case []any:
			for _, item := range t {
				add(item)
			}
		}
	}
	add(with)
	return b.String()
}

// sqlStepOutputNames returns the outputs a `run: sql` step's query is known
// to produce: its result columns, or rows_affected for a write without
// RETURNING. ok is false when they cannot be read from the text.
func sqlStepOutputNames(s FlowStepGHA) ([]string, bool) {
	if run := ghaStepRunType(s); run != "sql" && !(run == "" && s.Query != "") {
		return nil, false
	}
	query := s.Query
	if q, ok := s.With["query"].(string); ok && q != "" {
		query = q
	}
	if strings.TrimSpace(query) == "" {
		return nil, false
	}
	statements := sqlTokenStatements(sqlTokenize(query))
	if len(statements) != 1 {
		return nil, false
	}
	toks := statements[0]
	verb := sqlStatementVerbIndex(toks)
	if verb >= len(toks) {
		return nil, false
	}
	if strings.EqualFold(toks[verb].text, "SELECT") {
		return sqlResultColumnNames(toks[verb+1:], true)
	}
	if _, ok := sqlStatementWrite(toks); !ok {
		return nil, false
	}
	for i, t := range toks {
		if t.kind == sqlTokWord && strings.EqualFold(t.text, "RETURNING") {
			return sqlResultColumnNames(toks[i+1:], false)
		}
	}
	return []string{"rows_affected"}, true
}

// sqlResultColumnNameEnd are the words that end a SELECT's result list.
var sqlResultColumnNameEnd = map[string]bool{"FROM": true, "WHERE": true, "GROUP": true, "HAVING": true, "WINDOW": true, "ORDER": true, "LIMIT": true, "UNION": true, "INTERSECT": true, "EXCEPT": true}

// sqlResultColumnNameReserved are words that end an expression and so are
// never an implicit alias.
var sqlResultColumnNameReserved = map[string]bool{"END": true, "NULL": true, "TRUE": true, "FALSE": true, "AND": true, "OR": true, "NOT": true, "IS": true, "IN": true, "LIKE": true, "ELSE": true, "THEN": true, "WHEN": true, "CASE": true, "DISTINCT": true, "ALL": true, "CURRENT_TIMESTAMP": true, "CURRENT_DATE": true, "CURRENT_TIME": true}

// sqlResultColumnNames names each item of a result list (the tokens after
// SELECT, or after RETURNING): `col`, `t.col`, `expr AS name` and `expr
// name`. ok is false for `*`, `t.*` or an expression SQLite would name by
// its own text.
func sqlResultColumnNames(toks []sqlToken, selectList bool) ([]string, bool) {
	if selectList && len(toks) > 0 && toks[0].kind == sqlTokWord && (strings.EqualFold(toks[0].text, "DISTINCT") || strings.EqualFold(toks[0].text, "ALL")) {
		toks = toks[1:]
	}
	var items [][]sqlToken
	depth, start := 0, 0
	end := len(toks)
	for i, t := range toks {
		if t.kind == sqlTokPunct {
			switch t.text {
			case "(":
				depth++
			case ")":
				depth--
			case ",":
				if depth == 0 {
					items = append(items, toks[start:i])
					start = i + 1
				}
			}
			continue
		}
		if depth == 0 && selectList && t.kind == sqlTokWord && sqlResultColumnNameEnd[strings.ToUpper(t.text)] {
			end = i
			break
		}
	}
	if depth < 0 {
		return nil, false
	}
	items = append(items, toks[start:end])
	names := make([]string, 0, len(items))
	for _, item := range items {
		name, ok := sqlResultColumnName(item)
		if !ok {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

func sqlResultColumnName(item []sqlToken) (string, bool) {
	n := len(item)
	if n == 0 {
		return "", false
	}
	last := item[n-1]
	if last.kind == sqlTokPunct {
		return "", false // `*`, `t.*`, or an expression ending in a bracket
	}
	named := last.kind == sqlTokIdent || (last.kind == sqlTokWord && !sqlResultColumnNameReserved[strings.ToUpper(last.text)] && !sqlNumberWord(last.text))
	if !named {
		return "", false
	}
	switch {
	case n == 1:
		return last.text, true
	case n >= 2 && item[n-2].kind == sqlTokWord && strings.EqualFold(item[n-2].text, "AS"):
		return last.text, true
	case n == 3 && item[1].kind == sqlTokPunct && item[1].text == ".":
		return last.text, true
	case item[n-2].kind == sqlTokPunct && item[n-2].text == ")":
		return last.text, true // `COUNT(*) n`
	case n == 2 && item[0].kind != sqlTokPunct:
		return last.text, true // `col alias`, `'x' alias`
	}
	return "", false
}

func sqlNumberWord(s string) bool {
	return s != "" && s[0] >= '0' && s[0] <= '9'
}
