//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// AppGraph is a dependency graph for multi-agent development.
// It maps every file to its dependencies and what it provides,
// so agents can work on independent parts simultaneously.
type AppGraph struct {
	Nodes          []GraphNode         `json:"nodes"`
	Edges          []GraphEdge         `json:"edges"`
	Parallelism    [][]string          `json:"parallel_groups"`
	Conflicts      []ConflictZone      `json:"conflict_zones"`
	AgentPlan      []AgentTask         `json:"agent_plan,omitempty"`
	TokenBudget    map[string]int      `json:"token_budget,omitempty"`
	ChangeImpact   map[string][]string `json:"change_impact,omitempty"`
	SuggestedTests []string            `json:"suggested_tests,omitempty"`
}

// GraphNode represents a file in the app with its dependencies and outputs.
type GraphNode struct {
	File          string   `json:"file"`
	Type          string   `json:"type"` // page, schema, hooks, flows, design, partial, layout, env
	DependsOn     []string `json:"depends_on"`
	Provides      []string `json:"provides"`
	TablesRead    []string `json:"tables_read,omitempty"`
	TablesWrite   []string `json:"tables_write,omitempty"`
	Partials      []string `json:"includes,omitempty"`
	Layout        string   `json:"layout,omitempty"`
	SafeWith      []string `json:"safe_to_edit_with"`
	ConflictsWith []string `json:"conflicts_with,omitempty"`
	TokenEstimate int      `json:"token_estimate"`
	Complexity    string   `json:"complexity"` // low, medium, high
	ChangeImpact  []string `json:"change_impact,omitempty"`
}

// GraphEdge represents a dependency between two files.
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"` // reads_table, writes_table, includes, uses_layout, triggers_hook, triggers_flow
}

// ConflictZone is a set of files that share a dependency and must be edited sequentially.
type ConflictZone struct {
	Resource string   `json:"resource"` // e.g. "table:contacts", "partial:nav.html"
	Files    []string `json:"files"`
	Reason   string   `json:"reason"`
}

// AgentTask is a suggested work unit for a single agent.
type AgentTask struct {
	ID             string   `json:"id"`
	Files          []string `json:"files"`
	Description    string   `json:"description"`
	CanRunWith     []string `json:"can_run_with"` // other task IDs
	MustWaitFor    []string `json:"must_wait_for,omitempty"`
	TokenEstimate  int      `json:"token_estimate"`
	SuggestedTests []string `json:"suggested_tests,omitempty"`
}

var (
	modelRefRe   = regexp.MustCompile(`:model="([^"]+)"`)
	queryFromRe  = regexp.MustCompile(`from="([^"]+)"`)
	querySQLRe   = regexp.MustCompile(`(?i)(?:FROM|INTO|UPDATE|JOIN)\s+(\w+)`)
	includeRefRe = regexp.MustCompile(`<include\s+src="([^"]+)"`)
	createRefRe  = regexp.MustCompile(`:create="([^"]+)"`)
	deleteRefRe  = regexp.MustCompile(`:delete="([^"]+)"`)
	patchRefRe   = regexp.MustCompile(`:patch="/api/([^/"]+)`)
	fetchRefRe   = regexp.MustCompile(`<fetch\s+url="([^"]+)"`)
	layoutRefRe  = regexp.MustCompile(`layout="([^"]+)"`)

	// Component detection patterns for complexity analysis
	componentPatterns = []string{
		`<table\s`, `<board\s`, `<stat\s`, `<chart\s`, `<card[\s>]`, `<modal\s`,
		`<tabs[\s>]`, `<grid[\s>]`, `<badge\s`, `<nav\s`, `<detail\s`, `<list\s`,
		`<avatar\s`, `<empty\s`, `<skeleton\s`, `<dropdown[\s>]`, `<alert\s`,
		`<progress\s`, `<breadcrumb\s`, `<pagination\s`, `<separator\s*/>`,
		`<timeline\s`, `<toggle\s`, `<copy\s`, `<search[\s>]`, `<accordion[\s>]`,
		`<sheet[\s>]`, `<tooltip[\s>]`, `<hover-card[\s>]`, `<switch\s`, `<kbd\s`, `<meter\s`,
	}
	queryTagPattern     = regexp.MustCompile(`<query\s`)
	directivePattern    = regexp.MustCompile(`:(create|delete|patch|validate)=`)
)

// BuildGraph analyzes an app and generates the dependency graph.
func BuildGraph(app *App) AppGraph {
	graph := AppGraph{}

	// Get all tables
	tableNames, _ := GetTableNames(app.DB)
	var userTables []string
	for _, t := range tableNames {
		if !strings.HasPrefix(t, "_benmore_") {
			userTables = append(userTables, t)
		}
	}

	// --- Build nodes for each file ---

	// Schema
	schemaNode := GraphNode{
		File:     "schema.sql",
		Type:     "schema",
		Provides: make([]string, 0),
	}
	for _, t := range userTables {
		schemaNode.Provides = append(schemaNode.Provides, "table:"+t)
	}
	graph.Nodes = append(graph.Nodes, schemaNode)

	// Track which tables each page uses (for conflict detection)
	fileTableReads := make(map[string][]string)
	fileTableWrites := make(map[string][]string)
	fileIncludes := make(map[string][]string)

	// Pages
	for _, page := range app.Pages {
		node := GraphNode{
			File:      page.File,
			Type:      "page",
			DependsOn: []string{"schema.sql"},
			Provides:  []string{"route:" + page.Route},
		}

		html := page.RawHTML

		// Tables read (via :model, <query from=, raw SQL)
		tablesRead := extractTablesReferenced(html, userTables)
		node.TablesRead = tablesRead
		fileTableReads[page.File] = tablesRead

		for _, t := range tablesRead {
			node.DependsOn = append(node.DependsOn, "table:"+t)
			graph.Edges = append(graph.Edges, GraphEdge{From: page.File, To: "schema.sql", Type: "reads_table"})
		}

		// Tables written (via :create, :delete, :patch)
		tablesWrite := extractTablesWritten(html)
		node.TablesWrite = tablesWrite
		fileTableWrites[page.File] = tablesWrite

		for _, t := range tablesWrite {
			graph.Edges = append(graph.Edges, GraphEdge{From: page.File, To: "schema.sql", Type: "writes_table"})
			_ = t
		}

		// Includes
		includes := includeRefRe.FindAllStringSubmatch(html, -1)
		for _, m := range includes {
			node.Partials = append(node.Partials, m[1])
			node.DependsOn = append(node.DependsOn, "partial:"+m[1])
			fileIncludes[page.File] = append(fileIncludes[page.File], m[1])
			graph.Edges = append(graph.Edges, GraphEdge{From: page.File, To: m[1], Type: "includes"})
		}

		// Layout
		if lm := layoutRefRe.FindStringSubmatch(html); lm != nil && lm[1] != "none" {
			node.Layout = lm[1]
			layoutFile := "layouts/" + lm[1] + ".html"
			node.DependsOn = append(node.DependsOn, layoutFile)
			graph.Edges = append(graph.Edges, GraphEdge{From: page.File, To: layoutFile, Type: "uses_layout"})
		}

		// API endpoints provided
		for _, t := range tablesRead {
			node.Provides = append(node.Provides, "/api/"+t)
		}

		graph.Nodes = append(graph.Nodes, node)
	}

	// Hooks
	if app.Hooks != nil {
		hooksNode := GraphNode{
			File:     "hooks.yaml",
			Type:     "hooks",
			DependsOn: []string{"schema.sql"},
			Provides: []string{},
		}
		for table := range app.Hooks.OnInsert {
			hooksNode.TablesWrite = append(hooksNode.TablesWrite, table)
			hooksNode.DependsOn = append(hooksNode.DependsOn, "table:"+table)
			graph.Edges = append(graph.Edges, GraphEdge{From: "hooks.yaml", To: "schema.sql", Type: "triggers_hook"})
		}
		for table := range app.Hooks.OnUpdate {
			hooksNode.TablesWrite = append(hooksNode.TablesWrite, table)
		}
		for table := range app.Hooks.OnDelete {
			hooksNode.TablesWrite = append(hooksNode.TablesWrite, table)
		}
		graph.Nodes = append(graph.Nodes, hooksNode)
	}

	// Flows
	if len(app.Flows) > 0 {
		flowsNode := GraphNode{
			File:     "flows.yaml",
			Type:     "flows",
			DependsOn: []string{"schema.sql"},
			Provides: []string{},
		}
		for _, flow := range app.Flows {
			if flow.Trigger.Path != "" {
				flowsNode.Provides = append(flowsNode.Provides, "route:"+flow.Trigger.Path)
			}
			if flow.Trigger.Table != "" {
				flowsNode.DependsOn = append(flowsNode.DependsOn, "table:"+flow.Trigger.Table)
			}
			// Scan steps for table refs
			for _, step := range flow.Steps {
				if step.SQL != "" {
					for _, t := range userTables {
						if strings.Contains(strings.ToLower(step.SQL), strings.ToLower(t)) {
							flowsNode.TablesRead = append(flowsNode.TablesRead, t)
						}
					}
				}
			}
		}
		graph.Nodes = append(graph.Nodes, flowsNode)
	}

	// Design
	if app.Design != nil {
		graph.Nodes = append(graph.Nodes, GraphNode{
			File:     "app.yaml",
			Type:     "design",
			Provides: []string{"theme", "seo"},
		})
	}

	// Partials
	for name := range app.Partials {
		graph.Nodes = append(graph.Nodes, GraphNode{
			File:     name,
			Type:     "partial",
			Provides: []string{"partial:" + name},
		})
	}

	// Layouts
	layoutDir := filepath.Join(app.Dir, "layouts")
	if entries, err := os.ReadDir(layoutDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".html") {
				layoutName := strings.TrimSuffix(e.Name(), ".html")
				lNode := GraphNode{
					File:     "layouts/" + e.Name(),
					Type:     "layout",
					Provides: []string{"layout:" + layoutName},
				}
				// Scan layout for includes
				if data, err := os.ReadFile(filepath.Join(layoutDir, e.Name())); err == nil {
					for _, m := range includeRefRe.FindAllStringSubmatch(string(data), -1) {
						lNode.DependsOn = append(lNode.DependsOn, "partial:"+m[1])
						lNode.Partials = append(lNode.Partials, m[1])
					}
				}
				graph.Nodes = append(graph.Nodes, lNode)
			}
		}
	}

	// --- Compute token estimates, complexity, and change impact ---
	computeTokensAndComplexity(&graph, app)
	graph.ChangeImpact = buildChangeImpactMap(&graph)
	graph.SuggestedTests = buildSuggestedTests(&graph, app)

	// --- Compute safe-to-edit-with and conflicts ---
	computeParallelism(&graph, fileTableReads, fileTableWrites, fileIncludes)

	// --- Generate agent plan ---
	graph.AgentPlan = generateAgentPlan(&graph)

	// --- Compute token budgets per parallel group ---
	graph.TokenBudget = make(map[string]int)
	nodeTokens := make(map[string]int)
	for _, n := range graph.Nodes {
		nodeTokens[n.File] = n.TokenEstimate
	}
	for i, group := range graph.Parallelism {
		key := fmt.Sprintf("group-%d", i)
		total := 0
		for _, f := range group {
			total += nodeTokens[f]
		}
		graph.TokenBudget[key] = total
	}

	return graph
}

// computeParallelism determines which files can be edited simultaneously.
func computeParallelism(graph *AppGraph, reads, writes, includes map[string][]string) {
	// Two files conflict if they share a table write, or one reads what the other writes
	conflictMap := make(map[string]map[string]bool)
	sharedResources := make(map[string][]string) // resource → files

	for i := range graph.Nodes {
		n := &graph.Nodes[i]
		if n.Type != "page" {
			continue
		}

		// Track shared resources
		for _, t := range n.TablesRead {
			sharedResources["table:"+t] = append(sharedResources["table:"+t], n.File)
		}
		for _, t := range n.TablesWrite {
			sharedResources["write:"+t] = append(sharedResources["write:"+t], n.File)
		}
		for _, p := range n.Partials {
			sharedResources["partial:"+p] = append(sharedResources["partial:"+p], n.File)
		}
	}

	// Find conflicts: files that both WRITE to the same table
	for resource, files := range sharedResources {
		if !strings.HasPrefix(resource, "write:") {
			continue
		}
		if len(files) > 1 {
			table := strings.TrimPrefix(resource, "write:")
			graph.Conflicts = append(graph.Conflicts, ConflictZone{
				Resource: "table:" + table,
				Files:    files,
				Reason:   fmt.Sprintf("Multiple files write to table '%s' - edit sequentially to avoid CRUD conflicts", table),
			})
			for _, f := range files {
				if conflictMap[f] == nil {
					conflictMap[f] = make(map[string]bool)
				}
				for _, f2 := range files {
					if f != f2 {
						conflictMap[f][f2] = true
					}
				}
			}
		}
	}

	// Compute safe-to-edit-with for each page node
	pageFiles := []string{}
	for i := range graph.Nodes {
		if graph.Nodes[i].Type == "page" {
			pageFiles = append(pageFiles, graph.Nodes[i].File)
		}
	}

	for i := range graph.Nodes {
		n := &graph.Nodes[i]
		if n.Type != "page" {
			continue
		}
		for _, other := range pageFiles {
			if other == n.File {
				continue
			}
			if conflictMap[n.File] == nil || !conflictMap[n.File][other] {
				n.SafeWith = append(n.SafeWith, other)
			} else {
				n.ConflictsWith = append(n.ConflictsWith, other)
			}
		}
	}

	// Group files into parallel batches
	assigned := make(map[string]bool)
	for _, n := range graph.Nodes {
		if n.Type != "page" || assigned[n.File] {
			continue
		}
		group := []string{n.File}
		assigned[n.File] = true
		for _, safe := range n.SafeWith {
			if !assigned[safe] {
				// Check this file is also safe with everything already in the group
				allSafe := true
				for _, g := range group {
					if conflictMap[safe] != nil && conflictMap[safe][g] {
						allSafe = false
						break
					}
				}
				if allSafe {
					group = append(group, safe)
					assigned[safe] = true
				}
			}
		}
		graph.Parallelism = append(graph.Parallelism, group)
	}
}

// generateAgentPlan creates suggested work units for multi-agent development.
func generateAgentPlan(graph *AppGraph) []AgentTask {
	var tasks []AgentTask
	taskID := 0

	// Build token lookup
	nodeTokens := make(map[string]int)
	nodeTests := make(map[string][]string)
	for _, n := range graph.Nodes {
		nodeTokens[n.File] = n.TokenEstimate
		// Build per-file test suggestions
		var fileTests []string
		switch n.Type {
		case "page":
			for _, p := range n.Provides {
				if strings.HasPrefix(p, "route:") {
					route := strings.TrimPrefix(p, "route:")
					fileTests = append(fileTests, fmt.Sprintf("test page renders: GET %s", route))
				}
			}
			for _, t := range n.TablesWrite {
				fileTests = append(fileTests, fmt.Sprintf("test CRUD for %s table", t))
			}
		case "hooks":
			for _, t := range n.TablesWrite {
				fileTests = append(fileTests, fmt.Sprintf("test hooks on %s", t))
			}
		case "flows":
			for _, p := range n.Provides {
				if strings.HasPrefix(p, "route:") {
					fileTests = append(fileTests, fmt.Sprintf("test flow: %s", strings.TrimPrefix(p, "route:")))
				}
			}
		}
		nodeTests[n.File] = fileTests
	}

	// Task 0: Schema (must be done first)
	schemaTokens := nodeTokens["schema.sql"]
	schemaTask := AgentTask{
		ID:            fmt.Sprintf("task-%d", taskID),
		Files:         []string{"schema.sql"},
		Description:   "Define or modify the data model",
		TokenEstimate: schemaTokens,
		SuggestedTests: []string{"test all tables created", "test migrations run cleanly"},
	}
	tasks = append(tasks, schemaTask)
	schemaTaskID := schemaTask.ID
	taskID++

	// Balance parallel groups by token count.
	// Re-group from the existing parallelism: split heavy groups, merge light ones.
	const maxGroupTokens = 2000
	var balancedGroups [][]string
	for _, group := range graph.Parallelism {
		// Calculate total tokens for this group
		groupTotal := 0
		for _, f := range group {
			groupTotal += nodeTokens[f]
		}
		if groupTotal <= maxGroupTokens || len(group) <= 1 {
			balancedGroups = append(balancedGroups, group)
		} else {
			// Split: put heavy files in their own group
			var current []string
			currentTokens := 0
			for _, f := range group {
				ft := nodeTokens[f]
				if currentTokens+ft > maxGroupTokens && len(current) > 0 {
					balancedGroups = append(balancedGroups, current)
					current = []string{f}
					currentTokens = ft
				} else {
					current = append(current, f)
					currentTokens += ft
				}
			}
			if len(current) > 0 {
				balancedGroups = append(balancedGroups, current)
			}
		}
	}

	// Task per balanced group
	for _, group := range balancedGroups {
		desc := "Build pages: " + strings.Join(group, ", ")
		tokens := 0
		var tests []string
		for _, f := range group {
			tokens += nodeTokens[f]
			tests = append(tests, nodeTests[f]...)
		}
		task := AgentTask{
			ID:             fmt.Sprintf("task-%d", taskID),
			Files:          group,
			Description:    desc,
			MustWaitFor:    []string{schemaTaskID},
			TokenEstimate:  tokens,
			SuggestedTests: tests,
		}
		tasks = append(tasks, task)
		taskID++
	}

	// Compute can_run_with
	for i := range tasks {
		if tasks[i].ID == schemaTaskID {
			continue
		}
		for j := range tasks {
			if i == j || tasks[j].ID == schemaTaskID {
				continue
			}
			// Check if any file in task i conflicts with any file in task j
			conflicts := false
			for _, f1 := range tasks[i].Files {
				for _, f2 := range tasks[j].Files {
					for _, cz := range graph.Conflicts {
						inI := false
						inJ := false
						for _, cf := range cz.Files {
							if cf == f1 { inI = true }
							if cf == f2 { inJ = true }
						}
						if inI && inJ {
							conflicts = true
						}
					}
				}
			}
			if !conflicts {
				tasks[i].CanRunWith = append(tasks[i].CanRunWith, tasks[j].ID)
			}
		}
	}

	// Hooks/flows task (depends on schema + pages)
	hasHooks := false
	hasFlows := false
	for _, n := range graph.Nodes {
		if n.Type == "hooks" { hasHooks = true }
		if n.Type == "flows" { hasFlows = true }
	}
	if hasHooks || hasFlows {
		files := []string{}
		desc := "Business logic: "
		tokens := 0
		var tests []string
		if hasHooks {
			files = append(files, "hooks.yaml")
			desc += "hooks"
			tokens += nodeTokens["hooks.yaml"]
			tests = append(tests, nodeTests["hooks.yaml"]...)
		}
		if hasFlows {
			files = append(files, "flows.yaml")
			if hasHooks { desc += " + " }
			desc += "flows"
			tokens += nodeTokens["flows.yaml"]
			tests = append(tests, nodeTests["flows.yaml"]...)
		}
		tasks = append(tasks, AgentTask{
			ID:             fmt.Sprintf("task-%d", taskID),
			Files:          files,
			Description:    desc,
			MustWaitFor:    []string{schemaTaskID},
			TokenEstimate:  tokens,
			SuggestedTests: tests,
		})
		taskID++
	}

	// Design task (independent)
	designTokens := nodeTokens["app.yaml"]
	tasks = append(tasks, AgentTask{
		ID:             fmt.Sprintf("task-%d", taskID),
		Files:          []string{"app.yaml", "theme.css"},
		Description:    "Theme and styling",
		TokenEstimate:  designTokens + 60, // theme.css estimate
		SuggestedTests: []string{"test design tokens render correctly", "test theme CSS applies"},
	})

	return tasks
}

// countComponents counts how many distinct component types appear in HTML content.
func countComponents(html string) int {
	count := 0
	for _, pat := range componentPatterns {
		re := regexp.MustCompile(pat)
		if re.MatchString(html) {
			count++
		}
	}
	return count
}

// countQueries counts <query> tags in HTML content.
func countQueries(html string) int {
	return len(queryTagPattern.FindAllString(html, -1))
}

// countDirectives counts :create, :delete, :patch, :validate in HTML content.
func countDirectives(html string) int {
	return len(directivePattern.FindAllString(html, -1))
}

// estimateFileTokens estimates LLM tokens needed to generate a file.
// Multiplier varies by file type: HTML ~3 tokens/line, YAML ~2, SQL ~1.
func estimateFileTokens(filePath string, content string) int {
	lines := strings.Count(content, "\n") + 1
	ext := strings.ToLower(filepath.Ext(filePath))

	multiplier := 3 // default: HTML
	switch ext {
	case ".html":
		multiplier = 3
		// Add bonus for component density
		components := countComponents(content)
		queries := countQueries(content)
		directives := countDirectives(content)
		bonus := (components * 50) + (queries * 30) + (directives * 20)
		return (lines * multiplier) + bonus
	case ".yaml", ".yml":
		multiplier = 2
	case ".sql":
		multiplier = 1
	case ".css":
		multiplier = 2
	}
	return lines * multiplier
}

// classifyComplexity returns "low", "medium", or "high" based on component/query/directive counts.
func classifyComplexity(html string) string {
	components := countComponents(html)
	queries := countQueries(html)
	directives := countDirectives(html)
	total := components + queries + directives

	if total <= 2 {
		return "low"
	}
	if total <= 5 {
		return "medium"
	}
	return "high"
}

// computeTokensAndComplexity sets TokenEstimate and Complexity on each GraphNode.
func computeTokensAndComplexity(graph *AppGraph, app *App) {
	for i := range graph.Nodes {
		n := &graph.Nodes[i]

		switch n.Type {
		case "page":
			// Find page content
			if page, ok := app.Pages[n.File]; ok {
				n.TokenEstimate = estimateFileTokens(n.File, page.RawHTML)
				n.Complexity = classifyComplexity(page.RawHTML)
			}
		case "schema":
			schemaPath := filepath.Join(app.Dir, "schema.sql")
			if data, err := os.ReadFile(schemaPath); err == nil {
				n.TokenEstimate = estimateFileTokens("schema.sql", string(data))
			} else {
				n.TokenEstimate = 50 // minimal schema
			}
			n.Complexity = "medium"
		case "hooks":
			hooksPath := filepath.Join(app.Dir, "hooks.yaml")
			if data, err := os.ReadFile(hooksPath); err == nil {
				n.TokenEstimate = estimateFileTokens("hooks.yaml", string(data))
			} else {
				n.TokenEstimate = 30
			}
			n.Complexity = "medium"
		case "flows":
			flowsPath := filepath.Join(app.Dir, "flows.yaml")
			if data, err := os.ReadFile(flowsPath); err == nil {
				n.TokenEstimate = estimateFileTokens("flows.yaml", string(data))
			} else {
				n.TokenEstimate = 50
			}
			n.Complexity = "high"
		case "design":
			appPath := filepath.Join(app.Dir, "app.yaml")
			if data, err := os.ReadFile(appPath); err == nil {
				n.TokenEstimate = estimateFileTokens("app.yaml", string(data))
			} else {
				n.TokenEstimate = 40
			}
			n.Complexity = "low"
		case "partial":
			if content, ok := app.Partials[n.File]; ok {
				n.TokenEstimate = estimateFileTokens(n.File, content)
				n.Complexity = classifyComplexity(content)
			}
		case "layout":
			layoutPath := filepath.Join(app.Dir, n.File)
			if data, err := os.ReadFile(layoutPath); err == nil {
				n.TokenEstimate = estimateFileTokens(n.File, string(data))
				n.Complexity = classifyComplexity(string(data))
			} else {
				n.TokenEstimate = 60
				n.Complexity = "low"
			}
		default:
			n.TokenEstimate = 20
			n.Complexity = "low"
		}
	}
}

// buildChangeImpactMap determines: if file X changes, which other files are affected?
func buildChangeImpactMap(graph *AppGraph) map[string][]string {
	impact := make(map[string][]string)

	// Build reverse lookup: which files use each partial, layout, or depend on schema
	partialUsers := make(map[string][]string) // partial name -> files that include it
	layoutUsers := make(map[string][]string)  // layout name -> files that use it
	var allPageFiles []string

	for _, n := range graph.Nodes {
		if n.Type == "page" {
			allPageFiles = append(allPageFiles, n.File)
			for _, p := range n.Partials {
				partialUsers[p] = append(partialUsers[p], n.File)
			}
			if n.Layout != "" {
				layoutUsers[n.Layout] = append(layoutUsers[n.Layout], n.File)
			}
		}
	}

	for i := range graph.Nodes {
		n := &graph.Nodes[i]
		var affected []string

		switch n.Type {
		case "schema":
			// Schema changes affect ALL pages, hooks, and flows
			affected = append(affected, allPageFiles...)
			for _, other := range graph.Nodes {
				if other.Type == "hooks" || other.Type == "flows" {
					affected = append(affected, other.File)
				}
			}
		case "partial":
			// Partial changes affect all pages that include it
			partialName := n.File
			affected = append(affected, partialUsers[partialName]...)
			// Also check layouts that include this partial
			for _, ln := range graph.Nodes {
				if ln.Type == "layout" {
					for _, lp := range ln.Partials {
						if lp == partialName {
							// This layout includes the partial; all pages using this layout are affected
							layoutName := strings.TrimSuffix(strings.TrimPrefix(ln.File, "layouts/"), ".html")
							affected = append(affected, layoutUsers[layoutName]...)
						}
					}
				}
			}
		case "layout":
			// Layout changes affect all pages using this layout
			layoutName := strings.TrimSuffix(strings.TrimPrefix(n.File, "layouts/"), ".html")
			affected = append(affected, layoutUsers[layoutName]...)
		case "design":
			// Design changes affect all pages (visual rendering)
			affected = append(affected, allPageFiles...)
		case "hooks":
			// Hook changes may affect pages that write to the same tables
			for _, t := range n.TablesWrite {
				for _, pn := range graph.Nodes {
					if pn.Type == "page" {
						for _, tw := range pn.TablesWrite {
							if tw == t {
								affected = append(affected, pn.File)
							}
						}
					}
				}
			}
		}

		// Deduplicate
		seen := make(map[string]bool)
		var unique []string
		for _, f := range affected {
			if f != n.File && !seen[f] {
				seen[f] = true
				unique = append(unique, f)
			}
		}
		if len(unique) > 0 {
			n.ChangeImpact = unique
			impact[n.File] = unique
		}
	}

	return impact
}

// buildSuggestedTests generates test suggestions based on app structure.
func buildSuggestedTests(graph *AppGraph, app *App) []string {
	var tests []string
	seen := make(map[string]bool)

	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			tests = append(tests, t)
		}
	}

	for _, n := range graph.Nodes {
		switch n.Type {
		case "page":
			route := ""
			for _, p := range n.Provides {
				if strings.HasPrefix(p, "route:") {
					route = strings.TrimPrefix(p, "route:")
				}
			}
			if route != "" {
				add(fmt.Sprintf("test page renders: GET %s returns 200", route))
			}
			for _, t := range n.TablesWrite {
				add(fmt.Sprintf("test CRUD for %s table via %s", t, n.File))
			}
			for _, t := range n.TablesRead {
				add(fmt.Sprintf("test data display: %s shows %s records", n.File, t))
			}
			// Check for auth
			if page, ok := app.Pages[n.File]; ok {
				if page.Auth == "required" {
					add(fmt.Sprintf("test auth required on %s", route))
				}
				if page.Scope == "owner" {
					add(fmt.Sprintf("test owner scoping on %s", route))
				}
			}
		case "hooks":
			for _, t := range n.TablesWrite {
				add(fmt.Sprintf("test hooks fire on %s insert/update/delete", t))
			}
		case "flows":
			for _, p := range n.Provides {
				if strings.HasPrefix(p, "route:") {
					add(fmt.Sprintf("test flow trigger: POST %s", strings.TrimPrefix(p, "route:")))
				}
			}
		}
	}

	return tests
}

// extractTablesReferenced finds all tables a page reads from.
func extractTablesReferenced(html string, tables []string) []string {
	found := make(map[string]bool)

	// :model="table"
	for _, m := range modelRefRe.FindAllStringSubmatch(html, -1) {
		found[m[1]] = true
	}
	// <query from="table">
	for _, m := range queryFromRe.FindAllStringSubmatch(html, -1) {
		found[m[1]] = true
	}
	// Raw SQL references
	for _, m := range querySQLRe.FindAllStringSubmatch(html, -1) {
		t := strings.ToLower(m[1])
		for _, table := range tables {
			if strings.ToLower(table) == t {
				found[table] = true
			}
		}
	}

	var result []string
	for t := range found {
		result = append(result, t)
	}
	return result
}

// extractTablesWritten finds all tables a page writes to.
func extractTablesWritten(html string) []string {
	found := make(map[string]bool)
	for _, m := range createRefRe.FindAllStringSubmatch(html, -1) {
		found[m[1]] = true
	}
	for _, m := range deleteRefRe.FindAllStringSubmatch(html, -1) {
		found[m[1]] = true
	}
	for _, m := range patchRefRe.FindAllStringSubmatch(html, -1) {
		found[m[1]] = true
	}
	var result []string
	for t := range found {
		result = append(result, t)
	}
	return result
}

// PrintGraph outputs the dependency graph as JSON.
func PrintGraph(app *App) {
	graph := BuildGraph(app)
	data, _ := json.MarshalIndent(graph, "", "  ")
	fmt.Println(string(data))
}
