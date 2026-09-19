//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoBareGoFuncInWorkers(t *testing.T) {
	workerFiles := []string{
		"cron.go",
		"rbac.go",
		"jobs.go",
		"backup_worker.go",
		"marketing_drips.go",
		"quarantine.go",
		"hosted_chat_retention.go",
		"feedback_ui.go",
	}
	// Keep each refactored family covered as its implementation moves
	// between files. Test fixtures may contain deliberate raw goroutines.
	for _, pattern := range []string{"auth*.go", "flows*.go"} {
		files, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no source files match worker family %q", pattern)
		}
		for _, file := range files {
			if !strings.HasSuffix(file, "_test.go") {
				workerFiles = append(workerFiles, file)
			}
		}
	}
	allow := map[string][]string{
		"flows_steps.go": {
			"parallel branch",
		},
	}

	for _, file := range workerFiles {
		data, err := os.ReadFile(file)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "go func(") {
				continue
			}
			context := surroundingLines(lines, i)
			if allowedBareSpawn(context, allow[file]) {
				continue
			}
			t.Fatalf("%s:%d contains bare go func; use safeGo or add a justified allowlist entry", file, i+1)
		}
	}
}

func allowedBareSpawn(context string, allowed []string) bool {
	for _, marker := range allowed {
		if strings.Contains(context, marker) {
			return true
		}
	}
	return false
}

func surroundingLines(lines []string, idx int) string {
	start := idx - 8
	if start < 0 {
		start = 0
	}
	end := idx + 8
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return strings.Join(lines[start:end+1], "\n")
}
