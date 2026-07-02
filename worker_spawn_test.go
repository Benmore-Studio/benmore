//go:build !cli

package main

import (
	"os"
	"strings"
	"testing"
)

func TestNoBareGoFuncInWorkers(t *testing.T) {
	workerFiles := []string{
		"auth.go",
		"cron.go",
		"rbac.go",
		"jobs.go",
		"backup_worker.go",
		"marketing_drips.go",
		"quarantine.go",
		"builder_uploads.go",
		"flows.go",
		"feedback_ui.go",
	}
	allow := map[string][]string{
		"flows.go": {
			"parallel branch",
		},
	}

	for _, file := range workerFiles {
		data, err := os.ReadFile(file)
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
