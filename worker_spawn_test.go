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

	var scanned int
	for _, file := range workerFiles {
		data, err := os.ReadFile(file)
		if os.IsNotExist(err) {
			// Several worker files are platform-edition only and are
			// stripped from the open-source export. The invariant is
			// "no bare go func in a worker file", not "every file in
			// this list exists" - scan what's here and skip the rest,
			// so the guard still runs in every edition.
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		scanned++
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
	// Guard the guard: if the list ever drifts so far that nothing is
	// scanned, the test would pass vacuously while checking nothing.
	if scanned == 0 {
		t.Fatal("no worker files found to scan - workerFiles list has drifted")
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
