//go:build !cli

package main

// Trigger-shape checks for GHA flow files that the loader applies
// leniently. Each of these parsed clean and then behaved differently from
// what the file said: an on.schedule cron the scheduler can't evaluate
// never fired and a second trigger in the same `on:` was dropped. (An
// unknown on.request auth/mode or on.event op/table is checked by
// flowTriggerValueViolation; an unknown auth reads as required.) The write gate and
// `benmore check` refuse them (validateFlowsYAML); a deployed file still
// loads and parseGHAFlowFile logs the problem.

import (
	"fmt"
	"strings"
)

// flowTriggerProblems lists what a GHA flow file's `on:` block declares that
// the runtime would ignore or read differently.
func flowTriggerProblems(file FlowFileGHA) []string {
	var problems []string
	on := file.On
	declared := []string{}
	if on.Request != nil {
		declared = append(declared, "request")
		if _, err := flowStrictJSONFlag(on.Request.StrictJSON); err != nil {
			problems = append(problems, "flows.yaml: on.request.strict_json must be a YAML boolean (`true` or `false`).")
		}
	}
	if on.Schedule != nil {
		declared = append(declared, "schedule")
	}
	if on.Event != nil {
		declared = append(declared, "event")
	}
	if len(declared) > 1 {
		problems = append(problems, fmt.Sprintf("flows.yaml: `on:` declares %s, but a flow file has one trigger; only `%s` would be used. Put each trigger in its own file under flows/ (they can share steps through a named flow or cron `flow:`).",
			strings.Join(declared, " and "), declared[0]))
	}
	if on.Schedule != nil {
		expr := strings.TrimSpace(on.Schedule.Cron)
		if expr == "" {
			problems = append(problems, "flows.yaml: on.schedule needs `cron:` (e.g. `cron: \"0 9 * * 1\"` or `cron: \"every 15m\"`); without it the flow never runs.")
		} else if err := validateCronSchedule(expr); err != nil {
			problems = append(problems, fmt.Sprintf("flows.yaml: on.schedule cron %q: %s. The scheduler can't evaluate it, so the flow would never run. Use five cron fields (minute hour day month weekday, weekday 0-6), @hourly/@daily/@weekly/@monthly/@yearly, or `every <Go duration>` such as every 15m or every 24h.", expr, err))
		}
	}
	return problems
}
