//go:build !cli

package main

import (
	"fmt"
	"net/url"
)

// Shared by CLI, MCP, dashboard and the encrypted-store boundary. Never return
// parser diagnostics containing the credential supplied in a DSN.
func validateAppEnvValue(key, value string) error {
	switch key {
	case "SENTRY_DSN":
		if value == "" {
			return nil
		}
		d, err := parseSentryDSN(value)
		if err != nil {
			return err
		}
		if !sentrySendable(d) {
			return fmt.Errorf("SENTRY_DSN requires a public, resolvable HTTPS host")
		}
	case "ERROR_SLACK_WEBHOOK":
		// An outbound URL is checked when it is set and again at delivery
		// (sendSlackDirect).
		if value == "" {
			return nil
		}
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.User != nil || outboundURLCheck(value) != nil {
			return fmt.Errorf("ERROR_SLACK_WEBHOOK requires a public, resolvable HTTPS URL")
		}
	case "SENTRY_MIN_LEVEL":
		if value != "" && value != "error" && value != "warning" {
			return fmt.Errorf("SENTRY_MIN_LEVEL must be error or warning")
		}
	}
	return nil
}

func errorReportingEnvFindings(dir string) []CheckFinding {
	// Source checking reads only the source-owned env.yaml. Runtime checks also
	// inspect the app's already-published snapshot, never another tenant's store.
	var findings []CheckFinding
	data, err := readOptionalConfig(dir, "env.yaml")
	if err != nil {
		return findings
	}
	vars := map[string]string{}
	if len(data) > 0 {
		if err := decodeConfigYAML(data, &vars); err != nil {
			return findings
		}
	}
	for _, key := range []string{"SENTRY_DSN", "ERROR_SLACK_WEBHOOK", "SENTRY_MIN_LEVEL"} {
		if err := validateAppEnvValue(key, vars[key]); err != nil {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "environment", File: "env.yaml", Message: err.Error()})
		}
	}
	return findings
}
