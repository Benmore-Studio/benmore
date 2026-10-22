//go:build !cli

package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Built-in operations available as flow steps.
// These are the "top 20 operations" that cover 95% of agency app needs.

// ===== CSV Export =====

// ExportCSV exports a SQL query result to a CSV file.
func ExportCSV(app *App, sqlQuery, outPath string) error {
	rows, err := QueryRows(app.DB, sqlQuery)
	if err != nil {
		return fmt.Errorf("csv export query: %w", err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("csv export: no rows returned")
	}

	// Get column order from first row
	var cols []string
	for k := range rows[0] {
		cols = append(cols, k)
	}

	os.MkdirAll(filepath.Dir(outPath), 0755)
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("csv create: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write(cols)

	// Data
	for _, row := range rows {
		var record []string
		for _, col := range cols {
			record = append(record, csvSafeCell(fmt.Sprintf("%v", row[col])))
		}
		w.Write(record)
	}

	log.Printf("CSV exported: %s (%d rows)", outPath, len(rows))
	return nil
}

// ===== AI/LLM Call =====

// CallAI sends a prompt to an AI provider and returns the response.
func CallAI(appDir, prompt, provider string) (string, error) {
	switch strings.ToLower(provider) {
	case "anthropic", "claude":
		return callAnthropic(appDir, prompt)
	case "openai", "gpt":
		return callOpenAI(appDir, prompt)
	default:
		return "", fmt.Errorf("unknown AI provider: %s (use: anthropic, openai)", provider)
	}
}

func callAnthropic(appDir, prompt string) (string, error) {
	apiKey := GetEnv(appDir, "ANTHROPIC_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY not set in env.yaml")
	}

	body, _ := json.Marshal(map[string]any{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 1024,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	})

	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic api: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("anthropic api %d: %s", resp.StatusCode, string(respBody[:min(len(respBody), 200)]))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Content) > 0 {
		return result.Content[0].Text, nil
	}
	return "", fmt.Errorf("anthropic: empty response")
}

func callOpenAI(appDir, prompt string) (string, error) {
	apiKey := GetEnv(appDir, "OPENAI_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("OPENAI_API_KEY not set in env.yaml")
	}

	body, _ := json.Marshal(map[string]any{
		"model":      "gpt-4o-mini",
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens": 1024,
	})

	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai api: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("openai api %d: %s", resp.StatusCode, string(respBody[:min(len(respBody), 200)]))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Choices) > 0 {
		return result.Choices[0].Message.Content, nil
	}
	return "", fmt.Errorf("openai: empty response")
}

// ===== CSV Export as HTTP download =====

// RegisterExportRoutes adds CSV/JSON export endpoints for all tables.
// Export and import are CLI-only operations. Not HTTP endpoints.
// ExportCSV writes table rows to CSV/JSON/XLSX. Bulk import is import.go.
// See main.go for CLI command registration.

// csvSafeCell guards against CSV formula injection. Cells starting with
// =, +, -, @, or a tab/CR are interpreted by Excel / Google Sheets as
// formulas, which can exfiltrate data via HYPERLINK / WEBSERVICE or
// trigger DDE. Prefix with a single tick so the cell renders as text.
// Recipients who actually want the leading character can strip it.
func csvSafeCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
