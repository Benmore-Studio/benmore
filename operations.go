//go:build !cli

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
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

// ===== CSV Import =====

// ImportCSV reads a CSV file and inserts rows into a table.
func ImportCSV(app *App, csvPath, table string, mapping map[string]string) (int, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return 0, fmt.Errorf("csv open: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	headers, err := r.Read()
	if err != nil {
		return 0, fmt.Errorf("csv read headers: %w", err)
	}

	// Build column index
	headerIdx := make(map[string]int)
	for i, h := range headers {
		headerIdx[strings.TrimSpace(h)] = i
	}

	// If no mapping provided, use headers directly as column names
	if mapping == nil {
		mapping = make(map[string]string)
		for _, h := range headers {
			mapping[h] = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(h), " ", "_"))
		}
	}

	count := 0
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // skip bad rows
		}

		var dbCols []string
		var placeholders []string
		var values []any

		for csvCol, dbCol := range mapping {
			idx, ok := headerIdx[csvCol]
			if !ok || idx >= len(record) {
				continue
			}
			dbCols = append(dbCols, dbCol)
			placeholders = append(placeholders, "?")
			values = append(values, record[idx])
		}

		if len(dbCols) == 0 {
			continue
		}

		sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
			table, strings.Join(dbCols, ", "), strings.Join(placeholders, ", "))
		if _, err := app.DB.Exec(sql, values...); err != nil {
			log.Printf("CSV import row skip: %s", err)
			continue
		}
		count++
	}

	log.Printf("CSV imported: %d rows into %s", count, table)
	return count, nil
}

// ===== PDF Generation (HTML to PDF via Chrome) =====

// GeneratePDF renders an HTML template to PDF using headless Chrome.
func GeneratePDF(app *App, templatePath string, data map[string]any, outPath string) error {
	// Read and render template
	tmplData, err := os.ReadFile(filepath.Join(app.Dir, templatePath))
	if err != nil {
		return fmt.Errorf("pdf template: %w", err)
	}

	// Render with mustache
	flatData := flattenData(data)
	rendered := RenderMustache(string(tmplData), flatData)

	// Wrap in full HTML with print-friendly styles
	fullHTML := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
body { font-family: -apple-system, sans-serif; font-size: 12px; color: #1a1a1a; padding: 2rem; }
h1 { font-size: 1.5rem; margin-bottom: 1rem; }
h2 { font-size: 1.2rem; margin-bottom: 0.75rem; }
table { width: 100%%; border-collapse: collapse; margin: 1rem 0; }
th, td { padding: 0.5rem; border: 1px solid #ddd; text-align: left; font-size: 0.85rem; }
th { background: #f5f5f5; font-weight: 600; }
.card { border: 1px solid #ddd; border-radius: 4px; padding: 1rem; margin: 0.5rem 0; }
</style>
</head><body>%s</body></html>`, rendered)

	// Write temp HTML file
	tmpHTML := filepath.Join(os.TempDir(), fmt.Sprintf("benmore_pdf_%d.html", time.Now().UnixNano()))
	os.WriteFile(tmpHTML, []byte(fullHTML), 0644)
	defer os.Remove(tmpHTML)

	// Find Chrome
	chrome := findChrome()
	if chrome == "" {
		return fmt.Errorf("Chrome not found - needed for PDF generation")
	}

	os.MkdirAll(filepath.Dir(outPath), 0755)

	// Use Chrome headless to print to PDF
	cmd := execCommand(chrome,
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--print-to-pdf="+outPath,
		"--no-pdf-header-footer",
		tmpHTML,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chrome pdf: %s\n%s", err, string(output))
	}

	log.Printf("PDF generated: %s", outPath)
	return nil
}

// ===== Image Resize =====

// ResizeImage creates a resized copy. Uses Chrome canvas for simplicity (no image library dependency).
// For production, this could be replaced with a Go image library.
func ResizeImage(srcPath, destPath string, width, height int) error {
	// Read source image
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("image read: %w", err)
	}

	// Detect format
	ext := strings.ToLower(filepath.Ext(srcPath))
	mimeType := "image/jpeg"
	switch ext {
	case ".png":
		mimeType = "image/png"
	case ".gif":
		mimeType = "image/gif"
	case ".webp":
		mimeType = "image/webp"
	}

	// Create an HTML page with canvas that resizes and outputs
	b64 := base64.StdEncoding.EncodeToString(data)
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html><body>
<canvas id="c" width="%d" height="%d"></canvas>
<script>
var img = new Image();
img.onload = function() {
  var c = document.getElementById('c');
  c.getContext('2d').drawImage(img, 0, 0, %d, %d);
  // Output as data URL - Chrome will capture this
  document.title = 'done';
};
img.src = 'data:%s;base64,%s';
</script></body></html>`, width, height, width, height, mimeType, b64)

	tmpHTML := filepath.Join(os.TempDir(), fmt.Sprintf("benmore_resize_%d.html", time.Now().UnixNano()))
	os.WriteFile(tmpHTML, []byte(htmlContent), 0644)
	defer os.Remove(tmpHTML)

	chrome := findChrome()
	if chrome == "" {
		return fmt.Errorf("Chrome not found - needed for image resize")
	}

	os.MkdirAll(filepath.Dir(destPath), 0755)

	cmd := execCommand(chrome,
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		fmt.Sprintf("--window-size=%d,%d", width, height),
		"--screenshot="+destPath,
		"--hide-scrollbars",
		tmpHTML,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chrome resize: %s\n%s", err, string(output))
	}

	log.Printf("Image resized: %s → %s (%dx%d)", srcPath, destPath, width, height)
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
// ExportCSV writes table rows to CSV/JSON/XLSX.
// ImportCSV loads rows from a CSV file.
// See main.go for CLI command registration.

// execCommand wraps os/exec.Command.
func execCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

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
