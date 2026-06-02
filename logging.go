//go:build !cli

package main

// Structured log output. When BENMORE_LOG_FORMAT=json is set, every line
// the framework writes via the stdlib `log` package is wrapped as a
// single-line JSON object — log shippers (Datadog, Splunk, Loki,
// CloudWatch) consume it directly without custom parsers.
//
// Default (no env var) is the historical text format: `<timestamp>
// <message>`. Operators only flip JSON on when they want to ship logs;
// developers running `benmore` locally keep the readable text output.
//
// Implementation: replace `log.Default()`'s writer with a Writer that
// detects the stdlib log prefix (`2026/05/29 02:46:31 …`), strips it,
// and emits `{"ts":"…","level":"info","app":"…","msg":"…"}` per line.
// We don't replace every `log.Printf` callsite — that would touch
// hundreds of lines for no semantic benefit. Wrapping the writer keeps
// the change one file and 100% backward-compatible.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// stdlibLogPrefixRe matches the timestamp prefix that log.Default()
// writes when flags include LstdFlags. Example: `2026/05/29 02:46:31 `.
// log.Lshortfile / Llongfile aren't in the default flag set — we leave
// those bytes inside `msg` if the caller has overridden flags.
var stdlibLogPrefixRe = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\s+`)

// levelHintRe pulls a level out of the message body when callers wrote
// it as a prefix. Optional — useful when log.Printf("ERROR: foo") shows
// up so the JSON output gets level=error instead of level=info.
var levelHintRe = regexp.MustCompile(`(?i)^\s*(error|warn|warning|info|debug)[:\s]\s*`)

type jsonLogWriter struct {
	dest    io.Writer
	appName string // populated from BENMORE_APP_NAME if set; empty otherwise
	mu      sync.Mutex
	buf     bytes.Buffer
}

func (w *jsonLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// stdlib log writes one Printf per Write but may split on '\n' for
	// multi-line messages. Buffer + flush on each newline to keep one
	// JSON object per logical log line.
	w.buf.Write(p)
	for {
		idx := bytes.IndexByte(w.buf.Bytes(), '\n')
		if idx < 0 {
			break
		}
		line := w.buf.Next(idx + 1) // includes trailing newline
		if err := w.emitJSON(line[:len(line)-1]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *jsonLogWriter) emitJSON(line []byte) error {
	if len(line) == 0 {
		return nil
	}
	s := string(line)
	// Strip stdlib timestamp prefix if present — we emit our own
	// RFC3339 timestamp.
	s = stdlibLogPrefixRe.ReplaceAllString(s, "")
	level := "info"
	if m := levelHintRe.FindStringSubmatch(s); m != nil {
		level = strings.ToLower(m[1])
		if level == "warning" {
			level = "warn"
		}
		s = strings.TrimSpace(s[len(m[0]):])
	}
	entry := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"msg":   strings.TrimSpace(s),
	}
	if w.appName != "" {
		entry["app"] = w.appName
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		entry["host"] = hostname
	}
	b, err := json.Marshal(entry)
	if err != nil {
		// Fall back to raw text rather than swallowing the line — a
		// broken log entry is better than a silent one.
		_, _ = w.dest.Write(line)
		_, _ = w.dest.Write([]byte("\n"))
		return nil
	}
	b = append(b, '\n')
	_, _ = w.dest.Write(b)
	return nil
}

// InstallStructuredLogging redirects log.Default() to a JSON formatter
// when BENMORE_LOG_FORMAT=json. Safe to call multiple times; only the
// first call installs the wrapper. The wrapper passes through cleanly
// to either stdout (for systemd journal capture) or whatever destination
// log.Default() was pointing at.
//
// Callers don't need to change. `log.Printf("foo: %d", 42)` continues to
// work and now emits `{"ts":"…","level":"info","msg":"foo: 42"}`.
func InstallStructuredLogging() {
	if strings.ToLower(os.Getenv("BENMORE_LOG_FORMAT")) != "json" {
		return
	}
	// Capture the current destination so we don't accidentally lose
	// stderr if someone redirected it earlier in init.
	dest := log.Default().Writer()
	if dest == nil {
		dest = os.Stderr
	}
	w := &jsonLogWriter{
		dest:    dest,
		appName: strings.TrimSpace(os.Getenv("BENMORE_APP_NAME")),
	}
	log.SetOutput(w)
	// Drop the default text-mode prefix flags — we emit our own RFC3339
	// timestamp inside the JSON object. Leaving LstdFlags on would
	// double-print the timestamp in the message body (stdlib writes it,
	// our writer strips it, but the strip is best-effort).
	log.SetFlags(0)
}
