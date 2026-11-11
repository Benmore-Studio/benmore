//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var errorExportEmailRE = regexp.MustCompile(`(?i)[a-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}`)
var errorExportNumberRE = regexp.MustCompile(`[0-9]{9,}`)

type errorEnvScrubber struct {
	mu       sync.Mutex
	digest   [32]byte
	replacer *strings.Replacer
}

// exportScrubber redacts the text of one exported error event. It reads the
// environment once (newExportScrubber), so scrubbing each of an event's many
// fields is a replacer pass plus the shape patterns; reading it per field made
// one anonymous beacon cost tens of milliseconds.
type exportScrubber struct {
	env *strings.Replacer
}

func scrubForExport(app *App, s string) string {
	return newExportScrubber(app).scrub(s)
}

// newExportScrubber replaces every environment value of at least
// flowSecretMinLength bytes the way the flow failure text does
// (redactFlowSecretValues: as written and URL-escaped), plus its one-line
// form. Besides the app's own values it covers the runtime-only credentials
// in the process environment (runtimePrivateEnvKey), which app code never
// reads but framework error text can quote.
func newExportScrubber(app *App) *exportScrubber {
	if app == nil || app.Dir == "" {
		return &exportScrubber{}
	}
	app.mu.RLock()
	env := appEnvSnapshot(app.Dir, app.environment)
	app.mu.RUnlock()
	for _, kv := range os.Environ() {
		if key, value, ok := strings.Cut(kv, "="); ok && runtimePrivateEnvKey(key) {
			env["\x00runtime:"+key] = value
		}
	}
	encoded, _ := json.Marshal(env)
	digest := sha256.Sum256(encoded)
	c := &app.errorScrubber
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.replacer == nil || c.digest != digest {
		seen := map[string]bool{}
		var values []string
		for k, v := range env {
			if len(v) < flowSecretMinLength || errorConfigNames[k] {
				continue
			}
			for _, form := range []string{v, serverErrorOneLine(v), url.PathEscape(v), url.QueryEscape(v)} {
				if !seen[form] {
					seen[form] = true
					values = append(values, form)
				}
			}
		}
		sort.Slice(values, func(i, j int) bool {
			if len(values[i]) == len(values[j]) {
				return values[i] < values[j]
			}
			return len(values[i]) > len(values[j])
		})
		pairs := make([]string, 0, len(values)*2)
		for _, v := range values {
			pairs = append(pairs, v, "[redacted:env]")
		}
		c.digest, c.replacer = digest, strings.NewReplacer(pairs...)
	}
	return &exportScrubber{env: c.replacer}
}

// errorConfigNames name what the export calls itself, not secrets: the
// owner sets SENTRY_RELEASE to match the release CI uploads source maps to,
// and the default release is <subdomain>@<BENMORE_PUBLISHED_AT>. Hashing
// them broke release matching and the environment filter in Sentry.
var errorConfigNames = map[string]bool{"SENTRY_ENVIRONMENT": true, "SENTRY_RELEASE": true, "BENMORE_PUBLISHED_AT": true}

func (sc *exportScrubber) scrub(s string) string {
	// Omit oversized fields whole: cutting first could expose a secret prefix.
	if len(s) > 64<<10 {
		return "[omitted:oversized]"
	}
	// Recognize complete credential shapes before an overlapping environment
	// value can split them. There is deliberately no early truncation.
	s = redactErrorCredentials(s)
	if sc.env != nil {
		s = sc.env.Replace(s)
	}
	// Match complete secrets before any normalization or size limit can cut
	// off the bytes needed to recognize them.
	s = redactErrorCredentials(serverErrorOneLine(s))
	s = errorExportEmailRE.ReplaceAllString(s, "[email]")
	s = errorExportNumberRE.ReplaceAllString(s, "[number]")
	return requestLogTruncate(s, serverErrorDetailMax)
}

func errorUserAgent(value string) string {
	if len(value) > 2048 {
		return ""
	}
	return value
}

// Identity fields must distinguish apps, deployments and monitors even when
// the generic scrubber masks their text. Keep that scrubber unchanged and use
// an opaque, stable identity whenever exporting the original would reveal it.
func errorExportIdentity(app *App, kind, value string) string {
	if scrubbed := scrubForExport(app, value); scrubbed == value {
		return value
	}
	sum := sha256.Sum256([]byte(kind + "\x00" + value))
	return kind + "-" + hex.EncodeToString(sum[:12])
}

func (sc *exportScrubber) frames(frames []errorFrame) []errorFrame {
	out := append([]errorFrame(nil), frames...)
	for i := range out {
		f := &out[i]
		f.Filename = sc.scrub(f.Filename)
		f.AbsPath = sc.scrub(clientErrorLocation(f.AbsPath))
		f.Function = sc.scrub(f.Function)
		f.ContextLine = sc.scrub(f.ContextLine)
		f.PreContext = append([]string(nil), f.PreContext...)
		f.PostContext = append([]string(nil), f.PostContext...)
		for j := range f.PreContext {
			f.PreContext[j] = sc.scrub(f.PreContext[j])
		}
		for j := range f.PostContext {
			f.PostContext[j] = sc.scrub(f.PostContext[j])
		}
	}
	return out
}
