//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// I18n holds translations for the app.
type I18n struct {
	DefaultLang  string
	Translations map[string]map[string]string // lang -> key -> value
}

// i18n was a process global: LoadI18n overwrote it per app and left the
// previous app's translations in place for an app with no i18n/ dir, so in a
// `benmore host` process one app's strings rendered in another's pages. It
// now lives on App.I18n, and every lookup goes through the app's copy.

// bootstrap returns a <script> block that primes window.__bm_i18n.strings on
// every raw page, so bm.t('key') resolves without an extra round trip. The
// active language comes from app.yaml's seo.lang, falling back to the app's
// default. No-op when the app ships no translations.
func (in *I18n) bootstrap(lang string) string {
	if in == nil || len(in.Translations) == 0 {
		return ""
	}
	if lang == "" {
		lang = in.DefaultLang
	}
	dict, ok := in.Translations[lang]
	if !ok {
		lang = in.DefaultLang
		dict = in.Translations[lang]
	}
	if len(dict) == 0 {
		return ""
	}
	data, err := json.Marshal(map[string]any{
		"lang":    lang,
		"strings": dict,
	})
	if err != nil {
		return ""
	}
	// Defang </script> so embedding can't break the script tag.
	safe := strings.ReplaceAll(string(data), "</", `<\/`)
	// A JavaScript object literal drops a string property named __proto__.
	// Parse a JSON-quoted payload to preserve every own translation key; the
	// outer JSON encoding also keeps the inline script boundary intact.
	quoted, _ := json.Marshal(safe)
	return `<script>window.__bm_i18n=JSON.parse(` + string(quoted) + `);</script>` + "\n"
}

// RegisterI18nRoutes serves only the current app's published dictionaries.
// A locale is an exact map key, never a filename supplied by a request.
func RegisterI18nRoutes(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET /api/_i18n/{lang}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("CDN-Cache-Control", "no-store")
		w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
		in := app.i18nConfig()
		if in != nil {
			if dict, ok := in.Translations[r.PathValue("lang")]; ok {
				if dict == nil {
					dict = map[string]string{}
				}
				httpJSON(w, http.StatusOK, dict)
				return
			}
		}
		httpJSON(w, http.StatusNotFound, map[string]string{"error": "language_not_found"})
	})
}

// injectI18nBootstrap initializes the browser dictionary before authored scripts.
// Snapshot language and translations together; both belong to the immutable
// published generation, including reviewed sources that have changed on disk.
func injectI18nBootstrap(page []byte, app *App) []byte {
	if app == nil {
		return page
	}
	app.mu.RLock()
	in, lang := app.I18n, ""
	if app.Design != nil && app.Design.SEO != nil {
		lang = app.Design.SEO["lang"]
	}
	app.mu.RUnlock()
	script := in.bootstrap(lang)
	if script == "" {
		return page
	}
	// Tokenize only the prefix so comments, quoted '>' attributes and <header>
	// cannot be mistaken for the actual head. A fragment gets a prefix script;
	// a document without a head retains its doctype and opening html element.
	z := html.NewTokenizer(bytes.NewReader(page))
	offset, at := 0, 0
prefix:
	for {
		tt := z.Next()
		offset += len(z.Raw())
		switch tt {
		case html.ErrorToken:
			break prefix
		case html.DoctypeToken:
			at = offset
		case html.StartTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "html":
				at = offset
			case "head":
				at = offset
				break prefix
			default:
				break prefix
			}
		}
	}
	out := make([]byte, 0, len(page)+len(script))
	out = append(out, page[:at]...)
	out = append(out, script...)
	out = append(out, page[at:]...)
	return out
}

// LoadI18n reads translation files from the i18n/ directory and returns them,
// or nil when there is no i18n/ dir. The caller stores the result on the app.
// Expected structure: i18n/en.yaml, i18n/es.yaml, etc.
// Each file: key-value pairs like "welcome: Welcome to our app"
func LoadI18n(dir string) *I18n {
	return loadI18nFromSources(dir, nil)
}

func loadI18nFromSources(dir string, sources map[string][]byte) *I18n {
	i18nDir := filepath.Join(dir, "i18n")
	var names []string
	hasDefault := false
	if sources == nil {
		entries, err := os.ReadDir(i18nDir)
		if err != nil {
			return nil // no i18n directory
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml") {
				names = append(names, entry.Name())
			}
		}
	} else {
		for path := range sources {
			if path == "i18n/.default" {
				hasDefault = true
				continue
			}
			if !strings.HasPrefix(path, "i18n/") {
				continue
			}
			name := strings.TrimPrefix(path, "i18n/")
			if strings.Contains(name, "/") || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
				continue
			}
			names = append(names, name)
		}
		if len(names) == 0 && !hasDefault {
			return nil
		}
		sort.Strings(names)
	}

	in := &I18n{
		DefaultLang:  "en",
		Translations: make(map[string]map[string]string),
	}

	for _, name := range names {
		lang := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		var data []byte
		if sources == nil {
			var err error
			data, err = os.ReadFile(filepath.Join(i18nDir, name))
			if err != nil {
				continue
			}
		} else {
			data = sources["i18n/"+name]
		}

		var translations map[string]string
		if err := yamlUnmarshal(data, &translations); err != nil {
			// Try nested format
			var nested map[string]any
			if err := yamlUnmarshal(data, &nested); err != nil {
				continue
			}
			translations = flattenTranslations("", nested)
		}

		in.Translations[lang] = translations
	}

	// Check for default language override
	if sources == nil {
		if defaultFile, err := os.ReadFile(filepath.Join(i18nDir, ".default")); err == nil {
			in.DefaultLang = strings.TrimSpace(string(defaultFile))
		}
	} else if defaultFile, ok := sources["i18n/.default"]; ok {
		in.DefaultLang = strings.TrimSpace(string(defaultFile))
	}
	return in
}

// T translates a key to the given language, with fallback to default language.
// A nil receiver (app with no translations) returns the key unchanged.
func (in *I18n) T(key, lang string) string {
	if in == nil {
		return key
	}

	if lang == "" {
		lang = in.DefaultLang
	}

	// Try requested language
	if translations, ok := in.Translations[lang]; ok {
		if val, ok := translations[key]; ok {
			return val
		}
	}

	// Fallback to default language
	if lang != in.DefaultLang {
		if translations, ok := in.Translations[in.DefaultLang]; ok {
			if val, ok := translations[key]; ok {
				return val
			}
		}
	}

	// Return key as-is if no translation found
	return key
}

// TranslateTemplate replaces {{t "key"}} patterns with translations.
func (in *I18n) TranslateTemplate(content, lang string) string {
	if in == nil {
		return content
	}

	// Find all {{t "key"}} patterns
	result := content
	for {
		idx := strings.Index(result, `{{t "`)
		if idx < 0 {
			break
		}
		end := strings.Index(result[idx+5:], `"}}`)
		if end < 0 {
			break
		}
		key := result[idx+5 : idx+5+end]
		translation := in.T(key, lang)
		result = result[:idx] + translation + result[idx+5+end+3:]
	}

	// Also support {{t 'key'}} with single quotes
	for {
		idx := strings.Index(result, `{{t '`)
		if idx < 0 {
			break
		}
		end := strings.Index(result[idx+5:], `'}}`)
		if end < 0 {
			break
		}
		key := result[idx+5 : idx+5+end]
		translation := in.T(key, lang)
		result = result[:idx] + translation + result[idx+5+end+3:]
	}

	return result
}

// GetLangFromRequest extracts language preference from request.
func GetLangFromRequest(acceptLanguage string) string {
	if acceptLanguage == "" {
		return ""
	}
	// Parse Accept-Language: en-US,en;q=0.9,es;q=0.8
	parts := strings.Split(acceptLanguage, ",")
	if len(parts) > 0 {
		lang := strings.SplitN(strings.TrimSpace(parts[0]), "-", 2)[0]
		lang = strings.SplitN(lang, ";", 2)[0]
		return strings.TrimSpace(lang)
	}
	return ""
}

func flattenTranslations(prefix string, m map[string]any) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case string:
			result[key] = val
		case map[string]any:
			for fk, fv := range flattenTranslations(key, val) {
				result[fk] = fv
			}
		default:
			result[key] = anyToString(v)
		}
	}
	return result
}
