//go:build !cli

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// I18n holds translations for the app.
type I18n struct {
	DefaultLang  string
	Translations map[string]map[string]string // lang -> key -> value
}

var i18n *I18n

// loadI18nBootstrap returns a <script> block that primes
// window.__bm_i18n.strings on every raw page, so bm.t('key') resolves
// without an extra round trip. The active language comes from
// app.yaml's seo.lang, falling back to i18n's default. No-op when
// the app ships no translations.
func loadI18nBootstrap(app *App) string {
	if i18n == nil || len(i18n.Translations) == 0 {
		return ""
	}
	lang := ""
	if app != nil && app.Design != nil && app.Design.SEO != nil {
		lang = app.Design.SEO["lang"]
	}
	if lang == "" {
		lang = i18n.DefaultLang
	}
	dict, ok := i18n.Translations[lang]
	if !ok {
		dict = i18n.Translations[i18n.DefaultLang]
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
	return `<script>window.__bm_i18n=` + safe + `;</script>` + "\n"
}

// LoadI18n reads translation files from the i18n/ directory.
// Expected structure: i18n/en.yaml, i18n/es.yaml, etc.
// Each file: key-value pairs like "welcome: Welcome to our app"
func LoadI18n(dir string) {
	i18nDir := filepath.Join(dir, "i18n")
	entries, err := os.ReadDir(i18nDir)
	if err != nil {
		return // no i18n directory
	}

	i18n = &I18n{
		DefaultLang:  "en",
		Translations: make(map[string]map[string]string),
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		lang := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".yaml"), ".yml")
		data, err := os.ReadFile(filepath.Join(i18nDir, entry.Name()))
		if err != nil {
			continue
		}

		var translations map[string]string
		if err := yaml.Unmarshal(data, &translations); err != nil {
			// Try nested format
			var nested map[string]any
			if err := yaml.Unmarshal(data, &nested); err != nil {
				continue
			}
			translations = flattenTranslations("", nested)
		}

		i18n.Translations[lang] = translations
	}

	// Check for default language override
	if defaultFile, err := os.ReadFile(filepath.Join(i18nDir, ".default")); err == nil {
		i18n.DefaultLang = strings.TrimSpace(string(defaultFile))
	}
}

// T translates a key to the given language, with fallback to default language.
func T(key, lang string) string {
	if i18n == nil {
		return key
	}

	if lang == "" {
		lang = i18n.DefaultLang
	}

	// Try requested language
	if translations, ok := i18n.Translations[lang]; ok {
		if val, ok := translations[key]; ok {
			return val
		}
	}

	// Fallback to default language
	if lang != i18n.DefaultLang {
		if translations, ok := i18n.Translations[i18n.DefaultLang]; ok {
			if val, ok := translations[key]; ok {
				return val
			}
		}
	}

	// Return key as-is if no translation found
	return key
}

// TranslateTemplate replaces {{t "key"}} patterns with translations.
func TranslateTemplate(content, lang string) string {
	if i18n == nil {
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
		translation := T(key, lang)
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
		translation := T(key, lang)
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
