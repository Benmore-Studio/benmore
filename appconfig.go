//go:build !cli

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadAppConfig reads app.yaml and parses it into a DesignConfig.
// Uses a simple key-value parser to avoid adding a YAML dependency.
func LoadAppConfig(dir string) *DesignConfig {
	path := filepath.Join(dir, "app.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	config := &DesignConfig{
		Colors:     make(map[string]string),
		Typography: make(map[string]string),
		Spacing:    make(map[string]string),
		Nav:        make(map[string]string),
		Table:      make(map[string]any),
		SEO:        make(map[string]string),
		CSP:        make(map[string]string),
		Auth:       make(map[string]string),
		PWA:        make(map[string]string)}

	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check indentation to determine if this is a section or value
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}

		if indent == 0 && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)

			switch key {
			case "radius":
				config.Radius = val
			case "shadow":
				config.Shadow = val
			case "css":
				config.CSS = val
			case "theme":
				config.Colors["_theme"] = val
			case "mode":
				config.Colors["_mode"] = val
			case "brand":
				config.Colors["_brand"] = val
			case "font":
				config.Colors["_font"] = val
			case "site_name":
				// Top-level site_name is the scaffold's canonical form; it
				// was previously only honored inside the seo: block, so
				// auth-email subjects and OAuth metadata fell back to
				// "App". seo.site_name (parsed later) still wins if both
				// are set.
				config.SEO["site_name"] = val
			}
			continue
		}

		if indent > 0 && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)

			switch section {
			case "colors":
				config.Colors[key] = val
			case "typography":
				config.Typography[key] = val
			case "spacing":
				config.Spacing[key] = val
			case "nav":
				config.Nav[key] = val
			case "table":
				config.Table[key] = val
			case "seo":
				config.SEO[key] = val
			case "csp":
				// CSP allowlist extensions per directive. Only the
				// recognised directives are accepted; anything else is
				// silently dropped (validator surfaces unknown keys
				// separately via the antipattern check).
				switch key {
				case "script_src", "style_src", "img_src", "font_src", "connect_src", "frame_src", "frame_ancestors":
					config.CSP[key] = val
				}
			case "auth":
				config.Auth[key] = val
			case "pwa":
				config.PWA[key] = val
			case "recording":
				config.Recording[key] = val
			}
		}
	}

	return config
}

// GenerateAppCSS creates CSS custom property overrides from app.yaml tokens.
// With the Tailwind-first system, most design is handled via CSS vars in css.go.
// This only handles custom radius/font overrides from app.yaml.
func GenerateAppCSS(config *DesignConfig) string {
	if config == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(":root {\n")

	if config.Radius != "" {
		sb.WriteString(fmt.Sprintf("  --radius: %s;\n", config.Radius))
	}

	if font, ok := config.Typography["font"]; ok {
		sb.WriteString(fmt.Sprintf("  --font-sans: '%s', ui-sans-serif, system-ui, sans-serif;\n", font))
	}
	if mono, ok := config.Typography["mono"]; ok {
		sb.WriteString(fmt.Sprintf("  --font-mono: '%s', ui-monospace, monospace;\n", mono))
	}

	sb.WriteString("}\n")
	return sb.String()
}
