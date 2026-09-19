//go:build !cli

package main

import (
	"fmt"
	"strings"
)

// LoadAppConfig is the historical entry point. Its key/value YAML syntax is
// still supported, but malformed YAML no longer selects a weaker parser.
func LoadAppConfig(dir string) *DesignConfig { return LoadAppConfigYAML(dir) }

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
