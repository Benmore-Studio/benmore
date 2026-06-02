//go:build !cli

package main

import (
	"fmt"
	"math"
	"strings"
)

// --- shadcn-compatible Theme System ---
// Themes use HSL values without the hsl() wrapper.
// Tailwind config maps semantic names (bg-primary, text-muted-foreground, etc.)
// to hsl(var(--primary)), hsl(var(--muted-foreground)), etc.

// GetThemeVars returns the complete CSS custom property block for a theme+mode.
func GetThemeVars(theme, mode string) string {
	if theme == "" {
		theme = "zinc"
	}
	if mode == "" {
		mode = "dark"
	}

	// Color accent themes reuse zinc's neutral palette
	neutral := theme
	switch theme {
	case "red", "rose", "orange", "green", "blue", "yellow", "violet":
		neutral = "zinc"
	}

	base := neutralVars[neutral+"-"+mode]
	if base == "" {
		base = neutralVars["zinc-dark"]
	}

	primary := primaryVars[theme+"-"+mode]
	if primary == "" {
		primary = primaryVars["zinc-"+mode]
	}

	extra := extraVars[mode]
	if extra == "" {
		extra = extraVars["dark"]
	}

	return base + "\n" + primary + "\n" + extra
}

// BuildCSS returns the full <style> content: CSS variables + base styles.
func BuildCSS(themeName, mode, brand string) string {
	vars := GetThemeVars(themeName, mode)

	// Brand color override → replace primary HSL
	if brand != "" {
		hsl := hexToHSL(brand)
		if hsl != "" {
			vars += fmt.Sprintf("\n  --primary: %s;\n  --sidebar-primary: %s;\n  --ring: %s;", hsl, hsl, hsl)
		}
	}

	return fmt.Sprintf(":root {\n%s\n  --radius: 0.625rem;\n  --font-sans: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif;\n  --font-mono: ui-monospace, SFMono-Regular, \"SF Mono\", Menlo, Consolas, monospace;\n}\n\n%s", vars, BaseCSS)
}

// hexToHSL converts a hex color (#rrggbb or #rgb) to "H S% L%" format.
func hexToHSL(hex string) string {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) == 3 {
		hex = string(hex[0]) + string(hex[0]) + string(hex[1]) + string(hex[1]) + string(hex[2]) + string(hex[2])
	}
	if len(hex) != 6 {
		return ""
	}

	r := hexVal(hex[0:2])
	g := hexVal(hex[2:4])
	b := hexVal(hex[4:6])

	rf, gf, bf := float64(r)/255, float64(g)/255, float64(b)/255
	mx := math.Max(rf, math.Max(gf, bf))
	mn := math.Min(rf, math.Min(gf, bf))

	h, s, l := 0.0, 0.0, (mx+mn)/2

	if mx != mn {
		d := mx - mn
		if l > 0.5 {
			s = d / (2 - mx - mn)
		} else {
			s = d / (mx + mn)
		}
		switch mx {
		case rf:
			h = (gf - bf) / d
			if gf < bf {
				h += 6
			}
		case gf:
			h = (bf-rf)/d + 2
		case bf:
			h = (rf-gf)/d + 4
		}
		h *= 60
	}

	return fmt.Sprintf("%.1f %.1f%% %.1f%%", h, s*100, l*100)
}

func hexVal(s string) int {
	n := 0
	for _, c := range s {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n += int(c-'A') + 10
		}
	}
	return n
}

// ============================================================
// Neutral palette vars (background, foreground, card, popover,
// secondary, muted, accent, destructive, border, input, sidebar)
// ============================================================

var neutralVars = map[string]string{
	// ---- ZINC ----
	"zinc-dark": `  --background: 240 10% 3.9%;
  --foreground: 0 0% 98%;
  --card: 240 10% 3.9%;
  --card-foreground: 0 0% 98%;
  --popover: 240 10% 3.9%;
  --popover-foreground: 0 0% 98%;
  --secondary: 240 3.7% 15.9%;
  --secondary-foreground: 0 0% 98%;
  --muted: 240 3.7% 15.9%;
  --muted-foreground: 240 5% 64.9%;
  --accent: 240 3.7% 15.9%;
  --accent-foreground: 0 0% 98%;
  --destructive: 0 62.8% 30.6%;
  --destructive-foreground: 0 0% 98%;
  --border: 240 3.7% 15.9%;
  --input: 240 3.7% 15.9%;
  --sidebar-background: 240 5.9% 10%;
  --sidebar-foreground: 240 4.8% 95.9%;
  --sidebar-accent: 240 3.7% 15.9%;
  --sidebar-accent-foreground: 240 4.8% 95.9%;
  --sidebar-border: 240 3.7% 15.9%;`,

	"zinc-light": `  --background: 0 0% 100%;
  --foreground: 240 10% 3.9%;
  --card: 0 0% 100%;
  --card-foreground: 240 10% 3.9%;
  --popover: 0 0% 100%;
  --popover-foreground: 240 10% 3.9%;
  --secondary: 240 4.8% 95.9%;
  --secondary-foreground: 240 5.9% 10%;
  --muted: 240 4.8% 95.9%;
  --muted-foreground: 240 3.8% 46.1%;
  --accent: 240 4.8% 95.9%;
  --accent-foreground: 240 5.9% 10%;
  --destructive: 0 84.2% 60.2%;
  --destructive-foreground: 0 0% 98%;
  --border: 240 5.9% 90%;
  --input: 240 5.9% 90%;
  --sidebar-background: 0 0% 98%;
  --sidebar-foreground: 240 5.3% 26.1%;
  --sidebar-accent: 240 4.8% 95.9%;
  --sidebar-accent-foreground: 240 5.3% 26.1%;
  --sidebar-border: 220 13% 91%;`,

	// ---- SLATE ----
	"slate-dark": `  --background: 222.2 84% 4.9%;
  --foreground: 210 40% 98%;
  --card: 222.2 84% 4.9%;
  --card-foreground: 210 40% 98%;
  --popover: 222.2 84% 4.9%;
  --popover-foreground: 210 40% 98%;
  --secondary: 217.2 32.6% 17.5%;
  --secondary-foreground: 210 40% 98%;
  --muted: 217.2 32.6% 17.5%;
  --muted-foreground: 215 20.2% 65.1%;
  --accent: 217.2 32.6% 17.5%;
  --accent-foreground: 210 40% 98%;
  --destructive: 0 62.8% 30.6%;
  --destructive-foreground: 210 40% 98%;
  --border: 217.2 32.6% 17.5%;
  --input: 217.2 32.6% 17.5%;
  --sidebar-background: 222.2 47.4% 11.2%;
  --sidebar-foreground: 210 40% 96%;
  --sidebar-accent: 217.2 32.6% 17.5%;
  --sidebar-accent-foreground: 210 40% 96%;
  --sidebar-border: 217.2 32.6% 17.5%;`,

	"slate-light": `  --background: 0 0% 100%;
  --foreground: 222.2 84% 4.9%;
  --card: 0 0% 100%;
  --card-foreground: 222.2 84% 4.9%;
  --popover: 0 0% 100%;
  --popover-foreground: 222.2 84% 4.9%;
  --secondary: 210 40% 96.1%;
  --secondary-foreground: 222.2 47.4% 11.2%;
  --muted: 210 40% 96.1%;
  --muted-foreground: 215.4 16.3% 46.9%;
  --accent: 210 40% 96.1%;
  --accent-foreground: 222.2 47.4% 11.2%;
  --destructive: 0 84.2% 60.2%;
  --destructive-foreground: 210 40% 98%;
  --border: 214.3 31.8% 91.4%;
  --input: 214.3 31.8% 91.4%;
  --sidebar-background: 0 0% 98%;
  --sidebar-foreground: 222.2 47.4% 26%;
  --sidebar-accent: 210 40% 96.1%;
  --sidebar-accent-foreground: 222.2 47.4% 26%;
  --sidebar-border: 214.3 31.8% 91.4%;`,

	// ---- STONE ----
	"stone-dark": `  --background: 20 14.3% 4.1%;
  --foreground: 60 9.1% 97.8%;
  --card: 20 14.3% 4.1%;
  --card-foreground: 60 9.1% 97.8%;
  --popover: 20 14.3% 4.1%;
  --popover-foreground: 60 9.1% 97.8%;
  --secondary: 12 6.5% 15.1%;
  --secondary-foreground: 60 9.1% 97.8%;
  --muted: 12 6.5% 15.1%;
  --muted-foreground: 24 5.4% 63.9%;
  --accent: 12 6.5% 15.1%;
  --accent-foreground: 60 9.1% 97.8%;
  --destructive: 0 62.8% 30.6%;
  --destructive-foreground: 60 9.1% 97.8%;
  --border: 12 6.5% 15.1%;
  --input: 12 6.5% 15.1%;
  --sidebar-background: 24 9.8% 10%;
  --sidebar-foreground: 60 9.1% 95.9%;
  --sidebar-accent: 12 6.5% 15.1%;
  --sidebar-accent-foreground: 60 9.1% 95.9%;
  --sidebar-border: 12 6.5% 15.1%;`,

	"stone-light": `  --background: 0 0% 100%;
  --foreground: 20 14.3% 4.1%;
  --card: 0 0% 100%;
  --card-foreground: 20 14.3% 4.1%;
  --popover: 0 0% 100%;
  --popover-foreground: 20 14.3% 4.1%;
  --secondary: 60 4.8% 95.9%;
  --secondary-foreground: 24 9.8% 10%;
  --muted: 60 4.8% 95.9%;
  --muted-foreground: 25 5.3% 44.7%;
  --accent: 60 4.8% 95.9%;
  --accent-foreground: 24 9.8% 10%;
  --destructive: 0 84.2% 60.2%;
  --destructive-foreground: 60 9.1% 97.8%;
  --border: 20 5.9% 90%;
  --input: 20 5.9% 90%;
  --sidebar-background: 0 0% 98%;
  --sidebar-foreground: 24 9.8% 26%;
  --sidebar-accent: 60 4.8% 95.9%;
  --sidebar-accent-foreground: 24 9.8% 26%;
  --sidebar-border: 20 5.9% 90%;`,

	// ---- GRAY ----
	"gray-dark": `  --background: 224 71.4% 4.1%;
  --foreground: 210 20% 98%;
  --card: 224 71.4% 4.1%;
  --card-foreground: 210 20% 98%;
  --popover: 224 71.4% 4.1%;
  --popover-foreground: 210 20% 98%;
  --secondary: 215 27.9% 16.9%;
  --secondary-foreground: 210 20% 98%;
  --muted: 215 27.9% 16.9%;
  --muted-foreground: 217.9 10.6% 64.9%;
  --accent: 215 27.9% 16.9%;
  --accent-foreground: 210 20% 98%;
  --destructive: 0 62.8% 30.6%;
  --destructive-foreground: 210 20% 98%;
  --border: 215 27.9% 16.9%;
  --input: 215 27.9% 16.9%;
  --sidebar-background: 220.9 39.3% 11%;
  --sidebar-foreground: 210 20% 95.9%;
  --sidebar-accent: 215 27.9% 16.9%;
  --sidebar-accent-foreground: 210 20% 95.9%;
  --sidebar-border: 215 27.9% 16.9%;`,

	"gray-light": `  --background: 0 0% 100%;
  --foreground: 224 71.4% 4.1%;
  --card: 0 0% 100%;
  --card-foreground: 224 71.4% 4.1%;
  --popover: 0 0% 100%;
  --popover-foreground: 224 71.4% 4.1%;
  --secondary: 220 14.3% 95.9%;
  --secondary-foreground: 220.9 39.3% 11%;
  --muted: 220 14.3% 95.9%;
  --muted-foreground: 220 8.9% 46.1%;
  --accent: 220 14.3% 95.9%;
  --accent-foreground: 220.9 39.3% 11%;
  --destructive: 0 84.2% 60.2%;
  --destructive-foreground: 210 20% 98%;
  --border: 220 13% 91%;
  --input: 220 13% 91%;
  --sidebar-background: 0 0% 98%;
  --sidebar-foreground: 220.9 39.3% 26%;
  --sidebar-accent: 220 14.3% 95.9%;
  --sidebar-accent-foreground: 220.9 39.3% 26%;
  --sidebar-border: 220 13% 91%;`,

	// ---- NEUTRAL ----
	"neutral-dark": `  --background: 0 0% 3.9%;
  --foreground: 0 0% 98%;
  --card: 0 0% 3.9%;
  --card-foreground: 0 0% 98%;
  --popover: 0 0% 3.9%;
  --popover-foreground: 0 0% 98%;
  --secondary: 0 0% 14.9%;
  --secondary-foreground: 0 0% 98%;
  --muted: 0 0% 14.9%;
  --muted-foreground: 0 0% 63.9%;
  --accent: 0 0% 14.9%;
  --accent-foreground: 0 0% 98%;
  --destructive: 0 62.8% 30.6%;
  --destructive-foreground: 0 0% 98%;
  --border: 0 0% 14.9%;
  --input: 0 0% 14.9%;
  --sidebar-background: 0 0% 9%;
  --sidebar-foreground: 0 0% 95.9%;
  --sidebar-accent: 0 0% 14.9%;
  --sidebar-accent-foreground: 0 0% 95.9%;
  --sidebar-border: 0 0% 14.9%;`,

	"neutral-light": `  --background: 0 0% 100%;
  --foreground: 0 0% 3.9%;
  --card: 0 0% 100%;
  --card-foreground: 0 0% 3.9%;
  --popover: 0 0% 100%;
  --popover-foreground: 0 0% 3.9%;
  --secondary: 0 0% 96.1%;
  --secondary-foreground: 0 0% 9%;
  --muted: 0 0% 96.1%;
  --muted-foreground: 0 0% 45.1%;
  --accent: 0 0% 96.1%;
  --accent-foreground: 0 0% 9%;
  --destructive: 0 84.2% 60.2%;
  --destructive-foreground: 0 0% 98%;
  --border: 0 0% 89.8%;
  --input: 0 0% 89.8%;
  --sidebar-background: 0 0% 98%;
  --sidebar-foreground: 0 0% 26%;
  --sidebar-accent: 0 0% 96.1%;
  --sidebar-accent-foreground: 0 0% 26%;
  --sidebar-border: 0 0% 89.8%;`,
}

// ============================================================
// Primary color vars (primary, primary-fg, ring, sidebar-primary)
// ============================================================

var primaryVars = map[string]string{
	// Neutral themes: primary = foreground
	"zinc-dark": `  --primary: 0 0% 98%;
  --primary-foreground: 240 5.9% 10%;
  --ring: 240 4.9% 83.9%;
  --sidebar-primary: 0 0% 98%;
  --sidebar-primary-foreground: 240 5.9% 10%;
  --sidebar-ring: 240 4.9% 83.9%;`,

	"zinc-light": `  --primary: 240 5.9% 10%;
  --primary-foreground: 0 0% 98%;
  --ring: 240 5.9% 10%;
  --sidebar-primary: 240 5.9% 10%;
  --sidebar-primary-foreground: 0 0% 98%;
  --sidebar-ring: 240 5.9% 10%;`,

	"slate-dark": `  --primary: 210 40% 98%;
  --primary-foreground: 222.2 47.4% 11.2%;
  --ring: 212.7 26.8% 83.9%;
  --sidebar-primary: 210 40% 98%;
  --sidebar-primary-foreground: 222.2 47.4% 11.2%;
  --sidebar-ring: 212.7 26.8% 83.9%;`,

	"slate-light": `  --primary: 222.2 47.4% 11.2%;
  --primary-foreground: 210 40% 98%;
  --ring: 222.2 84% 4.9%;
  --sidebar-primary: 222.2 47.4% 11.2%;
  --sidebar-primary-foreground: 210 40% 98%;
  --sidebar-ring: 222.2 84% 4.9%;`,

	"stone-dark": `  --primary: 60 9.1% 97.8%;
  --primary-foreground: 24 9.8% 10%;
  --ring: 24 5.7% 82.9%;
  --sidebar-primary: 60 9.1% 97.8%;
  --sidebar-primary-foreground: 24 9.8% 10%;
  --sidebar-ring: 24 5.7% 82.9%;`,

	"stone-light": `  --primary: 24 9.8% 10%;
  --primary-foreground: 60 9.1% 97.8%;
  --ring: 20 14.3% 4.1%;
  --sidebar-primary: 24 9.8% 10%;
  --sidebar-primary-foreground: 60 9.1% 97.8%;
  --sidebar-ring: 20 14.3% 4.1%;`,

	"gray-dark": `  --primary: 210 20% 98%;
  --primary-foreground: 220.9 39.3% 11%;
  --ring: 216 12.2% 83.9%;
  --sidebar-primary: 210 20% 98%;
  --sidebar-primary-foreground: 220.9 39.3% 11%;
  --sidebar-ring: 216 12.2% 83.9%;`,

	"gray-light": `  --primary: 220.9 39.3% 11%;
  --primary-foreground: 210 20% 98%;
  --ring: 224 71.4% 4.1%;
  --sidebar-primary: 220.9 39.3% 11%;
  --sidebar-primary-foreground: 210 20% 98%;
  --sidebar-ring: 224 71.4% 4.1%;`,

	"neutral-dark": `  --primary: 0 0% 98%;
  --primary-foreground: 0 0% 9%;
  --ring: 0 0% 83.1%;
  --sidebar-primary: 0 0% 98%;
  --sidebar-primary-foreground: 0 0% 9%;
  --sidebar-ring: 0 0% 83.1%;`,

	"neutral-light": `  --primary: 0 0% 9%;
  --primary-foreground: 0 0% 98%;
  --ring: 0 0% 3.9%;
  --sidebar-primary: 0 0% 9%;
  --sidebar-primary-foreground: 0 0% 98%;
  --sidebar-ring: 0 0% 3.9%;`,

	// Color accent themes
	"red-dark": `  --primary: 0 72.2% 50.6%;
  --primary-foreground: 0 85.7% 97.3%;
  --ring: 0 72.2% 50.6%;
  --sidebar-primary: 0 72.2% 50.6%;
  --sidebar-primary-foreground: 0 85.7% 97.3%;
  --sidebar-ring: 0 72.2% 50.6%;`,

	"red-light": `  --primary: 0 72.2% 50.6%;
  --primary-foreground: 0 85.7% 97.3%;
  --ring: 0 72.2% 50.6%;
  --sidebar-primary: 0 72.2% 50.6%;
  --sidebar-primary-foreground: 0 85.7% 97.3%;
  --sidebar-ring: 0 72.2% 50.6%;`,

	"rose-dark": `  --primary: 346.8 77.2% 49.8%;
  --primary-foreground: 355.7 100% 97.3%;
  --ring: 346.8 77.2% 49.8%;
  --sidebar-primary: 346.8 77.2% 49.8%;
  --sidebar-primary-foreground: 355.7 100% 97.3%;
  --sidebar-ring: 346.8 77.2% 49.8%;`,

	"rose-light": `  --primary: 346.8 77.2% 49.8%;
  --primary-foreground: 355.7 100% 97.3%;
  --ring: 346.8 77.2% 49.8%;
  --sidebar-primary: 346.8 77.2% 49.8%;
  --sidebar-primary-foreground: 355.7 100% 97.3%;
  --sidebar-ring: 346.8 77.2% 49.8%;`,

	"orange-dark": `  --primary: 20.5 90.2% 48.2%;
  --primary-foreground: 60 9.1% 97.8%;
  --ring: 20.5 90.2% 48.2%;
  --sidebar-primary: 20.5 90.2% 48.2%;
  --sidebar-primary-foreground: 60 9.1% 97.8%;
  --sidebar-ring: 20.5 90.2% 48.2%;`,

	"orange-light": `  --primary: 24.6 95% 53.1%;
  --primary-foreground: 60 9.1% 97.8%;
  --ring: 24.6 95% 53.1%;
  --sidebar-primary: 24.6 95% 53.1%;
  --sidebar-primary-foreground: 60 9.1% 97.8%;
  --sidebar-ring: 24.6 95% 53.1%;`,

	"green-dark": `  --primary: 142.1 70.6% 45.3%;
  --primary-foreground: 144.9 80.4% 10%;
  --ring: 142.1 70.6% 45.3%;
  --sidebar-primary: 142.1 70.6% 45.3%;
  --sidebar-primary-foreground: 144.9 80.4% 10%;
  --sidebar-ring: 142.1 70.6% 45.3%;`,

	"green-light": `  --primary: 142.1 76.2% 36.3%;
  --primary-foreground: 355.7 100% 97.3%;
  --ring: 142.1 76.2% 36.3%;
  --sidebar-primary: 142.1 76.2% 36.3%;
  --sidebar-primary-foreground: 355.7 100% 97.3%;
  --sidebar-ring: 142.1 76.2% 36.3%;`,

	"blue-dark": `  --primary: 217.2 91.2% 59.8%;
  --primary-foreground: 222.2 47.4% 11.2%;
  --ring: 217.2 91.2% 59.8%;
  --sidebar-primary: 217.2 91.2% 59.8%;
  --sidebar-primary-foreground: 222.2 47.4% 11.2%;
  --sidebar-ring: 217.2 91.2% 59.8%;`,

	"blue-light": `  --primary: 221.2 83.2% 53.3%;
  --primary-foreground: 210 40% 98%;
  --ring: 221.2 83.2% 53.3%;
  --sidebar-primary: 221.2 83.2% 53.3%;
  --sidebar-primary-foreground: 210 40% 98%;
  --sidebar-ring: 221.2 83.2% 53.3%;`,

	"yellow-dark": `  --primary: 47.9 95.8% 53.1%;
  --primary-foreground: 26 83.3% 14.1%;
  --ring: 47.9 95.8% 53.1%;
  --sidebar-primary: 47.9 95.8% 53.1%;
  --sidebar-primary-foreground: 26 83.3% 14.1%;
  --sidebar-ring: 47.9 95.8% 53.1%;`,

	"yellow-light": `  --primary: 47.9 95.8% 53.1%;
  --primary-foreground: 26 83.3% 14.1%;
  --ring: 47.9 95.8% 53.1%;
  --sidebar-primary: 47.9 95.8% 53.1%;
  --sidebar-primary-foreground: 26 83.3% 14.1%;
  --sidebar-ring: 47.9 95.8% 53.1%;`,

	"violet-dark": `  --primary: 263.4 70% 50.4%;
  --primary-foreground: 210 20% 98%;
  --ring: 263.4 70% 50.4%;
  --sidebar-primary: 263.4 70% 50.4%;
  --sidebar-primary-foreground: 210 20% 98%;
  --sidebar-ring: 263.4 70% 50.4%;`,

	"violet-light": `  --primary: 262.1 83.3% 57.8%;
  --primary-foreground: 210 20% 98%;
  --ring: 262.1 83.3% 57.8%;
  --sidebar-primary: 262.1 83.3% 57.8%;
  --sidebar-primary-foreground: 210 20% 98%;
  --sidebar-ring: 262.1 83.3% 57.8%;`,
}

// ============================================================
// Extra vars: success, warning, info, chart colors
// ============================================================

var extraVars = map[string]string{
	"dark": `  --success: 142.1 76.2% 36.3%;
  --warning: 47.9 95.8% 53.1%;
  --info: 199.4 95.4% 53.7%;
  --chart-1: 220 70% 50%;
  --chart-2: 160 60% 45%;
  --chart-3: 30 80% 55%;
  --chart-4: 280 65% 60%;
  --chart-5: 340 75% 55%;`,

	"light": `  --success: 142.1 76.2% 36.3%;
  --warning: 47.9 95.8% 53.1%;
  --info: 199.4 95.4% 53.7%;
  --chart-1: 12 76% 61%;
  --chart-2: 173 58% 39%;
  --chart-3: 197 37% 24%;
  --chart-4: 43 74% 66%;
  --chart-5: 27 87% 67%;`,
}

// ============================================================
// Tailwind CDN inline config (maps CSS vars to Tailwind classes)
// ============================================================

const TailwindConfig = `tailwind.config = {
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: { DEFAULT: 'hsl(var(--primary))', foreground: 'hsl(var(--primary-foreground))' },
        secondary: { DEFAULT: 'hsl(var(--secondary))', foreground: 'hsl(var(--secondary-foreground))' },
        destructive: { DEFAULT: 'hsl(var(--destructive))', foreground: 'hsl(var(--destructive-foreground))' },
        muted: { DEFAULT: 'hsl(var(--muted))', foreground: 'hsl(var(--muted-foreground))' },
        accent: { DEFAULT: 'hsl(var(--accent))', foreground: 'hsl(var(--accent-foreground))' },
        popover: { DEFAULT: 'hsl(var(--popover))', foreground: 'hsl(var(--popover-foreground))' },
        card: { DEFAULT: 'hsl(var(--card))', foreground: 'hsl(var(--card-foreground))' },
        chart: { 1: 'hsl(var(--chart-1))', 2: 'hsl(var(--chart-2))', 3: 'hsl(var(--chart-3))', 4: 'hsl(var(--chart-4))', 5: 'hsl(var(--chart-5))' },
        sidebar: {
          DEFAULT: 'hsl(var(--sidebar-background))',
          foreground: 'hsl(var(--sidebar-foreground))',
          primary: 'hsl(var(--sidebar-primary))',
          'primary-foreground': 'hsl(var(--sidebar-primary-foreground))',
          accent: 'hsl(var(--sidebar-accent))',
          'accent-foreground': 'hsl(var(--sidebar-accent-foreground))',
          border: 'hsl(var(--sidebar-border))',
          ring: 'hsl(var(--sidebar-ring))'
        },
        success: 'hsl(var(--success))',
        warning: 'hsl(var(--warning))',
        info: 'hsl(var(--info))',
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      fontFamily: {
        sans: ['var(--font-sans)', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'monospace'],
      },
    },
  },
}`

// ============================================================
// Base CSS — minimal resets + animations (everything else is Tailwind)
// ============================================================

const BaseCSS = `
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
/* Checkbox/radio styling injected at end of body by layout.go to beat Tailwind CDN */

/* HTMX indicators */
.htmx-indicator { display: none; }
.htmx-request .htmx-indicator { display: inline-block; }
.htmx-request.htmx-indicator { display: inline-block; }

/* Error display (dev mode) */
.benmore-error {
  background: hsl(0 62.8% 30.6% / 0.1);
  border: 1px solid hsl(0 62.8% 30.6% / 0.2);
  padding: 1rem;
  margin: 0.5rem 0;
  color: hsl(var(--destructive));
  font-family: var(--font-mono);
  font-size: 0.8125rem;
}
`

// ============================================================
// DefaultJS — table sort/filter, tabs, modals, toasts, HTMX
// ============================================================

const DefaultJS = `
function filterTable(input) {
  var filter = input.value.toLowerCase();
  var table = input.closest('[data-component="table"]');
  if (!table) return;
  var tbody = table.querySelector('tbody');
  if (!tbody) return;
  for (var i = 0; i < tbody.rows.length; i++) {
    var row = tbody.rows[i];
    row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none';
  }
}
function sortTable(th) {
  var table = th.closest('table');
  var tbody = table.querySelector('tbody');
  var idx = Array.from(th.parentNode.children).indexOf(th);
  var rows = Array.from(tbody.rows);
  var asc = th.dataset.sort !== 'asc';
  table.querySelectorAll('th').forEach(function(h) { h.dataset.sort = ''; });
  th.dataset.sort = asc ? 'asc' : 'desc';
  rows.sort(function(a, b) {
    var av = (a.cells[idx] || {}).textContent || '';
    var bv = (b.cells[idx] || {}).textContent || '';
    av = av.trim(); bv = bv.trim();
    var an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
}
function switchTab(btn, idx) {
  var tabs = btn.closest('[data-component="tabs"]');
  tabs.querySelectorAll('[data-tab-trigger]').forEach(function(b) { b.classList.remove('bg-background', 'text-foreground', 'shadow-sm'); b.classList.add('text-muted-foreground'); });
  btn.classList.add('bg-background', 'text-foreground', 'shadow-sm');
  btn.classList.remove('text-muted-foreground');
  tabs.querySelectorAll('[data-tab-panel]').forEach(function(p, i) { p.style.display = i === idx ? 'block' : 'none'; });
}
function openModal(id) { var d = document.getElementById(id); if (d) d.showModal(); }
function closeModal(id) { var d = document.getElementById(id); if (d) d.close(); }
function toggleAccordion(btn) {
  var content = btn.nextElementSibling;
  var icon = btn.querySelector('[data-accordion-icon]');
  var isOpen = content.style.maxHeight && content.style.maxHeight !== '0px';
  if (isOpen) {
    content.style.maxHeight = '0px';
    content.style.opacity = '0';
    if (icon) icon.style.transform = 'rotate(0deg)';
  } else {
    content.style.maxHeight = content.scrollHeight + 'px';
    content.style.opacity = '1';
    if (icon) icon.style.transform = 'rotate(180deg)';
  }
}
function showToast(message, type) {
  var c = document.querySelector('[data-toast-container]');
  if (!c) { c = document.createElement('div'); c.setAttribute('data-toast-container',''); c.className = 'fixed top-4 right-4 z-[100] flex flex-col gap-2'; document.body.appendChild(c); }
  var colors = { error: 'bg-destructive text-destructive-foreground', success: 'bg-primary text-primary-foreground', warning: 'bg-warning text-foreground', info: 'bg-secondary text-secondary-foreground' };
  var t = document.createElement('div');
  t.className = 'px-4 py-3 rounded-lg text-sm font-medium shadow-lg max-w-sm ' + (colors[type] || colors.error);
  t.style.animation = 'toast-in 0.2s ease, toast-out 0.2s ease 3.8s forwards';
  t.textContent = message;
  c.appendChild(t);
  setTimeout(function() { t.remove(); }, 4000);
}
// Close dropdowns on outside click
document.addEventListener('click', function(e) {
  document.querySelectorAll('[data-dropdown-menu]').forEach(function(m) {
    if (!m.parentElement.contains(e.target)) m.style.display = 'none';
  });
});
// HTMX events
document.addEventListener('htmx:responseError', function(e) {
  // The responseText for a 404/500 is usually a full HTML error page —
  // rendering it raw inside a toast looks broken. Try to extract a
  // human message: JSON {error: "..."} body, the response's <title>,
  // or fall back to a generic message keyed off the status code.
  var xhr = e.detail.xhr;
  var msg = '';
  var body = (xhr.responseText || '').trim();
  if (body.length && body[0] === '{') {
    try { msg = (JSON.parse(body) || {}).error || ''; } catch (err) {}
  }
  if (!msg && body.indexOf('<title>') !== -1) {
    var m = body.match(/<title>([^<]+)<\/title>/i);
    if (m) msg = m[1].trim();
  }
  if (!msg) {
    msg = xhr.status === 404 ? 'Not found' :
          xhr.status === 401 ? 'Sign in required' :
          xhr.status === 403 ? 'Not allowed' :
          xhr.status >= 500   ? 'Server error' :
          'Something went wrong';
  }
  showToast(msg, 'error');
});
document.addEventListener('htmx:afterSwap', function(e) {
  if (e.detail.target === document.body) window.scrollTo(0, 0);
});
document.addEventListener('click', function(e) {
  var link = e.target.closest('a[href]');
  if (link && link.href && !link.href.startsWith('javascript:') && !link.hasAttribute('hx-get')) {
    if (typeof htmx !== 'undefined') {
      document.querySelectorAll('.htmx-request').forEach(function(el) { htmx.trigger(el, 'htmx:abort'); });
    }
  }
});
`
