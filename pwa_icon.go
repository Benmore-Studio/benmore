//go:build !cli

package main

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

// The manifest's icon.
//
// The manifest used to name pwa.icon, else seo.favicon, else
// /static/icon-512.png, whether or not the app had that file. The scaffold
// ships static/favicon.svg and no PNG, so every new app's manifest (and a
// `pwa:` section written without `icon`) listed an icon that answered 404,
// and an install prompt needs a manifest icon that loads. The order is
// unchanged; a /static/ choice the app does not have is now skipped for the
// next one it does have, ending with the scaffold's favicon.

// pwaDefaultIcon is the conventional icon path the manifest names when
// app.yaml sets neither pwa.icon nor seo.favicon.
const pwaDefaultIcon = "/static/icon-512.png"

// manifestIconChoices lists what the manifest may name, in order: pwa.icon,
// seo.favicon, the conventional PNG, the scaffold's favicon.
func manifestIconChoices(design *DesignConfig) []string {
	var choices []string
	if design != nil {
		for _, v := range []string{design.PWA["icon"], design.SEO["favicon"]} {
			if v != "" {
				choices = append(choices, v)
			}
		}
	}
	return append(choices, pwaDefaultIcon, "/"+appStaticFaviconSVG)
}

// manifestIconStaticRel returns the static/-relative path of an app-relative
// /static/ URL. Any other value (another origin, an upload, an app route, a
// path that climbs out of /static/) reports false: whether it loads cannot be
// decided from the app's files.
func manifestIconStaticRel(src string) (string, bool) {
	u, err := url.Parse(src)
	if err != nil || u.Scheme != "" || u.Host != "" || !strings.HasPrefix(u.Path, "/static/") {
		return "", false
	}
	rel := path.Clean(strings.TrimPrefix(u.Path, "/static/"))
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

// pickManifestIcon returns the icon the manifest lists and the first choice
// (what the configuration, or the default, asked for). missing reports a
// static/-relative file the app does not serve. A choice outside /static/ is
// taken as written. When every /static/ choice is missing the first one
// stays, so the manifest still says what the configuration says and
// manifestIconWarnings names the file.
func pickManifestIcon(design *DesignConfig, missing func(rel string) bool) (icon, first string) {
	choices := manifestIconChoices(design)
	first = choices[0]
	for _, choice := range choices {
		if rel, ok := manifestIconStaticRel(choice); !ok || !missing(rel) {
			return choice, first
		}
	}
	return first, first
}

// manifestIconFor is the icon of app's manifest: served files are the ones
// the static handler would answer with (reviewed source when a connector
// manifest is loaded, else the contained file under static/).
func manifestIconFor(app *App) string {
	icon, _ := pickManifestIcon(app.Design, func(rel string) bool {
		if app.Dir == "" {
			return false // nothing to check against: keep what is configured
		}
		if appMCPManifestSnapshot(app) != nil {
			_, err := app.readSourceFile(filepath.Join("static", filepath.FromSlash(rel)))
			return err != nil
		}
		return !staticFileOnDisk(app.Dir, rel)
	})
	return icon
}

// staticFileOnDisk reports whether static/<rel> is a file the static handler
// serves from disk: a regular file that stays inside static/.
func staticFileOnDisk(dir, rel string) bool {
	root := filepath.Join(dir, "static")
	file, ok := openServableFile(root, filepath.Join(root, filepath.FromSlash(rel)))
	if !ok {
		return false
	}
	file.Close()
	return true
}

// manifestIconWarnings tells an app that declares a `pwa:` section when a
// manifest icon file is missing from static/: the file app.yaml names
// (pwa.icon, else seo.favicon) even when another icon stands in for it, or
// the default path when the app has no icon at all and the manifest's icon
// answers 404. The default being absent while the favicon stands in is the
// documented behaviour and is not reported, and an app without a `pwa:`
// section is not asking to be installed. Filed under app.yaml, so `benmore
// check` and a write of app.yaml report it and a write of another file does
// not (writeRelevantFindings).
func manifestIconWarnings(dir string) []CheckFinding {
	design := LoadAppConfigYAML(dir)
	if design == nil || len(design.PWA) == 0 {
		return nil
	}
	icon, first := pickManifestIcon(design, func(rel string) bool { return !staticFileOnDisk(dir, rel) })
	rel, ok := manifestIconStaticRel(first)
	if !ok || staticFileOnDisk(dir, rel) {
		return nil
	}
	source := ""
	switch first {
	case design.PWA["icon"]:
		source = "`pwa.icon` in app.yaml"
	case design.SEO["favicon"]:
		source = "`seo.favicon` in app.yaml"
	}
	const fix = "Add the file (a 512x512 PNG is what install prompts ask for), or set `pwa.icon` to an image under static/."
	var message string
	switch {
	case icon != first && source == "":
		return nil // the favicon stands in for the absent default
	case icon != first:
		message = fmt.Sprintf("web manifest icon: %s (%s) is not a file in static/, so /manifest.json lists %s instead. %s", first, source, icon, fix)
	case source == "":
		message = fmt.Sprintf("web manifest icon: app.yaml has a `pwa:` section but the app has no icon. /manifest.json lists %s (the default when neither `pwa.icon` nor `seo.favicon` is set), which is not a file in static/, so the icon answers 404 (an install prompt needs a manifest icon that loads). %s", first, fix)
	default:
		message = fmt.Sprintf("web manifest icon: %s (%s) is not a file in static/ and the app has no other icon, so the icon /manifest.json lists answers 404 (an install prompt needs a manifest icon that loads). %s", first, source, fix)
	}
	return []CheckFinding{{Severity: "warning", Source: "pwa", File: "app.yaml", Message: message}}
}
