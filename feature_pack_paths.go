package main

// Feature-pack route/file mapping and protected-path checks.

import (
	"fmt"
	"path/filepath"
	"strings"
)

func normalizeFeatureRoutePath(route string) (string, error) {
	route = filepath.ToSlash(strings.TrimSpace(route))
	if route == "" {
		return "", fmt.Errorf("route is required")
	}
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	if strings.ContainsAny(route, " \t\r\n") {
		return "", fmt.Errorf("route cannot contain whitespace")
	}
	if hasParentPathSegment(strings.TrimPrefix(route, "/")) {
		return "", fmt.Errorf("route cannot contain ..")
	}
	return route, nil
}

func prefixedFeatureFilePath(p, routePrefix string) string {
	p = filepath.ToSlash(p)
	switch {
	case strings.HasPrefix(p, "static/"):
		rest := strings.TrimPrefix(p, "static/")
		return filepath.ToSlash(filepath.Join("static", filepath.FromSlash(routePrefix), filepath.FromSlash(rest)))
	case strings.HasPrefix(p, "flows/") && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")):
		base := filepath.Base(p)
		prefix := strings.ReplaceAll(routePrefix, "/", "-")
		return filepath.ToSlash(filepath.Join("flows", prefix+"-"+base))
	default:
		return p
	}
}

func transformedFeatureFilePath(p string, body []byte, routeMap map[string]string, routePrefix string) string {
	p = filepath.ToSlash(p)
	if strings.HasPrefix(p, "static/") {
		if nextRoute := routeMap[routeForStaticPath(p)]; nextRoute != "" {
			if nextPath := staticPathForRoute(nextRoute, filepath.Ext(p)); nextPath != "" {
				return nextPath
			}
		}
	}
	if strings.HasPrefix(p, "flows/") && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) && len(routeMap) > 0 && !featurePackLooksBinary(body) {
		var mapped []string
		for _, route := range scanFeatureRoutes(string(body)) {
			if nextRoute := routeMap[route]; nextRoute != "" {
				mapped = append(mapped, nextRoute)
			}
		}
		if len(mapped) == 1 {
			if nextPath := flowPathForRoute(mapped[0], filepath.Ext(p)); nextPath != "" {
				return nextPath
			}
		}
	}
	if routePrefix != "" {
		return prefixedFeatureFilePath(p, routePrefix)
	}
	return p
}

func staticPathForRoute(route, ext string) string {
	route = strings.TrimSpace(route)
	if route == "" || strings.HasPrefix(route, "/api/") {
		return ""
	}
	route = strings.Trim(route, "/")
	if route == "" {
		route = "index"
	}
	if hasParentPathSegment(route) {
		return ""
	}
	if ext == "" {
		ext = ".tsx"
	}
	return filepath.ToSlash(filepath.Join("static", filepath.FromSlash(route+ext)))
}

func flowPathForRoute(route, ext string) string {
	route = strings.TrimSpace(route)
	if !strings.HasPrefix(route, "/api/") {
		return ""
	}
	route = strings.TrimPrefix(route, "/api/")
	slug := slugifyFeatureName(route)
	if slug == "" {
		return ""
	}
	if ext == "" {
		ext = ".yaml"
	}
	return filepath.ToSlash(filepath.Join("flows", slug+ext))
}

func prefixedFeatureRoute(route, routePrefix string) string {
	route = strings.TrimSpace(route)
	if route == "" || route == "/" {
		return route
	}
	if strings.HasPrefix(route, "/api/") {
		rest := strings.TrimPrefix(route, "/api/")
		return "/" + filepath.ToSlash(filepath.Join("api", filepath.FromSlash(routePrefix), filepath.FromSlash(rest)))
	}
	if strings.HasPrefix(route, "/") {
		return "/" + filepath.ToSlash(filepath.Join(filepath.FromSlash(routePrefix), filepath.FromSlash(strings.TrimPrefix(route, "/"))))
	}
	return route
}

func safeFeatureJoin(root, rel string) (string, error) {
	return safeJoinUnderRoot(root, rel, "feature")
}

// featurePackPathProtected reports whether a pack file path targets a
// protected file or lives under a protected directory. sourceManifestExcluded's
// FILE branch only inspects the basename, so a crafted pack entry like
// ".benmore/server-secret" or ".git/config" would otherwise slip through and
// let an install overwrite the app's HMAC/session/OAuth secret or its git
// history. Reject any path with a protected directory segment as well.
func featurePackPathProtected(rel string) bool {
	rel = filepath.ToSlash(strings.TrimPrefix(rel, "./"))
	if sourceManifestExcluded(rel, false) {
		return true
	}
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case ".git", ".benmore", "uploads", "logs", "node_modules", "Benmore", ".claude", ".codex", ".agents":
			return true
		}
	}
	return false
}

func routeForStaticPath(p string) string {
	p = strings.TrimPrefix(filepath.ToSlash(p), "static/")
	ext := filepath.Ext(p)
	p = strings.TrimSuffix(p, ext)
	if p == "index" {
		return "/"
	}
	return "/" + p
}
