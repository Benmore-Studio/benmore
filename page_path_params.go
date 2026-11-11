//go:build !cli

package main

// Path parameters on server-rendered root pages.
//
// A root page's route comes from its filename. A `-:name` part of the
// filename is a path parameter, and the hyphens next to it separate path
// segments:
//
//	event-:id.html        → /event/:id
//	event-:id-rsvps.html  → /event/:id/rsvps
//	org-:org-team-:id.html → /org/:org/team/:id
//
// registerAppPageRoutes registers `:name` as a ServeMux `{name}` wildcard and
// copies the segment into the request's query, so a page binds it as `:name`
// or `:param_name` in queries: and as {{.param_name}} / {{param_name}} in the
// template, exactly like a query-string value (and with the same escaping).
//
// Such a page has no single URL: discovery files (sitemap.xml, llms.txt,
// feed.xml) and the service worker precache leave it out, and its canonical
// link is the requested record's own path. Filenames whose `:` is not a valid
// parameter keep their literal route (as before) and the write gate refuses
// them.

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// pageParamNameRe is a path parameter name: a ServeMux wildcard name and a
// SQL bind name at once.
var pageParamNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// pageRouteForFile is the route of a root page file (`about.html` → /about,
// `index.html` → /, `event-:id.html` → /event/:id).
func pageRouteForFile(name string) string {
	stem := strings.TrimSuffix(name, ".html")
	if stem == "index" {
		return "/"
	}
	if route, err := pageParamRoute(stem); err == nil && route != "" {
		return route
	}
	return "/" + stem
}

// pageParamRoute maps a filename stem with path parameters to its route. It
// returns "" and no error for a stem without `:`, and an error naming the
// problem for a `:` that is not a well-formed `-:name` parameter.
func pageParamRoute(stem string) (string, error) {
	if !strings.Contains(stem, ":") {
		return "", nil
	}
	var segments, literal []string
	seen := map[string]bool{}
	for _, token := range strings.Split(stem, "-") {
		name, isParam := strings.CutPrefix(token, ":")
		switch {
		case token == "":
			return "", fmt.Errorf("a `-` next to a path parameter must separate two parts (no leading, trailing or doubled `-`)")
		case !isParam && strings.Contains(token, ":"):
			return "", fmt.Errorf("`:` may only start a path parameter, written `-:name` (event-:id.html serves /event/:id)")
		case !isParam:
			literal = append(literal, token)
			continue
		case !pageParamNameRe.MatchString(name):
			return "", fmt.Errorf("path parameter %q must be a name of letters, digits and _ that does not start with a digit", ":"+name)
		case seen[name]:
			return "", fmt.Errorf("path parameter %q appears twice", ":"+name)
		case len(segments) == 0 && len(literal) == 0:
			return "", fmt.Errorf("the route must start with a fixed part (event-:id.html, not :id.html, which would answer every top-level path)")
		}
		seen[name] = true
		if len(literal) > 0 {
			segments = append(segments, strings.Join(literal, "-"))
			literal = nil
		}
		segments = append(segments, ":"+name)
	}
	if len(literal) > 0 {
		segments = append(segments, strings.Join(literal, "-"))
	}
	return "/" + strings.Join(segments, "/"), nil
}

// pageRouteHasParams reports whether a route has a `:` part, which no single
// URL stands for: a path parameter, or a malformed filename kept literal.
func pageRouteHasParams(route string) bool {
	return strings.Contains(route, ":")
}

// pageCanonicalPath is the path a page's canonical link and og:url name: the
// route itself, or for a route with path parameters the request's values put
// back into it, each escaped as one path segment. The query string is never
// part of it. It is "" when a parameter has no value (a render outside the
// page's own route).
func pageCanonicalPath(route string, r *http.Request) string {
	if !pageRouteHasParams(route) {
		return route
	}
	parts := strings.Split(route, "/")
	for i, part := range parts {
		name, isParam := strings.CutPrefix(part, ":")
		if !isParam {
			if strings.Contains(part, ":") {
				return ""
			}
			continue
		}
		value := ""
		if r != nil {
			value = r.PathValue(name)
		}
		if value == "" {
			return ""
		}
		parts[i] = url.PathEscape(value)
	}
	return strings.Join(parts, "/")
}

// pageDefaultTitle is the title of a page that declares none: its route, title
// cased, without path parameters (/about → About, /event/:id → Event).
func pageDefaultTitle(route string) string {
	if !pageRouteHasParams(route) {
		return strings.Title(strings.TrimPrefix(route, "/"))
	}
	var words []string
	for _, part := range strings.Split(strings.Trim(route, "/"), "/") {
		if part != "" && !strings.HasPrefix(part, ":") {
			words = append(words, strings.Title(part))
		}
	}
	return strings.Join(words, " ")
}

// rootPageFile reports whether an app-relative path is a root page the loader
// reads (loadPagesFromSources), not a static/, partials/, layouts/ or email
// file.
func rootPageFile(rel string) bool {
	rel = filepath.ToSlash(rel)
	return !strings.Contains(rel, "/") && strings.HasSuffix(rel, ".html") && rel != "head.html" && !isMetadataSidecar(rel)
}

// validatePageRouteFile is the write gate for a root page's filename: a `:`
// must be a well-formed path parameter, and a page with parameters must be
// reachable: its route may not collide with a framework route, a flow or
// another page, which the runtime would answer instead (registration skips
// the colliding page). Flat pages are not checked here.
func validatePageRouteFile(appDir, path string) string {
	rel := appRelativeFile(appDir, path)
	if !rootPageFile(rel) {
		return ""
	}
	stem := strings.TrimSuffix(rel, ".html")
	route, err := pageParamRoute(stem)
	if err != nil {
		return fmt.Sprintf("page route: %s: %v. A root page's path parameters come from its filename: `event-:id.html` serves /event/:id and binds :id (and :param_id, {{.param_id}}), `event-:id-rsvps.html` serves /event/:id/rsvps. See api(at:\"frontend\") ssr_path_params.", rel, err)
	}
	if route == "" || appDir == "" {
		return ""
	}
	if conflict := pageRouteCollision(appDir, route); conflict != "" {
		return fmt.Sprintf("page route: %s serves %s, which collides with %s, so the page would never be served. Rename the file (for example add a fixed part: `%s`). See api(at:\"frontend\") ssr_path_params.",
			rel, pageMuxPattern(route), conflict, pageRouteRenameHint(stem))
	}
	return ""
}

// pageRouteRenameHint suggests a filename whose route starts with another
// fixed part (event-:id → event-view-:id, served at /event-view/:id).
func pageRouteRenameHint(stem string) string {
	first, rest, ok := strings.Cut(stem, "-")
	if !ok {
		return stem + "-view.html"
	}
	return first + "-view-" + rest + ".html"
}

// pageRouteCollision registers the app's framework routes, flows and other
// pages as the loader does (dev and production) and names what route would
// take requests for the page route; "" when it registers.
func pageRouteCollision(appDir, route string) (conflict string) {
	defer func() {
		if recover() != nil {
			conflict = ""
		}
	}()
	app, tables, err := routeCandidateApp(appDir)
	if err != nil {
		// A schema or app.yaml that does not parse is reported by its own validator.
		return ""
	}
	if app.Pages != nil {
		delete(app.Pages, route) // this file's current version, if any
	}
	app.Flows = appRouteFlows(appDir)
	pattern := pageMuxPattern(route)
	for _, dev := range []bool{false, true} {
		app.DevMode = dev
		mux := buildAppRouteMux(app, dev, "", false, tables)
		registered, source := mux.conflictingRoute(pattern)
		if registered == "" {
			continue
		}
		for other, page := range app.Pages {
			if pageMuxPattern(other) == registered {
				return fmt.Sprintf("the page %s (%s)", page.File, registered)
			}
		}
		for name, flowPattern := range mux.flows {
			if flowPattern == registered {
				return fmt.Sprintf("flow %q (%s)", name, registered)
			}
		}
		return fmt.Sprintf("the framework route %s (%s)", registered, source)
	}
	return ""
}

// canonicalHref is the canonical/og:url value for a site URL and page path,
// escaped for a double-quoted attribute.
func canonicalHref(siteURL, path string) string {
	return html.EscapeString(siteURL + path)
}
