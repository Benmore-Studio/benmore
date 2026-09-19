package main

// Feature-pack preparation, route/model renaming, and literal rewriting.

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

func prepareFeaturePackForInstall(pack FeaturePack, files map[string][]byte, opts FeatureInstallOptions) (FeaturePack, map[string][]byte, []FeaturePackRename, []FeaturePackRename, []FeaturePackRename, error) {
	pack.Files = append([]FeaturePackFile(nil), pack.Files...)
	pack.SchemaModels = append([]FeaturePackModel(nil), pack.SchemaModels...)
	pack.Flows = append([]string(nil), pack.Flows...)
	pack.Hooks = append([]string(nil), pack.Hooks...)
	pack.Routes = append([]string(nil), pack.Routes...)
	pack.StaticAssets = append([]string(nil), pack.StaticAssets...)
	pack.EnvRefs = append([]string(nil), pack.EnvRefs...)
	pack.RequiredOptions = append([]FeaturePackOption(nil), pack.RequiredOptions...)
	rawRoutePrefix := filepath.ToSlash(strings.TrimSpace(opts.RoutePrefix))
	routePrefix := normalizedRoutePrefix(opts.RoutePrefix)
	modelPrefix := normalizedModelPrefix(opts.ModelPrefix)
	explicitRouteMap, routeMapErr := normalizeFeatureRouteMap(opts.RouteMap)
	explicitModelMap, modelMapErr := normalizeFeatureModelMap(opts.ModelMap)
	var fileRenames []FeaturePackRename
	var routeRenames []FeaturePackRename
	var modelRenames []FeaturePackRename
	if strings.TrimSpace(opts.RoutePrefix) != "" && routePrefix == "" {
		return pack, files, nil, nil, nil, fmt.Errorf("route_prefix must contain at least one safe path segment")
	}
	if strings.TrimSpace(opts.ModelPrefix) != "" && modelPrefix == "" {
		return pack, files, nil, nil, nil, fmt.Errorf("model_prefix must contain at least one identifier character")
	}
	if rawRoutePrefix != "" && hasParentPathSegment(rawRoutePrefix) {
		return pack, files, nil, nil, nil, fmt.Errorf("route_prefix cannot contain ..")
	}
	if routeMapErr != nil {
		return pack, files, nil, nil, nil, routeMapErr
	}
	if modelMapErr != nil {
		return pack, files, nil, nil, nil, modelMapErr
	}

	modelMap := map[string]string{}
	tableMap := map[string]string{}
	routeMap := map[string]string{}
	packModelNames := map[string]bool{}
	for _, m := range pack.SchemaModels {
		if strings.TrimSpace(m.Name) != "" {
			packModelNames[m.Name] = true
		}
	}
	for old := range explicitModelMap {
		if !packModelNames[old] {
			return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("model_map references missing model %s", old)
		}
	}
	for _, m := range pack.SchemaModels {
		if strings.TrimSpace(m.Name) == "" {
			continue
		}
		next := ""
		if explicit := explicitModelMap[m.Name]; explicit != "" {
			next = explicit
		} else if modelPrefix != "" {
			next = modelPrefix + m.Name
		}
		if next != "" {
			modelMap[m.Name] = next
			if next != m.Name {
				modelRenames = append(modelRenames, FeaturePackRename{From: m.Name, To: next})
			}
		}
	}

	if len(modelMap) > 0 {
		seenModels := map[string]bool{}
		for i, m := range pack.SchemaModels {
			if next := modelMap[m.Name]; next != "" {
				src := replaceModelIdentifiers(m.Source, modelMap)
				renamed := curatedModel(next, src)
				if renamed.Source == "" {
					renamed = m
					renamed.Name = next
					renamed.Source = src
				}
				if m.Table != "" && renamed.Table != "" {
					if renamed.Table == m.Table && renamed.Name != m.Name {
						return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("model transform cannot safely rename model %s because table mapping remains %s", m.Name, m.Table)
					}
					tableMap[m.Table] = renamed.Table
				}
				pack.SchemaModels[i] = renamed
			}
			if seenModels[pack.SchemaModels[i].Name] {
				return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("model transforms create duplicate model %s", pack.SchemaModels[i].Name)
			}
			seenModels[pack.SchemaModels[i].Name] = true
		}
	}
	packRouteNames := map[string]bool{}
	for _, route := range pack.Routes {
		packRouteNames[route] = true
	}
	for old := range explicitRouteMap {
		if !packRouteNames[old] {
			return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("route_map references missing route %s", old)
		}
	}
	if routePrefix != "" || len(explicitRouteMap) > 0 {
		for _, route := range pack.Routes {
			next := explicitRouteMap[route]
			if next == "" && routePrefix != "" {
				next = prefixedFeatureRoute(route, routePrefix)
			}
			if next != "" && next != route {
				routeMap[route] = next
				routeRenames = append(routeRenames, FeaturePackRename{From: route, To: next})
			}
		}
	}
	rewriteMap := map[string]string{}
	for old, next := range tableMap {
		rewriteMap[old] = next
	}
	for old, next := range modelMap {
		rewriteMap[old] = next
	}

	preparedFiles := map[string][]byte{}
	transformedBodies := map[string]bool{}
	seenPaths := map[string]bool{}
	for p, body := range files {
		nextPath := filepath.ToSlash(p)
		nextPath = transformedFeatureFilePath(nextPath, body, routeMap, routePrefix)
		if nextPath != filepath.ToSlash(p) {
			fileRenames = append(fileRenames, FeaturePackRename{From: filepath.ToSlash(p), To: nextPath})
		}
		if hasParentPathSegment(nextPath) {
			return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("transformed path escapes feature root: %s", nextPath)
		}
		if seenPaths[nextPath] {
			return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("route transforms create duplicate file path %s", nextPath)
		}
		seenPaths[nextPath] = true
		body = transformFeatureBody(body, nextPath, rewriteMap, routeMap, transformedBodies)
		preparedFiles[nextPath] = body
	}

	var preparedManifestFiles []FeaturePackFile
	for _, f := range pack.Files {
		oldPath := filepath.ToSlash(f.Path)
		nextPath := oldPath
		nextPath = transformedFeatureFilePath(nextPath, files[oldPath], routeMap, routePrefix)
		body, ok := preparedFiles[nextPath]
		if !ok {
			body = transformFeatureBody(files[oldPath], nextPath, rewriteMap, routeMap, transformedBodies)
		}
		sha := f.SHA256
		size := f.Size
		if transformedBodies[nextPath] {
			sha = hashBytesSHA256(body)
			size = int64(len(body))
		}
		preparedManifestFiles = append(preparedManifestFiles, FeaturePackFile{Path: nextPath, SHA256: sha, Size: size})
	}
	pack.Files = preparedManifestFiles
	pack.StaticAssets = nil
	pack.Routes = nil
	for _, f := range pack.Files {
		if strings.HasPrefix(f.Path, "static/") {
			pack.StaticAssets = appendUnique(pack.StaticAssets, f.Path)
			pack.Routes = appendUnique(pack.Routes, routeForStaticPath(f.Path))
		}
	}
	for _, route := range routeMap {
		if strings.HasPrefix(route, "/api/") {
			pack.Routes = appendUnique(pack.Routes, route)
		}
	}
	sort.Slice(pack.Files, func(i, j int) bool { return pack.Files[i].Path < pack.Files[j].Path })
	sort.Strings(pack.StaticAssets)
	sort.Strings(pack.Routes)
	sortFeaturePackRenames(fileRenames)
	sortFeaturePackRenames(routeRenames)
	sortFeaturePackRenames(modelRenames)
	return pack, preparedFiles, fileRenames, routeRenames, modelRenames, nil
}

// transformFeatureBody applies the token/route rewrite maps to a text body,
// recording in transformed whether the content actually changed. Binary
// bodies pass through untouched.
func transformFeatureBody(body []byte, nextPath string, rewriteMap, routeMap map[string]string, transformed map[string]bool) []byte {
	if (len(rewriteMap) == 0 && len(routeMap) == 0) || featurePackLooksBinary(body) {
		return body
	}
	nextBody := []byte(rewriteFeaturePackText(string(body), rewriteMap, routeMap))
	if !bytes.Equal(nextBody, body) {
		transformed[nextPath] = true
	}
	return nextBody
}

func normalizedRoutePrefix(prefix string) string {
	prefix = filepath.ToSlash(strings.TrimSpace(prefix))
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return ""
	}
	parts := strings.Split(prefix, "/")
	var out []string
	for _, part := range parts {
		part = slugifyFeatureName(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, "/")
}

func normalizedModelPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ""
	}
	parts := regexp.MustCompile(`[A-Za-z0-9]+`).FindAllString(prefix, -1)
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		if len(part) > 1 {
			b.WriteString(part[1:])
		}
	}
	out := b.String()
	if out == "" {
		return ""
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "M" + out
	}
	return out
}

func parseFeatureRenameMap(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range values {
		for _, item := range splitCSV(v) {
			if item == "" {
				continue
			}
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("mapping %q must use FROM=TO", item)
			}
			from := strings.TrimSpace(parts[0])
			to := strings.TrimSpace(parts[1])
			if from == "" || to == "" {
				return nil, fmt.Errorf("mapping %q must include both FROM and TO", item)
			}
			if existing, ok := out[from]; ok && existing != to {
				return nil, fmt.Errorf("duplicate mapping for %q", from)
			}
			out[from] = to
		}
	}
	return out, nil
}

func mergeFeatureRenameMap(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = map[string]string{}
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func sortedStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeFeatureRouteMap(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	targets := map[string]string{}
	for from, to := range in {
		cleanFrom, err := normalizeFeatureRoutePath(from)
		if err != nil {
			return nil, fmt.Errorf("route_map source %q: %w", from, err)
		}
		cleanTo, err := normalizeFeatureRoutePath(to)
		if err != nil {
			return nil, fmt.Errorf("route_map target %q: %w", to, err)
		}
		if cleanFrom == cleanTo {
			continue
		}
		if strings.HasPrefix(cleanFrom, "/api/") != strings.HasPrefix(cleanTo, "/api/") {
			return nil, fmt.Errorf("route_map cannot change route type between page and api routes: %s -> %s", cleanFrom, cleanTo)
		}
		if prior := targets[cleanTo]; prior != "" && prior != cleanFrom {
			return nil, fmt.Errorf("route_map maps both %s and %s to %s", prior, cleanFrom, cleanTo)
		}
		targets[cleanTo] = cleanFrom
		out[cleanFrom] = cleanTo
	}
	return out, nil
}

func normalizeFeatureModelMap(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	targets := map[string]string{}
	for from, to := range in {
		from = strings.TrimSpace(from)
		to = strings.TrimSpace(to)
		if !featurePrismaModelNameRE.MatchString(from) {
			return nil, fmt.Errorf("model_map source %q is not a valid Prisma model name", from)
		}
		if !featurePrismaModelNameRE.MatchString(to) {
			return nil, fmt.Errorf("model_map target %q is not a valid Prisma model name", to)
		}
		if from == to {
			continue
		}
		if prior := targets[to]; prior != "" && prior != from {
			return nil, fmt.Errorf("model_map maps both %s and %s to %s", prior, from, to)
		}
		targets[to] = from
		out[from] = to
	}
	return out, nil
}

func rewriteFeaturePackText(s string, tokenMap, routeMap map[string]string) string {
	s = replaceModelIdentifiers(s, tokenMap)
	if len(routeMap) == 0 || s == "" {
		return s
	}
	routes := make([]string, 0, len(routeMap))
	for old := range routeMap {
		routes = append(routes, old)
	}
	sort.Slice(routes, func(i, j int) bool { return len(routes[i]) > len(routes[j]) })
	for _, old := range routes {
		s = replaceRouteLiteral(s, old, routeMap[old])
	}
	return s
}

func replaceRouteLiteral(s, old, replacement string) string {
	if s == "" || old == "" || old == replacement {
		return s
	}
	var b strings.Builder
	pos := 0
	changed := false
	for {
		idx := strings.Index(s[pos:], old)
		if idx < 0 {
			break
		}
		start := pos + idx
		end := start + len(old)
		b.WriteString(s[pos:start])
		if routeLiteralBoundaryBefore(s, start) && routeLiteralBoundaryAfter(s, end) {
			b.WriteString(replacement)
			changed = true
		} else {
			b.WriteString(s[start:end])
		}
		pos = end
	}
	if !changed {
		return s
	}
	b.WriteString(s[pos:])
	return b.String()
}

func routeLiteralBoundaryBefore(s string, start int) bool {
	if start <= 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:start])
	return !isRouteLiteralPathRune(r)
}

func routeLiteralBoundaryAfter(s string, end int) bool {
	if end >= len(s) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(s[end:])
	return !isRouteLiteralPathRune(r)
}

func isRouteLiteralPathRune(r rune) bool {
	return r == '/' || r == '-' || r == '_' || r == '.' || r == '~' || r == '%' ||
		(r >= '0' && r <= '9') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z')
}

func replaceModelIdentifiers(s string, modelMap map[string]string) string {
	if len(modelMap) == 0 || s == "" {
		return s
	}
	names := make([]string, 0, len(modelMap))
	for old := range modelMap {
		names = append(names, old)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, old := range names {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(old) + `\b`)
		s = re.ReplaceAllString(s, modelMap[old])
	}
	return s
}

func featurePackLooksBinary(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	limit := len(b)
	if limit > 8192 {
		limit = 8192
	}
	for _, c := range b[:limit] {
		if c == 0 {
			return true
		}
	}
	return !utf8.Valid(b)
}

func sortFeaturePackRenames(in []FeaturePackRename) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].From == in[j].From {
			return in[i].To < in[j].To
		}
		return in[i].From < in[j].From
	})
}
