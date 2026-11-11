//go:build !cli

package main

import (
	"net/http"
	"slices"
	"strings"
)

// ignoredFieldsHeader names the submitted body fields that are no column of
// the table. Auto-CRUD drops them, and a create answered 201 with no sign of
// it: a typo (`titel`, `qty` for `quantity`) saved the row without the value.
// The header sits beside X-Stripped-Fields (protected columns); fields
// starting with "_" are framework parameters, and query parameters are not
// body fields.
const ignoredFieldsHeader = "X-Ignored-Fields"

func setIgnoredFieldsHeader(w http.ResponseWriter, r *http.Request, submitted []string, cols []Column) {
	known := make(map[string]bool, len(cols))
	for _, c := range cols {
		known[c.Name] = true
	}
	query := r.URL.Query()
	var ignored []string
	for _, name := range submitted {
		if name == "" || strings.HasPrefix(name, "_") || known[name] || query.Has(name) {
			continue
		}
		ignored = append(ignored, name)
	}
	if len(ignored) == 0 {
		return
	}
	slices.Sort(ignored)
	w.Header().Set(ignoredFieldsHeader, strings.Join(slices.Compact(ignored), ","))
}

// addIgnoredFields adds names to X-Ignored-Fields, keeping the list sorted and
// unique. An update also names there the encrypted fields it did not write
// because the value was the mask the caller reads (crud_masked_echo.go).
func addIgnoredFields(w http.ResponseWriter, names []string) {
	if len(names) == 0 {
		return
	}
	all := append([]string(nil), names...)
	if existing := w.Header().Get(ignoredFieldsHeader); existing != "" {
		all = append(all, strings.Split(existing, ",")...)
	}
	slices.Sort(all)
	w.Header().Set(ignoredFieldsHeader, strings.Join(slices.Compact(all), ","))
}

// ignoredParamsHeader names the query parameters a list did not apply: a
// filter on a column the table does not have, or an operator it does not
// know. `?stauts=active` (for status) answered every row the caller may
// read, as if the filter had matched them all. Live on 2.7.303:
// GET /api/probes?nope=1 returned all 12 rows with no sign. extra adds the
// reserved parameters the caller found unapplied: sort keys
// (resolveAPIListSort) and `include=<entry>` for an include entry that
// expands nothing (ignoredIncludeEntries).
const ignoredParamsHeader = "X-Ignored-Params"

func setIgnoredListParamsHeader(w http.ResponseWriter, r *http.Request, allowed map[string]bool, extra ...string) {
	ignored := append([]string(nil), extra...)
	for key := range r.URL.Query() {
		switch {
		case key == "" || strings.HasPrefix(key, "_") || apiFilterReservedParam(key):
			continue
		case key == "count" || key == "count_only":
			continue
		}
		if col, _ := splitAPIFilterKey(key); col != "" && allowed[col] {
			continue
		}
		ignored = append(ignored, key)
	}
	setIgnoredParamsHeader(w, ignored)
}

// setIgnoredParamsHeader sets X-Ignored-Params to the sorted, de-duplicated
// names, or leaves it unset when there are none.
func setIgnoredParamsHeader(w http.ResponseWriter, ignored []string) {
	if len(ignored) == 0 {
		return
	}
	ignored = slices.Clone(ignored)
	slices.Sort(ignored)
	w.Header().Set(ignoredParamsHeader, strings.Join(slices.Compact(ignored), ","))
}
