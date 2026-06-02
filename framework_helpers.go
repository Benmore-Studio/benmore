package main

// framework_helpers.go holds tiny, generic helpers that are referenced from
// build-tag-agnostic (untagged) framework files and therefore must exist in
// every build combination — open framework and full platform alike. Keeping
// them here (no build constraint) avoids both the "undefined in the framework
// build" and the "duplicate symbol in the platform build" failure modes.

import "fmt"

// toInt64 coerces an arbitrary scanned value (nil / int / int64 / float64 /
// numeric string) to int64, returning 0 for anything it can't interpret.
func toInt64(v any) int64 {
	switch t := v.(type) {
	case nil:
		return 0
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case string:
		var n int64
		_, _ = fmt.Sscanf(t, "%d", &n)
		return n
	default:
		return 0
	}
}
