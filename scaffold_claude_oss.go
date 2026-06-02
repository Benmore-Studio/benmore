//go:build !cli && !platform

package main

import "fmt"

// scaffoldClaudeMD returns the per-app guide for the open-source framework
// build: it points at the self-hosted workflow (benmore serve / benmore docs),
// not the hosted toolchain. The platform build uses the richer version in
// scaffold_claude_platform.go.
func scaffoldClaudeMD(title, name string) string {
	_ = name
	return fmt.Sprintf(`# %s — a Benmore app

Built on the Benmore framework. Edit files under `+"`static/`"+`, declare your
data in `+"`schema.prisma`"+`, configure in `+"`app.yaml`"+`, and run the app:

    benmore serve . --port 8080

The framework compiles `+"`static/*.tsx`"+` on the fly (no Node/build step),
auto-generates a REST + SSE + WebSocket API for every table in your schema,
and serves a typed `+"`bm`"+` SDK at `+"`/_internal/bm.js`"+` (types in `+"`src/bm.d.ts`"+`).

Reference: run `+"`benmore docs`"+` for the full framework guide, or read the
README in the framework repo. The frontend pattern lives in `+"`static/app.tsx`"+`.
`, title)
}
