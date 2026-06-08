# Getting help

Thanks for using Benmore. Here's where to go, depending on what you need.

## First, the built-in docs

Most "how do I…" questions are answered without filing anything:

- **`./benmore docs`** — the full framework guide, built into the binary.
- **[`docs/agent/build.md`](docs/agent/build.md)** — the same guide in the repo (the model, schema, config, the `bm` SDK, auto-CRUD, auth, flows/hooks, the dev loop).
- **[`README.md`](README.md)** — install + quickstart.

## Usage questions ("how do I do X?")

Open a **GitHub Discussion**, not an issue. The issue tracker is for confirmed bugs and concrete feature requests — keeping questions in Discussions makes them searchable for the next person and keeps the tracker actionable.

## Bug reports

Open a **GitHub Issue** using the bug template. A good report includes:

- `./benmore version` output, your OS, and Go version
- A **minimal app** that reproduces it (an `app.yaml` + `schema.prisma` + the smallest page/flow that triggers the problem) — `benmore new` gives you a clean starting point
- What you expected vs. what happened, with exact error text / logs

## Feature requests

Open an **Issue** using the feature template. Describe the use case, not just the proposed API — it helps us find the right primitive.

## Security vulnerabilities

**Do not open a public issue.** See [`SECURITY.md`](SECURITY.md) for private reporting.

## What's out of scope here

This repository is the **open-source Benmore framework** — the runtime you build and self-host. The **hosted Benmore platform** (deployment, fleet management, the agent build loop, billing, accounts) is a separate commercial product. For anything about the hosted service — billing, your account, a deployed app on benmore.ai — contact **support@benmore.tech**; the maintainers here can't help with hosted-platform issues through this tracker.
