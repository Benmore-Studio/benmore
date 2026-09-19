# PR Review: Feature Packs And Sync Safety

Date: 2026-07-09
PR: https://github.com/ric897/benmore-go/pull/103
Branch: `agent-feature-packs-sync-safety`
Base: `main`
Risk level: High until live hosted clone-over validation is complete

## Findings

| ID | Severity | Status | Finding | Evidence | Recommendation |
| --- | --- | --- | --- | --- | --- |
| F1 | High | Fixed in this review pass and hardened in the subagent batch | Selected/component/curated clone accepted `--delete-missing`, which could delete every target source file absent from a mini-pack. The CLI rejects selections/transforms, and the planner now only allows delete-missing when the pack is a whole-source snapshot with `app.yaml` and `schema.prisma`. | `cli_feature.go:356`, `feature_pack.go:469`, `cli_feature_test.go:68`, `feature_pack_test.go:248` | Keep `--delete-missing` limited to whole-source clone-over. Hosted dry-run proof is still needed after platform rollout. |
| F2 | Medium | Fixed in this review pass | MCP feature export previously wrote the pack through a predictable temp path before returning `pack_b64`, which was unnecessary code-spill risk on a multi-user host. | `mcp_tools_feature.go:53`, `mcp_tools_feature.go:57` | Keep export in memory with `FeaturePackTarGzBytes`; do not reintroduce temp files for pack transport. |
| F3 | Medium | Fixed in this review pass | `sync-status` did not satisfy the `.benmore-link.yaml` secondary context requirement unless the directory also had normal upstream metadata. | `cli_sync_status.go:219`, `cli_sync_status.go:239`, `cli_sync_status_test.go:10`, `cli_sync_status_test.go:25` | Preserve linked repo metadata and branch mismatch notes as secondary context only. |
| F4 | High | Partially fixed in this review pass | Curated packs now include richer schema, plain TS pages, and one flow per core pack: Kanban drag/drop + status history, Notify Hub broadcast/unread inbox, and Foundry intake/review/evaluation. App-shell wiring guidance is now documented; hosted route proof is still missing. | `feature_pack.go:1152`, `feature_pack.go:1168`, `feature_pack.go:1209`, `feature_pack.go:1246`, `feature_pack_test.go:725`, `mcp_tools_api.go:1060`, `docs/agent/build.md:427`, `skills/benmore-cli/SKILL.md:298` | Keep the richer pack content and app-shell guidance; next prove `benmore clone ... --apply` on disposable hosted apps and probe installed static/flow routes. |
| F5 | High | Open | The PR proves CLI packaging and install planning locally, but not a real hosted dry-run/apply from source app to target app. | `cli_feature.go:315`, `mcp_tools_feature.go:90`, `cli_feature_test.go:131` | Run disposable hosted source and target apps through `benmore clone ... --dry-run` and `--apply`, then probe installed routes. |
| F6 | Medium | Fixed after review pass | Collision handling blocked safely, but route/model prefix support was missing, so "pick components to clone" was still hard when target names overlapped. | `cli_feature.go:39`, `cli_feature.go:305`, `feature_pack.go:630`, `feature_pack.go:712`, `feature_pack.go:996`, `feature_pack.go:1073`, `feature_pack_test.go:337` | `--route-prefix`/`--model-prefix` and exact `--route-map FROM=TO`/`--model-map Old=New` now rewrite static route files, single-route flow files, route strings, Prisma model names, and inferred table-name tokens before plan/apply. |
| F7 | Medium | Fixed after rollback batch | Server-side rollback is wired through app git and now has failure-injection coverage for tracked file restore after a partial apply. Untracked generated-file cleanup is still unproven. | `mcp_tools_feature.go:147`, `feature_pack.go:567`, `feature_pack.go:613`, `mcp_tools_feature_test.go:48`, `git_app.go:202`, `git_app.go:236` | Keep the platform-tag rollback test; add untracked generated-file cleanup proof if install apply ever writes generated files before a failure. |
| F8 | Medium | Fixed after review pass | Platform MCP feature install accepted unbounded `pack_b64` before app lookup/extract, which could waste host memory/CPU on oversized archives. | `feature_pack.go:30`, `feature_pack.go:310`, `feature_pack.go:348`, `mcp_tools_feature.go:98`, `feature_pack_test.go:600`, `mcp_tools_feature_test.go:13` | Keep archive, uncompressed, entry, manifest, and file-count limits; reject oversized MCP payloads before app lookup. |
| F9 | High | Fixed for CLI message; deploy-blocked for hosted proof | Hosted dry-run against disposable app `clone-proof-8-rf92ss` fails because the currently deployed platform does not yet expose `feature_install`. The CLI now turns that raw JSON-RPC error into an explicit platform-update dependency. | `cli_mcp.go:131`, `cli_mcp_test.go:10`, hosted command output on 2026-07-09 | Deploy/update the platform with this PR before claiming hosted clone/apply proof. Keep the actionable CLI message for mixed-version client/server windows. |
| F10 | High | Fixed for CLI message; deploy-blocked for hosted proof | Hosted `sync-status` against disposable app `clone-proof-8-rf92ss` fails because the deployed platform does not yet expose `/platform/app-manifest`. The CLI now returns an explicit platform-update dependency in JSON setup-error output. | `cli_sync_status.go:126`, `cli_sync_status_test.go:53`, hosted command output on 2026-07-09 | Deploy/update the platform with this PR before claiming hosted sync/conflict proof. Keep the actionable CLI message for mixed-version client/server windows. |
| F11 | High | Fixed in subagent batch | `benmore deploy` for a newly created app could skip the bulk manifest guard but still self-conflict on per-file pushes against the remote bare scaffold. | `cli_deploy.go:129`, `cli_deploy.go:175`, `cli_deploy_test.go:55` | Keep newly-created deploy pushes forced while ordinary deploys retain sync safety. |
| F12 | High | Fixed in subagent batch | `benmore deploy` could ship files that source manifests ignore, making local tooling/runtime artifacts invisible to later sync safety. | `cli_deploy.go:146`, `cli_deploy.go:160`, `cli_deploy_test.go:11` | Keep deploy collection on `sourceManifestExcluded` as the shared source of truth. |
| F13 | Medium | Fixed in subagent batch | `benmore feature install` / `clone` could exit 0 when the MCP response contained `ok:false`, hiding blocked plans or failed applies from automation. | `cli_feature.go:362`, `cli_feature.go:399`, `cli_feature_test.go:249` | Keep nonzero exit on `ok:false`; pretty JSON output remains unchanged. |
| F14 | Medium | Fixed in subagent batch | `benmore sync` reported failed app pulls but returned success to the shell. | `cli_sync.go:77`, `cli_sync.go:88`, `cli_sync_test.go:11`, `cli_sync_test.go:53` | Keep interactive sync nonzero on list/pull failure; bootstrap remains best-effort by ignoring the count. |
| F15 | Low | Fixed in subagent batch | Pull tar extraction used an ad hoc `..` substring skip. It now rejects unsafe paths and link entries loudly while allowing benign dotted names. | `cli_pull_hybrid.go:196`, `cli_pull_hybrid.go:250`, `tar_resilience_test.go:91`, `tar_resilience_test.go:118`, `tar_resilience_test.go:151` | Keep safe extraction; remaining caveat is streaming extraction is not atomic if a bad entry appears after earlier safe files. |

## Intent Capture

The user intent is not just "tar up files." The requested product outcome is:

- A Benmore user can clone a useful feature or whole app into another deployed app without accidentally overwriting remote edits.
- Notify Hub, Kanban, and Foundry are reusable starter packs, not one-off templates.
- A user can choose either a curated pack or specific source-app components: files, models, and flows.
- Dry-run is the default and tells the user exactly what will be added, updated, deleted, blocked, or required.
- Apply is explicit, conservative, rollback-aware, and easy to reason about.
- The deployed Benmore app is the source of truth; GitHub is only supporting context.

## User Stories

| ID | Story | Acceptance Criteria | Current State |
| --- | --- | --- | --- |
| US1 | As an app builder, I can run `benmore clone notify-hub --app vint-compliance --dry-run` to preview Notify Hub install. | Dry-run returns file/model/env/collision plan and does not mutate target. | CLI/MCP payload paths exist; local pack tests prove Notify Hub includes page, models, broadcast flow, and route metadata. |
| US2 | As an app builder, I can install Notify Hub with `--apply` after reviewing the dry-run. | Target receives useful inbox, preferences, broadcast/send flow, and unread count behavior. | Local apply/parser/compile tests pass; hosted apply and route probe remain open. |
| US3 | As an app builder, I can run `benmore feature clone foundry --app target --dry-run`. | Foundry appears in catalog and installs a meaningful foundry-style workflow. | Foundry now includes project/artifact/evaluation/review models, page, and advance flow; hosted proof remains open. |
| US4 | As an app builder, I can pick components from a source app. | `--paths`, `--models`, and `--flows` export only selected parts; selected clone cannot delete unrelated target files; prefix or exact map flags avoid route/model collisions. | Implemented with `--delete-missing` guard, `--route-prefix`/`--model-prefix`, and exact `--route-map`/`--model-map`. |
| US5 | As a remote collaborator, my hosted edits are not silently overwritten by a stale local push. | Push, delete, deploy, pull, and sync use manifest drift checks and block conflicts by default. | Implemented with unit coverage; hosted conflict smoke remains open. |
| US6 | As a platform operator, I can inspect local-vs-deployed state. | `sync-status` exits 0/1/2/3 and reports GitHub as secondary context when `.git` or `.benmore-link.yaml` exists. | Implemented; `.benmore-link.yaml` context fixed. Hosted proof is deploy-blocked because current platform lacks `/platform/app-manifest`; CLI now explains that. |
| US7 | As a safety reviewer, I can verify no data, uploads, env values, or secrets leave the source app. | Manifests and packs exclude protected paths; env refs are names only. | Unit-covered for manifest/pack exclusion; pull endpoint smoke still recommended. |

## Persona Review

| Persona | What Works | Concern |
| --- | --- | --- |
| CLI app builder | `benmore clone` is discoverable, dry-run by default, supports curated/source/local/pack inputs, and has route/model prefixes plus exact maps for collision rewrites. | Arbitrary file maps are still not implemented; hosted apply proof is still missing. |
| Remote collaborator | Manifest guard reduces accidental overwrites of hosted changes. | Live hosted conflict proof is still missing. |
| Template curator | All curated packs share `feature.yaml` format and catalog entries, with richer page/flow/model content for Kanban, Notify Hub, and Foundry; docs now explain that installed TSX modules need app-shell linking or a host HTML page. | Hosted route probes are still missing. |
| Platform operator | Apply snapshots app git, reloads after success, and now has a failure-injection test proving tracked files return to the snapshot. | Untracked generated files written before a future failure path remain unproven. |
| Security reviewer | Protected paths are excluded, tar paths are guarded, hash mismatches block, MCP export no longer writes temp pack files, and pack payloads are size/file-count bounded. | Hosted gateway request-size behavior still needs live proof. |
| Release operator | Mixed-version hosted validation now fails with an actionable platform-update message instead of a raw unknown-tool error. | Hosted clone/apply cannot be proven until the platform deployment includes `feature_install`. |

## Review Evidence

| Evidence ID | Source | Verified Fact |
| --- | --- | --- |
| E1 | `platform.go:665` | This branch's platform source registers `GET /platform/app-manifest` as the deployed-source manifest endpoint; the currently deployed hosted platform still lacks it. |
| E2 | `source_manifest.go:18` | Source manifest is defined as deployable-code fingerprint excluding secrets, data, uploads, git/runtime state, logs, and generated `bm.d.ts`. |
| E3 | `source_manifest.go:134` | Protected-path exclusion implementation covers data DB files, `env.yaml`, `.git`, `.benmore`, uploads, logs, and generated types. |
| E4 | `cli_sync_status.go:235` | `sync-status` gathers local Git and `.benmore-link.yaml` secondary context. |
| E5 | `cli_feature.go:221` | Clone/install parser supports source, target, env split, selection, dry-run/apply, replace, and delete-missing flags. |
| E6 | `cli_feature.go:356` | Parser rejects `--delete-missing` with selected component clone flags or route/model transforms. |
| E7 | `feature_pack.go:438` | Feature install planning computes adds, updates, deletes, schema additions, env refs, required options, transforms, and collisions. |
| E8 | `feature_pack.go:559` | Install plan blocks when collisions or required options exist. |
| E9 | `mcp_tools_feature.go:57` | MCP feature export returns an in-memory tarball encoded as `pack_b64`. |
| E10 | `mcp_tools_feature.go:147` | Server install snapshots app git before apply and restores on apply error when a snapshot exists. |
| E11 | `cli_feature_test.go:68` | Parser regression covers rejection of selected clone plus `--delete-missing`. |
| E12 | `cli_sync_status_test.go:10` | Linked workspace context is covered even without a git checkout. |
| E13 | `feature_pack_test.go:230` | Prefix install coverage proves route/model prefixes avoid existing file/model collisions and write transformed file/schema/table references. |
| E14 | `feature_pack_test.go:288` | Route-prefix coverage proves flow files and custom API route strings are renamed and rewritten. |
| E15 | `feature_pack_test.go:463` | Curated-pack coverage proves Kanban, Notify Hub, and Foundry include routes, flows, added models, apply cleanly, load through `LoadFlowsGHA`, and compile their static pages. |
| E16 | `feature_pack.go:30` | Pack limits cap decoded archive size, uncompressed source bytes, per-entry size, manifest size, and archive entry count. |
| E17 | `feature_pack_test.go:600` | Oversized entry and too-many-file packs are rejected on write/read paths. |
| E18 | `mcp_tools_feature_test.go:13` | Oversized MCP `pack_b64` is rejected before app lookup. |
| E19 | `feature_pack.go:630` | Exact route/model maps are normalized and validated before install transforms run. |
| E20 | `feature_pack.go:996` | Explicit route maps move matching static route files and single-route flow files before planning/apply. |
| E21 | `feature_pack_test.go:337` | Unit coverage proves exact route/model maps avoid collisions and rewrite static files, flow files, route strings, Prisma models, and table-name tokens. |
| E22 | `mcp_tools_feature_test.go:28` | Platform MCP map arguments parse from JSON objects and string shorthand. |
| E23 | `feature_pack.go:567` | Apply has a test-only after-write hook, nil in production, used to force deterministic partial-write failure. |
| E24 | `mcp_tools_feature_test.go:48` | Platform-tagged rollback test snapshots a git-backed temp app, forces failure after overwriting a tracked file, restores with `gitHardRestore`, and verifies old content returns. |
| E25 | `cli_mcp.go:131` | CLI formats missing `feature_*` MCP tools with a feature-pack platform-update hint. |
| E26 | `cli_mcp_test.go:10` | Cloud/platform-tagged tests cover the missing feature-tool hint and prove unrelated unknown tools keep their original error shape. |
| E27 | Hosted command output, 2026-07-09 | `/tmp/benmore-cloud clone notify-hub clone-proof-8-rf92ss --target-env dev --dry-run` reached the platform but returned `unknown tool: feature_install`; patched CLI added the deploy/update guidance. |
| E28 | `mcp_tools_api.go:1060` | Canonical `api(at:"feature-packs")` now says installed `static/*.tsx` files are feature modules and do not rewrite existing nav automatically. |
| E29 | `docs/agent/build.md:427` | Agent build docs now tell app builders to import/link installed TSX modules or add a host HTML page for clean navigation. |
| E30 | `skills/benmore-cli/SKILL.md:298` | CLI skill guidance now carries the same app-shell integration note for agents using `benmore clone`. |
| E31 | `CHANGELOG.md:43` | Release notes disclose the app-shell linking expectation for installed TSX feature modules. |
| E32 | `cli_sync_status.go:126` | CLI formats missing `/platform/app-manifest` with a sync-status/source-manifest platform-update hint. |
| E33 | `cli_sync_status_test.go:53` | Cloud/platform-tagged tests cover the missing app-manifest hint and unrelated HTTP status passthrough. |
| E34 | Hosted command output, 2026-07-09 | `/tmp/benmore-cloud sync-status /tmp/benmore-sync-proof --app clone-proof-8-rf92ss --env dev --json` reached the platform but returned HTTP 404; patched CLI returned a JSON setup error with the deploy/update guidance. |
| E35 | `tar_resilience_test.go:15` | Cloud/platform-tagged test proves `createTarGz` includes normal source but excludes `data.db*`, `env.yaml`, `.git`, `.benmore`, `uploads`, `logs`, `src/bm.d.ts`, and `*.log`. |
| E36 | `feature_pack.go:469` | Planner blocks `delete_missing` unless the pack is a whole-source snapshot containing `app.yaml` and `schema.prisma`. |
| E37 | `feature_pack_test.go:248` | Curated Notify Hub plus `--replace --delete-missing` blocks and plans no target file deletes. |
| E38 | `cli_feature.go:399` | CLI parses feature-install MCP JSON and returns nonzero when `ok:false`. |
| E39 | `cli_feature_test.go:249` | Cloud-tagged test proves blocked `feature_install` responses return a nonzero CLI helper code. |
| E40 | `cli_deploy.go:160` | Deploy file collection now uses `sourceManifestExcluded` so deploy and manifests share protected-path rules. |
| E41 | `cli_deploy.go:175` | Newly created app deploy pushes are forced to avoid bare-scaffold self-conflicts; existing deploys keep guard behavior. |
| E42 | `cli_deploy_test.go:11` | Deploy collection excludes `.codex`, logs, screenshots, uploads, data DB files, generated `src/bm.d.ts`, and env files. |
| E43 | `cli_sync.go:77` | Interactive `benmore sync` exits nonzero when app listing or any app pull fails. |
| E44 | `cli_sync_test.go:11` | Sync tests cover failed pull accounting while still attempting every app. |
| E45 | `cli_pull_hybrid.go:250` | Pull tar extraction uses a safe join that rejects absolute paths and parent path segments. |
| E46 | `tar_resilience_test.go:91` | Pull extraction tests reject absolute/parent paths, reject symlink/hardlink entries, and allow benign dotted filenames. |

## Adversarial Review

What could break:

- A hosted source app clone can still fail due to auth, env routing, platform reload, or runtime migration behavior not covered by local unit tests.
- Hosted validation is currently blocked before install planning because the deployed platform has not picked up the `feature_install` MCP tool from this PR.
- Hosted sync/conflict validation is currently blocked before diffing because the deployed platform has not picked up `/platform/app-manifest` from this PR.
- Curated packs can install successfully locally while still failing hosted route probes; app-shell linking is now documented but not hosted-proven.
- `--replace` is correctly explicit, but users still need clearer dry-run copy around overwrite semantics before applying clone-over.
- Prefix and exact map support cover route/model collisions, including static routes, single-route flow files, route strings, Prisma models, and inferred table-name tokens; arbitrary file maps are still not implemented.
- Rollback failure-injection now proves tracked files return to the pre-apply snapshot; untracked generated files are still not proven.
- Pull extraction is safer, but still streaming and non-atomic: safe entries before a later malicious entry can remain on disk before the error returns.

What was fixed during the review:

- Blocked selected-component clone plus `--delete-missing`.
- Removed temp-file export from MCP feature export.
- Added `.benmore-link.yaml` secondary context and branch mismatch reporting to `sync-status`.
- Added route-prefix flow route/file rewriting, model-prefix table-token rewriting, and richer curated Kanban/Notify Hub/Foundry starter content.
- Added pack archive, uncompressed source, per-entry, manifest, and file-count limits before local or MCP install.
- Added exact `--route-map`/`--model-map` collision rewrites through CLI, MCP, dry-run planning, and apply.
- Added platform-tagged rollback failure-injection coverage for tracked file restore.
- Added an actionable mixed-version CLI error when hosted feature-pack MCP tools are missing.
- Added app-shell import/link guidance for installed TSX feature modules.
- Added an actionable mixed-version CLI error when the hosted source-manifest endpoint is missing.
- Added direct protected-path regression coverage for pull/deploy tarball creation.
- Hardened `delete_missing` so curated/component packs cannot prune whole target apps.
- Made feature install/clone return nonzero when the MCP result says `ok:false`.
- Aligned deploy file collection with source-manifest exclusions.
- Prevented newly-created deploys from self-conflicting against bare scaffold files.
- Made interactive `benmore sync` exit nonzero on list or pull failures.
- Replaced pull tar extraction traversal skipping with safe-path/link rejection tests.

What is intentionally mock-ahead:

- `TestRunFeatureInstallSendsExpectedMCPArgs` proves the CLI sends the right MCP payload, but does not prove the hosted server applies it.
- Curated pack tests prove local install, flow parsing, and TS compilation; docs explain app-shell linking, but hosted route exposure is still unproven.
- Pack-limit tests prove local/MCP rejection paths, not hosted request-size behavior at an upstream gateway.
- Exact-map tests prove local/MCP parsing and local apply rewrites, not hosted source-to-target clone behavior.
- Rollback failure-injection proves the apply/restore helper path in a git-backed temp app, not a live hosted MCP failure response.
- Hosted dry-run was attempted with real auth and a disposable target, but the platform deployment is behind the PR and lacks `feature_install`.

## Validation

Commands run on 2026-07-09:

| Command | Result |
| --- | --- |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -tags 'sqlite_fts5 cloud' ./... -run 'TestParseFeatureCloneArgs\|TestRunFeatureInstallSendsExpectedMCPArgs\|TestFeatureInstallExplicitRouteAndModelMaps\|TestFeatureInstallBlocksInvalidExplicitMaps\|TestFeatureInstallBlocksDeleteMissingWithPrefixes'` | PASS: `ok github.com/benmore-tech/benmore 0.679s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -tags 'sqlite_fts5 platform' ./... -run 'TestFeatureInstallMCPStringMapArgParsesObjectsAndStrings\|TestFeatureInstallMCPRejectsOversizedPackBeforeAppLookup\|TestFeatureInstallExplicitRouteAndModelMaps\|TestFeatureInstallBlocksInvalidExplicitMaps'` | PASS: `ok github.com/benmore-tech/benmore 0.594s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags 'sqlite_fts5 platform' ./... -run 'TestFeatureInstallRollbackRestoresTrackedFilesOnApplyFailure\|TestFeatureInstallMCPStringMapArgParsesObjectsAndStrings\|TestFeatureInstallExplicitRouteAndModelMaps'` | PASS: `ok github.com/benmore-tech/benmore 0.903s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -tags 'sqlite_fts5 cloud' ./... -run 'TestFormatMCPRPCError\|TestParseFeatureCloneArgs'` | PASS: `ok github.com/benmore-tech/benmore 1.067s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -tags 'sqlite_fts5 cloud' ./... -run 'TestFormatRemoteManifestHTTPError\|TestLocalGitAheadBehindIncludesBenmoreLink'` | PASS: `ok github.com/benmore-tech/benmore 1.034s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags 'sqlite_fts5 cloud' ./... -run 'TestRunFeatureInstall\|TestFeatureInstallReplaceUpdatesAndDeletesMissingFiles\|TestFeatureInstallBlocksDeleteMissingForCuratedPacks\|TestFeatureInstallBlocksDeleteMissingWithPrefixes\|TestParseFeatureCloneArgs'` | PASS: `ok github.com/benmore-tech/benmore 2.418s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags 'sqlite_fts5 cloud' ./... -run 'Test(CollectDeployFilesUsesSourceManifestExclusions\|DeployPushForceCoversNewlyCreatedApps\|SyncWorkspaceAppsReportsFailedPulls\|SyncWorkspaceAppsReportsListFailure\|BuildSourceManifestExcludesProtectedPaths\|FormatRemoteManifestHTTPError)'` | PASS: `ok github.com/benmore-tech/benmore 3.145s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags 'sqlite_fts5 cloud' -run 'Test(CreateTarGz\|ExtractTarGzPull)' -v .` | PASS: `ok github.com/benmore-tech/benmore 1.954s`; includes protected-path tar exclusion, unsafe pull paths, link rejection, dotted filenames, and unreadable-file skip. |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags sqlite_fts5 ./...` inside sandbox | FAIL: `TestExecStepAPI_AppendsQueryParams` panicked because `httptest.NewServer` could not bind localhost: `listen tcp6 [::1]:0: bind: operation not permitted`. |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags 'sqlite_fts5 cloud' ./...` inside sandbox | FAIL: same sandbox port-bind restriction in `TestExecStepAPI_AppendsQueryParams`. |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags 'sqlite_fts5 platform' ./...` inside sandbox | FAIL: same sandbox port-bind restriction in `TestExecStepAPI_AppendsQueryParams`. |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags sqlite_fts5 ./...` outside sandbox | PASS: `ok github.com/benmore-tech/benmore 5.525s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags 'sqlite_fts5 cloud' ./...` outside sandbox | PASS: `ok github.com/benmore-tech/benmore 3.061s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -count=1 -tags 'sqlite_fts5 platform' ./...` outside sandbox | PASS: `ok github.com/benmore-tech/benmore 4.426s` |
| `/tmp/benmore-cloud clone notify-hub clone-proof-8-rf92ss --target-env dev --dry-run` | BLOCKED by deployed platform version: exit 1, `MCP error -32601: unknown tool: feature_install`; patched CLI also printed `This Benmore platform does not yet expose feature-pack MCP tools. Deploy/update the platform server that includes this PR before running benmore clone or benmore feature install against hosted apps.` |
| `/tmp/benmore-cloud sync-status /tmp/benmore-sync-proof --app clone-proof-8-rf92ss --env dev --json` | BLOCKED by deployed platform version: exit 3, `{"error":"manifest failed (HTTP 404): 404 page not found\nThis Benmore platform does not yet expose /platform/app-manifest. Deploy/update the platform server that includes sync-status source manifests before running benmore sync-status, guarded push/pull/deploy/delete, or clone safety checks against hosted apps.","ok":false}` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -tags sqlite_fts5 ./...` | PASS: `ok github.com/benmore-tech/benmore 7.248s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -tags 'sqlite_fts5 cloud' ./...` | PASS: `ok github.com/benmore-tech/benmore 4.149s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go test -tags 'sqlite_fts5 platform' ./...` | PASS: `ok github.com/benmore-tech/benmore 4.192s` |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go vet ./...` | PASS: exit 0, no output |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go build -tags 'sqlite_fts5 cloud' -o /tmp/benmore-cloud .` | PASS: exit 0, no output |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache go build -tags 'sqlite_fts5 platform' -o /tmp/benmore-platform .` | PASS: exit 0, no output |
| `env GOCACHE=/tmp/benmore-go-cache GOMODCACHE=/tmp/benmore-go-modcache bash scripts/cloud-leak-guard.sh` | PASS: `cloud leak-guard: 182 cloud .go files + 3 embedded docs + shipped JS`; `cloud CLI is clean - no fleet code, credentials, client names, personal info, infra, or doc-internals` |
| `git diff --check` | PASS: exit 0, no output |

## Exact Follow-Ups

1. After platform rollout, hosted-smoke curated Kanban, Notify Hub, and Foundry install/apply paths and probe their static/flow routes; add more pack depth only for gaps found.
2. Add arbitrary file-map support only if mature app installs need direct file collision rewrites beyond route/model maps.
3. After the platform deployment includes `feature_install` and `/platform/app-manifest`, rerun disposable hosted source-to-target clone dry-run/apply plus hosted sync/conflict proof, then `benmore probe` or browser_check the installed routes.
4. Extend rollback proof to untracked generated files if a future install apply path can create them before failure.
5. Confirm hosted gateway and platform MCP surfaces report pack-limit errors cleanly for oversized clone archives.
6. Decide whether pull extraction should become atomic through temp-dir extraction plus rename if malicious archives are a realistic platform threat model.
