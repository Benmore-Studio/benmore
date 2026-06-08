# CLI Conventions (clig.dev)

The benmore CLI follows [clig.dev](https://clig.dev) guidelines. This doc is the contract every command should meet and the primitives to use.

## Output discipline

- **stdout is data.** Only emit results, JSON, or user-requested text here.
- **stderr is status / logs / progress / warnings / errors.** Anything the user wants to see but not pipe.
- **Never mix.** A piped `benmore describe | jq` must never choke on a status line in the middle of the JSON.

## Flags every data-returning command supports

| Flag | Behavior |
|---|---|
| `--json` | Force JSON output regardless of TTY |
| `--no-json` | Force human output even when piped |
| `--yes` | Auto-confirm prompts (required in non-TTY for destructive ops) |

Auto-detection: if stdout is **not** a TTY (piped / redirected), `--json` is assumed. Humans at a terminal get pretty output by default.

## Color

- Enabled when stderr/stdout is a TTY.
- Disabled when `NO_COLOR` is set (https://no-color.org).
- Disabled when `TERM=dumb`.

## Exit codes

```
0  success
1  generic failure
2  bad usage (unknown flag, missing arg)
3  domain-specific failure (deploy failed, build errored)
4  auth / permission
5  not found (app / file / resource)
```

Scripts can branch on these. Don't use `os.Exit(1)` as the catch-all.

## Prompts

- Never prompt when stdin is not a TTY. Refuse with a warning pointing at `--yes`.
- Destructive commands (`delete_*`, `revert_*`) MUST confirm via `cliConfirm()`.
- `--yes` skips all prompts.

## Primitives (in `cli_output.go`)

```go
cliWantsJSON() bool
cliIsTTY(*os.File) bool
cliIsColorTerm(*os.File) bool

cliExit(code int, fmt string, args...)    // writes to stderr, exits
cliWarn(fmt string, args...)              // stderr, yellow prefix
cliInfo(fmt string, args...)              // stderr, dimmed
cliWrite(data any, human func(io.Writer)) // auto JSON/human
cliConfirm(prompt string) bool            // y/N, refuses non-TTY
```

## Idiomatic command shape

```go
func cmdStatus() {
    dir := getAppDir(2)
    out, err := computeStatus(dir)
    if err != nil {
        cliExit(cliExitDomain, "status failed: %v", err)
    }
    cliWrite(out, func(w io.Writer) {
        fmt.Fprintf(w, "App: %s\n", out.Name)
        fmt.Fprintf(w, "Tables: %d\n", out.TableCount)
        fmt.Fprintf(w, "Pages: %d\n", out.PageCount)
    })
}
```

## Migration status

The primitives ship in v1.6. Existing commands use the old `fmt.Println` pattern and will migrate incrementally. Commands that already emit JSON with their own pattern keep it — no change required — but all new commands MUST use `cliWrite`.

See `cli_compliance_test.go` for the enforcement rules (WIP).
