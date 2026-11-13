package main

// Shared argument preflight for every CLI command, run by main() before a
// command authenticates, installs skills, emits telemetry or touches the
// network:
//
//   - `--help` / `-h` anywhere before `--` prints that command's usage and
//     exits 0. Only the first argument used to be checked, so
//     `benmore disable myapp --help` paused the app.
//   - A flag the command does not declare is an error (exit 2, or the
//     command's own usage status) with a "did you mean" hint and the
//     accepted flags. Most commands read flags with getFlag/hasFlag, which
//     ignore anything else: `benmore probe <app> POST /x --data '{...}'`
//     sent the request with no body and reported success.
//   - `--flag=value` is rewritten to `--flag value` for declared value
//     flags, so every command accepts both spellings (several hand-rolled
//     parsers matched only `--flag value` and ignored or refused the other).
//
// The flags each command accepts are declared in cliCommandFlagSpecs
// (cli_flag_specs.go for the hosted CLI, below for the framework commands).
// TestCLIFlagSpecsCoverHandlerFlagReads keeps the declarations in step with
// the flags the handlers read.

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// cliFlagSpec is the set of flags one command accepts, named with their
// dashes ("--body", "-n").
type cliFlagSpec struct {
	valueFlags map[string]bool // take one argument: "--body X" or "--body=X"
	boolFlags  map[string]bool // take none
	// usageExit is the exit status for a rejected flag; 0 means 2 (usage).
	usageExit int
}

// cliFlags builds a spec. A trailing "=" marks a flag that takes a value:
// cliFlags("--body=", "--keep-session").
func cliFlags(names ...string) cliFlagSpec {
	spec := cliFlagSpec{valueFlags: map[string]bool{}, boolFlags: map[string]bool{}}
	for _, name := range names {
		if flag, ok := strings.CutSuffix(name, "="); ok {
			spec.valueFlags[flag] = true
		} else {
			spec.boolFlags[name] = true
		}
	}
	return spec
}

// withUsageExit returns spec with a different exit status for a rejected
// flag (sync-status reserves 2 for "conflict").
func (s cliFlagSpec) withUsageExit(code int) cliFlagSpec {
	s.usageExit = code
	return s
}

func (s cliFlagSpec) exitCode() int {
	if s.usageExit != 0 {
		return s.usageExit
	}
	return 2
}

func (s cliFlagSpec) accepts(flag string) bool {
	return s.valueFlags[flag] || s.boolFlags[flag]
}

// names lists the accepted flags, value flags marked with " <value>".
func (s cliFlagSpec) names() []string {
	var out []string
	for f := range s.valueFlags {
		out = append(out, f+" <value>")
	}
	for f := range s.boolFlags {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// cliCommandFlagSpecs maps a command name (and each alias) to the flags it
// accepts. A command that is not listed gets only the --help handling.
var cliCommandFlagSpecs = map[string]cliFlagSpec{}

// cliCommandAliases maps an alias to the name the usage text lists.
var cliCommandAliases = map[string]string{}

func registerCLIFlagSpecs(specs map[string]cliFlagSpec) {
	for cmd, spec := range specs {
		cliCommandFlagSpecs[cmd] = spec
	}
}

func registerCLICommandAliases(aliases map[string]string) {
	for alias, cmd := range aliases {
		cliCommandAliases[alias] = cmd
		if spec, ok := cliCommandFlagSpecs[cmd]; ok {
			cliCommandFlagSpecs[alias] = spec
		}
	}
}

func cliCanonicalCommand(cmd string) string {
	if canonical, ok := cliCommandAliases[cmd]; ok {
		return canonical
	}
	return cmd
}

// Framework commands present in every edition. Server-launch commands that
// systemd and operators run (host, router, migrate-media, upgrade-check) are
// not listed: they keep their own parsing.
func init() {
	registerCLIFlagSpecs(map[string]cliFlagSpec{
		"version": cliFlags("--json"),
		"docs":    cliFlags("--full", "--reference", "--search="),
		"new":     cliFlags(),
		"serve":   cliFlags("--port=", "--mcp-local", "--mcp-writes"),
		"test":    cliFlags("--app", "--framework", "--json"),
	})
	registerCLICommandAliases(map[string]string{"--version": "version", "-v": "version", "-V": "version"})
}

// cliFlagTokenRe matches what the preflight treats as a flag: --name,
// --name=value, or a single dash followed by a letter (-n, -y, and the
// mistyped -body). Anything else (a path, "-", a negative number, a quoted
// SQL comment like "-- note") is a positional argument.
var cliFlagTokenRe = regexp.MustCompile(`(?s)^(--[A-Za-z][A-Za-z0-9_-]*(=.*)?|-[A-Za-z][A-Za-z0-9-]*)$`)

func cliFlagToken(arg string) bool {
	return cliFlagTokenRe.MatchString(arg)
}

// cliArgsRequestHelp reports a --help or -h before any `--`.
func cliArgsRequestHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}

// check validates args (the arguments after the command name) and returns
// them with every declared `--flag=value` split into `--flag value`. Values
// that start with "-" keep the `=` form so a parser that refuses a value
// looking like a flag still receives it intact.
func (s cliFlagSpec) check(args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	selected := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			out = append(out, args[i:]...)
			break
		}
		if !cliFlagToken(a) {
			out = append(out, a)
			continue
		}
		name, value, hasValue := strings.Cut(a, "=")
		switch {
		case s.valueFlags[name]:
			if v, given := cliFlagValue(args, i, value, hasValue); given {
				if err := cliSelectorConflict(selected, name, v); err != nil {
					return nil, err
				}
			}
			switch {
			case hasValue && value == "":
				return nil, fmt.Errorf("%s needs a value", name)
			case hasValue && strings.HasPrefix(value, "-"):
				out = append(out, a)
			case hasValue:
				out = append(out, name, value)
			case i+1 >= len(args):
				return nil, fmt.Errorf("%s needs a value", name)
			default:
				out = append(out, name, args[i+1])
				i++
			}
		case s.boolFlags[name]:
			if hasValue {
				return nil, fmt.Errorf("%s does not take a value", name)
			}
			out = append(out, a)
		default:
			msg := "unknown flag " + name
			if hint := s.suggest(name); hint != "" {
				msg += " (did you mean " + hint + "?)"
			}
			return nil, fmt.Errorf("%s", msg)
		}
	}
	return out, nil
}

// cliFlagValueRefusal, when set, refuses the value given to one of cmd's
// declared value flags. The hosted CLI sets it for --env (cli_flag_specs.go).
var cliFlagValueRefusal func(cmd, flag, value string) error

// eachFlagValue calls visit with every declared value flag in args and its
// value, in order, up to a `--`, and returns the first error. args have
// passed check, so each such flag has a value.
func (s cliFlagSpec) eachFlagValue(args []string, visit func(flag, value string) error) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return nil
		}
		if !cliFlagToken(a) {
			continue
		}
		name, value, hasValue := strings.Cut(a, "=")
		if !s.valueFlags[name] {
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil
			}
			i++
			value = args[i]
		}
		if err := visit(name, value); err != nil {
			return err
		}
	}
	return nil
}

// positionals returns the arguments that are not flags, in order: the spec
// tells a value flag's argument from a positional, so `<app> --env prod <x>`,
// `--env=prod <app> <x>` and `<app> <x> --env prod` all give [<app>, <x>].
// Everything after `--` is positional. Handlers that index the argument list
// instead read a flag written before a positional as that positional.
func (s cliFlagSpec) positionals(args []string) []string {
	lead, _ := s.splitPositionals(args, len(args))
	return lead
}

// splitPositionals takes the first n positional arguments out of args and
// returns them with the remaining arguments (flags with their values, and
// any further positionals) in their original order. A command with a
// sub-command uses it to read `<app> <sub-command>` wherever the flags are
// written and hand the rest to that sub-command's parser.
func (s cliFlagSpec) splitPositionals(args []string, n int) (lead, rest []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			tail := args[i+1:]
			for len(lead) < n && len(tail) > 0 {
				lead, tail = append(lead, tail[0]), tail[1:]
			}
			if len(tail) > 0 {
				rest = append(append(rest, "--"), tail...)
			}
			return lead, rest
		case !cliFlagToken(a):
			if len(lead) < n {
				lead = append(lead, a)
			} else {
				rest = append(rest, a)
			}
		default:
			rest = append(rest, a)
			if name, _, hasValue := strings.Cut(a, "="); s.valueFlags[name] && !hasValue && i+1 < len(args) {
				i++
				rest = append(rest, args[i]) // the flag's value
			}
		}
	}
	return lead, rest
}

// cliSelectorFlags choose which app, directory or environment a command acts
// on. Parsers disagreed on a repeated one (push used the last --env while its
// prod warning read the first), so two different values are refused.
var cliSelectorFlags = map[string]bool{"--app": true, "--app-dir": true, "--env": true, "--dir": true}

func cliFlagValue(args []string, i int, value string, hasValue bool) (string, bool) {
	if hasValue {
		return value, true
	}
	if i+1 < len(args) {
		return args[i+1], true
	}
	return "", false
}

func cliSelectorConflict(selected map[string]string, name, value string) error {
	if !cliSelectorFlags[name] {
		return nil
	}
	canon := strings.TrimSpace(value)
	if name == "--app" || name == "--env" { // names are case-insensitive; directories are not
		canon = strings.ToLower(canon)
	}
	if name == "--env" && canon == "production" {
		canon = "prod"
	}
	if prev, ok := selected[name]; ok && prev != canon {
		return fmt.Errorf("%s given twice with different values (%s and %s); pass it once", name, prev, canon)
	}
	selected[name] = canon
	return nil
}

// cliFlagSynonyms are flags other tools spell differently, mapped to the
// Benmore spelling to suggest when the command accepts it.
var cliFlagSynonyms = map[string][]string{
	"--data":        {"--body"},
	"-d":            {"--body"},
	"--data-raw":    {"--body"},
	"--json-body":   {"--body"},
	"--payload":     {"--body"},
	"--user":        {"--as"},
	"--as-user":     {"--as"},
	"--email":       {"--as"},
	"--environment": {"--env"},
	"-e":            {"--env"},
	"--yes":         {"--confirm"},
	"-y":            {"--yes", "--confirm"},
	"--dryrun":      {"--dry-run"},
	"--dry":         {"--dry-run"},
	"--file":        {"--from-file"},
	"--output":      {"--out"},
	"-o":            {"--out"},
	"--app-name":    {"--app"},
	"--number":      {"--lines"},
	"--tail":        {"--lines"},
}

// suggest names the declared flag the caller most likely meant, or "".
func (s cliFlagSpec) suggest(name string) string {
	for _, alt := range cliFlagSynonyms[name] {
		if s.accepts(alt) {
			return alt
		}
	}
	bare := strings.TrimLeft(name, "-")
	if s.accepts("--" + bare) {
		return "--" + bare // -body for --body
	}
	var flags []string
	for f := range s.valueFlags {
		flags = append(flags, f)
	}
	for f := range s.boolFlags {
		flags = append(flags, f)
	}
	sort.Strings(flags)
	best, bestDist, ties := "", 1<<30, 0
	for _, f := range flags {
		fb := strings.TrimLeft(f, "-")
		d := cliFlagDistance(bare, fb)
		if d > 1 && len(bare) >= 3 && len(fb) >= 2 && (strings.HasPrefix(fb, bare) || strings.HasPrefix(bare, fb)) {
			d = 1 // --with for --with-data
		}
		switch {
		case d < bestDist:
			best, bestDist, ties = f, d, 1
		case d == bestDist:
			ties++
		}
	}
	limit := 2
	if len(bare) <= 4 {
		limit = 1
	}
	if best == "" || bestDist > limit || ties > 1 {
		return ""
	}
	return best
}

// cliFlagDistance is the edit distance between two flag names. (helpers.go's
// levenshtein is absent from the cli-tagged build.)
func cliFlagDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			best := prev[j] + 1
			if cur[j-1]+1 < best {
				best = cur[j-1] + 1
			}
			sub := prev[j-1]
			if a[i-1] != b[j-1] {
				sub++
			}
			if sub < best {
				best = sub
			}
			cur[j] = best
		}
		prev = cur
	}
	return prev[len(b)]
}

// printCommandUsage writes cmd's lines from the usage text, or the whole
// command list when the usage text does not name it.
func printCommandUsage(w io.Writer, cmd string) {
	if usage := commandUsage(cliCanonicalCommand(cmd)); usage != "" {
		fmt.Fprint(w, usage)
		return
	}
	fmt.Fprint(w, usageText())
}

// cliPreflight runs the shared --help and flag checks for cmd. It returns
// the arguments to run the command with, and stop=true with the exit status
// when the command must not run (help printed, or a flag refused).
func cliPreflight(cmd string, args []string, stdout, stderr io.Writer) (out []string, code int, stop bool) {
	if cliArgsRequestHelp(args) {
		if commandsWithOwnHelp[cmd] {
			return args, 0, false
		}
		printCommandUsage(stdout, cmd)
		return nil, 0, true
	}
	spec, ok := cliCommandFlagSpecs[cmd]
	if !ok {
		return args, 0, false
	}
	out, err := spec.check(args)
	if err == nil && cliFlagValueRefusal != nil {
		err = spec.eachFlagValue(args, func(flag, value string) error { return cliFlagValueRefusal(cmd, flag, value) })
	}
	if err != nil {
		fmt.Fprintf(stderr, "benmore %s: %s\n", cmd, err)
		if names := spec.names(); len(names) > 0 {
			fmt.Fprintf(stderr, "Flags for benmore %s: %s\n", cliCanonicalCommand(cmd), strings.Join(names, ", "))
		} else {
			fmt.Fprintf(stderr, "benmore %s takes no flags.\n", cliCanonicalCommand(cmd))
		}
		if usage := commandUsage(cliCanonicalCommand(cmd)); usage != "" {
			fmt.Fprint(stderr, usageForError(usage))
		}
		return nil, spec.exitCode(), true
	}
	return out, 0, false
}

// usageForError formats a command's usage-text lines as "Usage: benmore ...",
// with further synopsis lines aligned under the first.
func usageForError(usage string) string {
	var b strings.Builder
	first := true
	for _, line := range strings.Split(strings.TrimRight(usage, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "benmore ") && first:
			b.WriteString("Usage: " + trimmed + "\n")
			first = false
		case strings.HasPrefix(trimmed, "benmore "):
			b.WriteString("       " + trimmed + "\n")
		default:
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}
