//go:build !cli

package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// chromeKeychainFreeArgs keep a framework-started Chrome away from the OS
// password store. Every launch runs with a private, empty HOME or profile, so
// on macOS Chrome finds no login keychain for its "Chrome Safe Storage" key
// and SecurityAgent offers "Reset To Defaults" - which replaces the user's
// real login keychain with an empty one. Seen on a developer Mac on
// 2026-10-22 from a local test run. Every exec of Chrome must carry these.
var chromeKeychainFreeArgs = []string{"--password-store=basic", "--use-mock-keychain"}

// chromeKeepsHome reports that a framework-started Chrome keeps the user's
// HOME. On macOS a HOME without Library/Keychains made Chrome ask
// SecurityAgent for a keychain to hold "Chrome Safe Storage" even with
// --use-mock-keychain (a Puppeteer launch with the same flag and the real
// HOME did not prompt), and the dialog's default button resets the user's
// login keychain. The private profile (--user-data-dir) and XDG dirs still
// keep Chrome's state out of the app; hosted renders run on Linux, where
// HOME stays private.
func chromeKeepsHome() bool { return runtime.GOOS == "darwin" }

// browserChromeEnv is a browser-tool Chrome's environment override: HOME and
// the XDG dirs in the private profile dir, HOME excepted on macOS
// (chromeKeepsHome).
func browserChromeEnv(tmpDir string) []string {
	env := []string{"XDG_CONFIG_HOME=" + tmpDir, "XDG_CACHE_HOME=" + tmpDir}
	if !chromeKeepsHome() {
		env = append([]string{"HOME=" + tmpDir}, env...)
	}
	return env
}

// chromeBundleVersion reads "Google Chrome 155.0.8059.85" - what
// `--version` prints - from the app bundle's Info.plist when chromePath is a
// macOS bundle executable, so asking the version never starts Chrome there.
func chromeBundleVersion(chromePath string) (string, bool) {
	if runtime.GOOS != "darwin" {
		return "", false
	}
	macOS := filepath.Dir(chromePath)
	contents := filepath.Dir(macOS)
	if filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(filepath.Dir(contents), ".app") {
		return "", false
	}
	data, err := os.ReadFile(filepath.Join(contents, "Info.plist"))
	if err != nil || len(data) > 1<<20 {
		return "", false
	}
	values := plistStrings(data, "CFBundleDisplayName", "CFBundleName", "CFBundleShortVersionString")
	name := values["CFBundleDisplayName"]
	if name == "" {
		name = values["CFBundleName"]
	}
	version := values["CFBundleShortVersionString"]
	if name == "" || version == "" || len(name)+len(version) > 200 {
		return "", false
	}
	return name + " " + version, true
}

// plistStrings returns the top-level <key>/<string> pairs of an XML plist
// whose keys are in want.
func plistStrings(data []byte, want ...string) map[string]string {
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w] = true
	}
	out := map[string]string{}
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	depth, key := 0, ""
	for {
		tok, err := decoder.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			// <plist><dict><key>…</key><string>…</string>: depth 3.
			if depth != 3 {
				continue
			}
			var text string
			if err := decoder.DecodeElement(&text, &t); err != nil {
				return out
			}
			depth--
			switch t.Name.Local {
			case "key":
				key = text
			case "string":
				if wanted[key] {
					out[key] = strings.TrimSpace(text)
				}
				key = ""
			default:
				key = ""
			}
		case xml.EndElement:
			depth--
		}
	}
}
