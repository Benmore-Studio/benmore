//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

type embeddedThirdPartyManifest struct {
	UpdateProcedure []string `json:"update_procedure"`
	FirstParty      []string `json:"first_party"`
	Files           []struct {
		Path              string `json:"path"`
		Library           string `json:"library"`
		Version           string `json:"version"`
		License           string `json:"license"`
		Source            string `json:"source"`
		RegistryIntegrity string `json:"registry_integrity"`
		SHA256            string `json:"sha256"`
		Size              int    `json:"size_bytes"`
	} `json:"files"`
	CDNLoaded []struct {
		URL       string `json:"url"`
		Library   string `json:"library"`
		Version   string `json:"version"`
		Integrity string `json:"integrity"`
	} `json:"cdn_loaded"`
}

func loadEmbeddedThirdPartyManifest(t *testing.T) embeddedThirdPartyManifest {
	t.Helper()
	raw, err := os.ReadFile("embedded/THIRD_PARTY.json")
	if err != nil {
		t.Fatal(err)
	}
	var m embeddedThirdPartyManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("THIRD_PARTY.json: %v", err)
	}
	return m
}

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Every third-party file under embedded/ must be listed in THIRD_PARTY.json
// with its provenance and match the recorded sha256; every other file must be
// named as first-party. A swapped, partially refreshed or unrecorded vendored
// file fails here.
func TestEmbeddedThirdPartyManifest(t *testing.T) {
	m := loadEmbeddedThirdPartyManifest(t)
	if len(m.UpdateProcedure) == 0 {
		t.Error("THIRD_PARTY.json has no update_procedure")
	}
	firstParty := map[string]bool{}
	for _, p := range m.FirstParty {
		firstParty[p] = true
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		if listed[f.Path] {
			t.Errorf("%s is listed twice", f.Path)
		}
		listed[f.Path] = true
		if firstParty[f.Path] {
			t.Errorf("%s is listed as both third-party and first-party", f.Path)
		}
		if f.Library == "" || f.Version == "" || f.License == "" || f.Source == "" || !sha256HexRe.MatchString(f.SHA256) {
			t.Errorf("%s: library, version, license, source and a sha256 are required: %+v", f.Path, f)
		}
		if strings.HasPrefix(f.Source, "https://registry.npmjs.org/") && !strings.HasPrefix(f.RegistryIntegrity, "sha512-") {
			t.Errorf("%s: an npm tarball source needs its registry_integrity", f.Path)
		}
		data, err := os.ReadFile("embedded/" + f.Path)
		if err != nil {
			t.Errorf("%s is listed but not readable: %v", f.Path, err)
			continue
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			t.Errorf("%s sha256 %s != THIRD_PARTY.json %s", f.Path, got, f.SHA256)
		}
		if f.Size != len(data) {
			t.Errorf("%s is %d bytes, THIRD_PARTY.json records %d", f.Path, len(data), f.Size)
		}
	}
	err := fs.WalkDir(os.DirFS("embedded"), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if listed[p] || firstParty[p] || strings.HasSuffix(p, "_test.mjs") {
			return nil
		}
		t.Errorf("embedded/%s is neither listed in THIRD_PARTY.json files nor named in first_party", p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for p := range firstParty {
		if _, err := os.Stat("embedded/" + p); err != nil {
			t.Errorf("first_party names %s, which does not exist", p)
		}
	}
}

// sdui.js loads each cdn_loaded file with exactly the recorded URL and
// integrity, and the page CSP allows exactly those Leaflet files.
func TestSDUILeafletURLsMatchCSP(t *testing.T) {
	m := loadEmbeddedThirdPartyManifest(t)
	src, err := os.ReadFile("embedded/sdui.js")
	if err != nil {
		t.Fatal(err)
	}
	urls := map[string]bool{}
	for _, c := range m.CDNLoaded {
		urls[c.URL] = true
		if !strings.HasPrefix(c.Integrity, "sha384-") {
			t.Errorf("%s: integrity must be sha384, got %q", c.URL, c.Integrity)
		}
		if !strings.Contains(string(src), "'"+c.URL+"'") || !strings.Contains(string(src), "'"+c.Integrity+"'") {
			t.Errorf("sdui.js does not load %s with integrity %s", c.URL, c.Integrity)
		}
	}
	for _, u := range []string{sduiLeafletJS, sduiLeafletCSS} {
		if !urls[u] {
			t.Errorf("CSP constant %s is not a cdn_loaded entry", u)
		}
	}
	if len(urls) != 2 {
		t.Errorf("cdn_loaded lists %d files; the CSP allows the two Leaflet files", len(urls))
	}
	if !strings.HasPrefix(sduiLeafletImages, strings.TrimSuffix(sduiLeafletCSS, "leaflet.css")) {
		t.Errorf("Leaflet image path %s is not beside %s", sduiLeafletImages, sduiLeafletCSS)
	}
	for _, s := range []string{"sc.integrity = LEAFLET_JS_SRI", "css.integrity = LEAFLET_CSS_SRI", "sc.crossOrigin = 'anonymous'", "css.crossOrigin = 'anonymous'"} {
		if !strings.Contains(string(src), s) {
			t.Errorf("sdui.js loadLeaflet lacks %q", s)
		}
	}
}
