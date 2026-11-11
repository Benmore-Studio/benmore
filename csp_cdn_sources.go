//go:build !cli

package main

// Page CSP: which public script CDNs an app may load from.
//
// The page CSP used to allow unpkg, jsDelivr, esm.sh and Skypack in
// script-src and connect-src for every app, so any markup injected into any
// app could load arbitrary npm code from four origins. Most apps load nothing
// from them (the framework serves its own libraries from /_internal/). An app
// now gets a CDN origin only when its own source names that host: a
// `<script src="https://cdn.jsdelivr.net/...">`, an
// `import x from 'https://esm.sh/...'` in a .tsx module, an import map, a
// string a bundle builds a URL from. The schema-driven Map component
// (embedded/sdui.js) loads Leaflet 1.9.4 from unpkg, so an app that imports
// sdui gets exactly those Leaflet files, which sdui.js pins with
// Subresource Integrity.
//
// The scan errs toward allowing: any mention of a host counts, including a
// comment, and whatever the scan cannot read or finish gives the old
// all-four-CDNs policy. It reads the app directory except what is never
// served (hidden entries, uploads, node_modules, backups, migrations, tests,
// docs, Markdown at the app root, TypeScript declaration files, databases,
// env files, and binary media). A URL that appears nowhere in the app's files
// (built from data in the database or from an env value) is not seen: such an
// app lists the origin under `csp: script_src` / `connect_src` in app.yaml,
// which is appended as before.
//
// Results are cached per app directory. A refresh runs in the background at
// most once per cdnSourceUseTTL; it re-reads only files whose size or mtime
// changed, and a hot reload refreshes synchronously, so a pushed change is in
// the policy the moment the reloaded handler serves.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// pageScriptCDNHosts are the public npm CDNs the page CSP allows (script-src
// and connect-src) when an app's source names them.
var pageScriptCDNHosts = []string{"unpkg.com", "cdn.jsdelivr.net", "esm.sh", "cdn.skypack.dev"}

// The Leaflet files embedded/sdui.js's Map component loads. They must equal
// the URLs in loadLeaflet (TestSDUILeafletURLsMatchCSP pins that).
const (
	sduiLeafletJS     = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
	sduiLeafletCSS    = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
	sduiLeafletImages = "https://unpkg.com/leaflet@1.9.4/dist/images/"
)

// cdnSourceUse is what an app's source needs from the CDNs.
type cdnSourceUse struct {
	hosts   map[string]bool // members of pageScriptCDNHosts the source names
	leaflet bool            // the source imports sdui (Map loads Leaflet)
}

// cdnSourceUseFallback is the policy for an app whose source could not be
// scanned (or has not been yet): every CDN, as before the narrowing.
func cdnSourceUseFallback() cdnSourceUse {
	u := cdnSourceUse{hosts: map[string]bool{}, leaflet: true}
	for _, h := range pageScriptCDNHosts {
		u.hosts[h] = true
	}
	return u
}

// origins lists the allowed CDN origins in pageScriptCDNHosts order.
func (u cdnSourceUse) origins() []string {
	var out []string
	for _, h := range pageScriptCDNHosts {
		if u.hosts[h] {
			out = append(out, "https://"+h)
		}
	}
	return out
}

// cdnSourceUseTTL bounds how often a background refresh re-walks an app's
// files to notice an edit made without a hot reload.
var cdnSourceUseTTL = time.Second

// Scan limits: an app over either one keeps the fallback policy.
const (
	cdnScanMaxFiles = 100_000
	cdnScanMaxBytes = 2 << 30
)

type cdnFileScan struct {
	size, mtime int64
	flags       uint8
}

const (
	cdnFlagLeaflet uint8 = 1 << 7 // bits 0..3 are pageScriptCDNHosts indexes
)

type cdnSourceEntry struct {
	scanMu sync.Mutex // serializes scans, so an older scan never publishes last

	mu         sync.Mutex
	have       bool
	use        cdnSourceUse
	next       time.Time // earliest start of the next background refresh
	probe      string
	files      map[string]cdnFileScan
	refreshing bool
	lastErr    string
}

var cdnSourceCache = struct {
	sync.Mutex
	m map[string]*cdnSourceEntry
}{m: map[string]*cdnSourceEntry{}}

func cdnSourceEntryFor(dir string) *cdnSourceEntry {
	cdnSourceCache.Lock()
	defer cdnSourceCache.Unlock()
	e := cdnSourceCache.m[dir]
	if e == nil {
		if len(cdnSourceCache.m) >= 4096 {
			// One entry per app; the bound keeps a long-lived host process
			// from accumulating removed apps.
			clear(cdnSourceCache.m)
		}
		e = &cdnSourceEntry{}
		cdnSourceCache.m[dir] = e
	}
	return e
}

// pageCDNSources returns the CDN use of the app's source for the page CSP.
// It never blocks on a scan: until the first scan finishes it returns the
// fallback, and the current result is served while a refresh runs.
func pageCDNSources(app *App) cdnSourceUse {
	if app == nil || app.Dir == "" {
		return cdnSourceUseFallback()
	}
	e := cdnSourceEntryFor(app.Dir)
	e.mu.Lock()
	use, have := e.use, e.have
	start := !e.refreshing && !time.Now().Before(e.next)
	if start {
		e.refreshing = true
	}
	e.mu.Unlock()
	if start {
		go func() {
			e.refresh(app.Dir)
			e.mu.Lock()
			e.refreshing = false
			e.mu.Unlock()
		}()
	}
	if !have {
		return cdnSourceUseFallback()
	}
	return use
}

// refreshCDNSources rescans the app's source now and returns the result
// (hot reload, tests).
func refreshCDNSources(dir string) cdnSourceUse {
	e := cdnSourceEntryFor(dir)
	e.refresh(dir)
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.use
}

// cdnScanRetry is how long a failed scan keeps the fallback before retrying.
var cdnScanRetry = time.Minute

func (e *cdnSourceEntry) refresh(dir string) {
	e.scanMu.Lock()
	defer e.scanMu.Unlock()
	e.mu.Lock()
	prevProbe, prevFiles := e.probe, e.files
	e.mu.Unlock()
	list, probe, err := listCDNScanFiles(dir)
	if err == nil && probe == prevProbe && prevFiles != nil {
		e.mu.Lock()
		e.next = time.Now().Add(cdnSourceUseTTL)
		e.mu.Unlock()
		return
	}
	if err == nil && prevFiles != nil {
		// The files changed: allow every CDN until the new content is
		// read, rather than serve a policy that may miss a new reference.
		e.mu.Lock()
		e.use = cdnSourceUseFallback()
		e.mu.Unlock()
	}
	var use cdnSourceUse
	var files map[string]cdnFileScan
	if err == nil {
		use, files, err = scanCDNFiles(dir, list, prevFiles)
	}
	retry := cdnSourceUseTTL
	errText := ""
	if err != nil {
		use, files, probe, retry, errText = cdnSourceUseFallback(), nil, "", cdnScanRetry, err.Error()
	}
	e.mu.Lock()
	if errText != "" && errText != e.lastErr {
		log.Printf("[csp] %s: source scan incomplete (%s); page CSP keeps every script CDN", dir, errText)
	}
	e.use, e.have, e.files, e.probe, e.lastErr = use, true, files, probe, errText
	e.next = time.Now().Add(retry)
	e.mu.Unlock()
}

// invalidateCDNSources makes the next page response start a fresh scan.
func invalidateCDNSources(dir string) {
	if dir == "" {
		return
	}
	cdnSourceCache.Lock()
	e := cdnSourceCache.m[dir]
	cdnSourceCache.Unlock()
	if e != nil {
		e.mu.Lock()
		e.next = time.Time{}
		e.mu.Unlock()
	}
}

type cdnScanFile struct {
	rel         string
	size, mtime int64
}

var errCDNScanTooLarge = errors.New("app source exceeds the scan limits")

// listCDNScanFiles walks the app directory (through an os.Root, never
// following links) and returns the files the scan reads plus a probe over
// their names, sizes and mtimes.
func listCDNScanFiles(dir string) ([]cdnScanFile, string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	defer root.Close()
	var list []cdnScanFile
	var total int64
	h := sha256.New()
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, walkErr error) error {
		if p == "." {
			return walkErr
		}
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if cdnScanSkipDir(p, d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || cdnScanSkipFile(p, d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		f := cdnScanFile{rel: p, size: info.Size(), mtime: info.ModTime().UnixNano()}
		list = append(list, f)
		total += f.size
		if len(list) > cdnScanMaxFiles || total > cdnScanMaxBytes {
			return errCDNScanTooLarge
		}
		h.Write([]byte(f.rel + "\x00" + strconv.FormatInt(f.size, 10) + "\x00" + strconv.FormatInt(f.mtime, 10) + "\x00"))
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return list, hex.EncodeToString(h.Sum(nil)), nil
}

// cdnScanSkipDir reports directories that are never served: hidden entries,
// user uploads, dependencies, backups, migrations, tests and docs at the app
// root, and node_modules / .git anywhere.
func cdnScanSkipDir(rel, name string) bool {
	if name == "node_modules" || name == ".git" {
		return true
	}
	if strings.Contains(rel, "/") {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "uploads", "backups", "migrations", "tests", "docs":
		return true
	}
	return false
}

// cdnScanSkipFile reports files the scan does not read: hidden and Markdown
// files at the app root (agent notes, never served), TypeScript declarations
// (no runtime code; the generated src/bm.d.ts documents sdui's Map), env and
// database files, and binary media that cannot name a script URL.
func cdnScanSkipFile(rel, name string) bool {
	lower := strings.ToLower(name)
	if !strings.Contains(rel, "/") {
		if strings.HasPrefix(name, ".") || strings.HasSuffix(lower, ".md") {
			return true
		}
	}
	if strings.HasSuffix(lower, ".d.ts") || strings.HasSuffix(lower, ".d.mts") || strings.HasSuffix(lower, ".d.cts") {
		return true
	}
	if lower == "env.yaml" || lower == "env.yml" || strings.HasPrefix(lower, "data.db") || isMetadataSidecar(name) {
		return true
	}
	switch path.Ext(lower) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".tif", ".tiff", ".heic", ".heif", ".psd",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".mp4", ".m4v", ".mov", ".webm", ".mkv", ".avi", ".mp3", ".wav", ".m4a", ".aac", ".ogg", ".oga", ".flac", ".opus",
		".pdf", ".zip", ".gz", ".tgz", ".tar", ".br", ".zst", ".7z", ".rar",
		".db", ".sqlite", ".sqlite3", ".glb", ".dmg", ".iso", ".exe":
		return true
	}
	return false
}

// scanCDNFiles reads each listed file (reusing prev for files whose size and
// mtime are unchanged) and unions what they reference.
func scanCDNFiles(dir string, list []cdnScanFile, prev map[string]cdnFileScan) (cdnSourceUse, map[string]cdnFileScan, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return cdnSourceUse{}, nil, err
	}
	defer root.Close()
	files := make(map[string]cdnFileScan, len(list))
	var union uint8
	for _, f := range list {
		if p, ok := prev[f.rel]; ok && p.size == f.size && p.mtime == f.mtime {
			files[f.rel] = p
			union |= p.flags
			continue
		}
		flags, err := scanCDNFile(root, f.rel)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // removed since the walk
			}
			return cdnSourceUse{}, nil, err
		}
		files[f.rel] = cdnFileScan{size: f.size, mtime: f.mtime, flags: flags}
		union |= flags
	}
	use := cdnSourceUse{hosts: map[string]bool{}, leaflet: union&cdnFlagLeaflet != 0}
	for i, h := range pageScriptCDNHosts {
		if union&(1<<i) != 0 {
			use.hosts[h] = true
		}
	}
	return use, files, nil
}

// sduiImportNeedles name the sdui module: the injected import-map specifier
// (quoted) or its served path.
var sduiImportNeedles = [][]byte{[]byte(`'sdui'`), []byte(`"sdui"`), []byte("`sdui`"), []byte("_internal/sdui")}

const cdnScanChunk = 256 << 10

// cdnScanOverlap must exceed the longest needle plus its boundary bytes.
const cdnScanOverlap = 64

// scanCDNFile streams one file and reports which CDN hosts it names (as a
// whole host: not preceded by a host character, not followed by a label
// character) and whether it imports sdui. Hosts compare case-insensitively.
func scanCDNFile(root *os.Root, rel string) (uint8, error) {
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil {
		return 0, err
	} else if !info.Mode().IsRegular() {
		return 0, nil // swapped for a FIFO or device: nothing a page loads
	}
	hostNeedles := make([][]byte, len(pageScriptCDNHosts))
	for i, h := range pageScriptCDNHosts {
		hostNeedles[i] = []byte(h)
	}
	want := uint8(cdnFlagLeaflet)
	for i := range pageScriptCDNHosts {
		want |= 1 << i
	}
	var flags uint8
	buf := make([]byte, cdnScanChunk+cdnScanOverlap+1)
	carry, start := 0, 0
	for {
		n, rerr := io.ReadFull(f, buf[carry:])
		data := buf[:carry+n]
		lowerASCII(data[carry:])
		eof := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if rerr != nil && !eof {
			return 0, rerr
		}
		// A match starting at or after limit is examined in the next window,
		// where its right boundary byte is available.
		limit := len(data)
		if !eof {
			limit = len(data) - cdnScanOverlap
		}
		for i, needle := range hostNeedles {
			if flags&(1<<i) == 0 && containsHost(data, start, limit, needle) {
				flags |= 1 << i
			}
		}
		if flags&cdnFlagLeaflet == 0 {
			for _, needle := range sduiImportNeedles {
				if idx := bytes.Index(data[start:], needle); idx >= 0 && start+idx < limit {
					flags |= cdnFlagLeaflet
					break
				}
			}
		}
		if eof || flags == want {
			return flags, nil
		}
		// Carry the deferred tail plus one byte of left context.
		keep := cdnScanOverlap + 1
		copy(buf, data[len(data)-keep:])
		carry, start = keep, 1
	}
}

// containsHost reports a whole-host occurrence of needle starting in
// data[start:limit].
func containsHost(data []byte, start, limit int, needle []byte) bool {
	for from := start; from < limit; {
		idx := bytes.Index(data[from:], needle)
		if idx < 0 {
			return false
		}
		at := from + idx
		if at >= limit {
			return false
		}
		end := at + len(needle)
		leftOK := at == 0 || !isHostByte(data[at-1])
		rightOK := end >= len(data) || !isLabelByte(data[end])
		if leftOK && rightOK {
			return true
		}
		from = at + 1
	}
	return false
}

func isLabelByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}

// isHostByte also counts '.' and '_': "fastly.jsdelivr.net" or
// "build-esm.sh" is not the CDN host.
func isHostByte(c byte) bool { return isLabelByte(c) || c == '.' || c == '_' }

func lowerASCII(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}
