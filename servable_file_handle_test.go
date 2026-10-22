//go:build !cli

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Response headers are set after the serving helpers validate the file and
// before they send its bytes. Replacing a fixture at this boundary makes the
// path-reopen regression deterministic, without a racing goroutine.
type swapOnHeaderWriter struct {
	*httptest.ResponseRecorder
	swap func()
}

func TestFileServingPreservesIndexRedirect(t *testing.T) {
	withPlatformMedia(t, nil)
	for _, kind := range []string{"static", "upload", "flow"} {
		t.Run(kind, func(t *testing.T) {
			app := &App{Dir: t.TempDir()}
			root := filepath.Join(app.Dir, "uploads")
			if kind == "static" {
				root = filepath.Join(app.Dir, "static")
			}
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			servePinnedFixture(t, kind, w, httptest.NewRequest(http.MethodGet, "/index.html?q=1", nil), app, "index.html")
			if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "./?q=1" {
				t.Fatalf("index redirect changed: status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
		})
	}
}

func TestFileServingRetainsHTTPAndAliasContracts(t *testing.T) {
	withPlatformMedia(t, nil)
	for _, kind := range []string{"static", "upload", "flow"} {
		for _, mounted := range []bool{false, true} {
			name := kind + "/directory-root"
			if mounted {
				name = kind + "/symlinked-root"
			}
			t.Run(name, func(t *testing.T) {
				app := &App{Dir: t.TempDir()}
				root := filepath.Join(app.Dir, "uploads")
				if kind == "static" {
					root = filepath.Join(app.Dir, "static")
				}
				realRoot := root
				if mounted {
					realRoot = t.TempDir()
					if err := os.Symlink(realRoot, root); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.MkdirAll(filepath.Join(realRoot, "nested"), 0o755); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(realRoot, "nested", "document.txt")
				if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join("nested", "document.txt"), filepath.Join(realRoot, "alias.txt")); err != nil {
					t.Fatal(err)
				}
				for _, request := range []struct {
					method, header, value, body string
					status                      int
				}{
					{http.MethodGet, "Range", "bytes=2-5", "2345", http.StatusPartialContent},
					{http.MethodHead, "", "", "", http.StatusOK},
					{http.MethodGet, "If-Modified-Since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat), "", http.StatusNotModified},
				} {
					r := httptest.NewRequest(request.method, "/alias.txt", nil)
					if request.header != "" {
						r.Header.Set(request.header, request.value)
					}
					w := httptest.NewRecorder()
					servePinnedFixture(t, kind, w, r, app, "alias.txt")
					if w.Code != request.status || w.Body.String() != request.body {
						t.Fatalf("%s %s: status=%d body=%q", request.method, request.header, w.Code, w.Body.String())
					}
					if request.header == "Range" && w.Header().Get("Content-Range") != "bytes 2-5/10" {
						t.Fatalf("bad range response: %v", w.Header())
					}
					if request.method == http.MethodHead && w.Header().Get("Content-Length") != "10" {
						t.Fatalf("bad HEAD content length: %v", w.Header())
					}
				}
			})
		}
	}
}

func TestOpenServableFilePinsCanonicalNamespace(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "nested", "private")
	if err := os.MkdirAll(private, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "document.txt")
	if err := os.WriteFile(path, []byte("original private fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "public.txt")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	file, ok := openServableFile(root, alias)
	if !ok {
		t.Fatal("in-root alias could not be opened")
	}
	defer file.Close()
	if filepath.ToSlash(file.relative) != "nested/private/document.txt" {
		t.Fatalf("lost private namespace: %q", file.relative)
	}
	if err := os.Rename(private, private+".original"); err != nil {
		t.Fatal(err)
	}
	replacement := t.TempDir()
	if err := os.WriteFile(filepath.Join(replacement, "document.txt"), []byte("replacement fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, private); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	if err != nil || string(data) != "original private fixture" {
		t.Fatalf("pinned read changed: data=%q err=%v", data, err)
	}
}

func (w *swapOnHeaderWriter) Header() http.Header {
	if swap := w.swap; swap != nil {
		w.swap = nil
		swap()
	}
	return w.ResponseRecorder.Header()
}

func servePinnedFixture(t *testing.T, kind string, w http.ResponseWriter, r *http.Request, app *App, relative string) {
	t.Helper()
	switch kind {
	case "static":
		serveStaticAsset(w, r, app, false, relative)
	case "upload":
		serveUploadAsset(w, r, app, false, relative)
	case "flow":
		ctx := &FlowContext{App: app, Writer: w, Request: r, Data: map[string]any{}, Params: map[string]string{}}
		if err := execStepServeFile(ctx, &FlowStep{Type: "serve_file", ServeFile: &FlowServeFile{Path: "uploads/" + relative}}); err != nil {
			t.Fatal(err)
		}
		if !ctx.Stopped {
			t.Fatal("serve_file did not terminate the flow")
		}
	default:
		t.Fatalf("unknown serving kind %q", kind)
	}
}

func TestFileServingPinsValidatedFile(t *testing.T) {
	withPlatformMedia(t, nil)
	for _, kind := range []string{"static", "upload", "flow"} {
		for _, replacement := range []string{"file", "parent"} {
			for _, destination := range []string{"outside", "private"} {
				t.Run(kind+"/"+replacement+"/"+destination, func(t *testing.T) {
					base := t.TempDir()
					app := &App{Dir: filepath.Join(base, "app")}
					root := filepath.Join(app.Dir, "uploads")
					if kind == "static" {
						root = filepath.Join(app.Dir, "static")
					}
					parent := filepath.Join(root, "public")
					targetDir := filepath.Join(base, "outside")
					if destination == "private" {
						targetDir = filepath.Join(root, "private")
					}
					for _, dir := range []string{parent, targetDir} {
						if err := os.MkdirAll(dir, 0o755); err != nil {
							t.Fatal(err)
						}
					}
					publicFile := filepath.Join(parent, "document.txt")
					otherFile := filepath.Join(targetDir, "document.txt")
					for path, body := range map[string]string{publicFile: "original public fixture", otherFile: "replacement private fixture"} {
						if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					w := &swapOnHeaderWriter{ResponseRecorder: httptest.NewRecorder()}
					w.swap = func() {
						from, to := publicFile, otherFile
						if replacement == "parent" {
							from, to = parent, targetDir
						}
						if err := os.Rename(from, from+".original"); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(to, from); err != nil {
							t.Fatal(err)
						}
					}
					servePinnedFixture(t, kind, w, httptest.NewRequest(http.MethodGet, "/public/document.txt", nil), app, "public/document.txt")
					if w.swap != nil {
						t.Fatal("fixture replacement did not run")
					}
					if w.Code != http.StatusOK || w.Body.String() != "original public fixture" {
						t.Fatalf("served different bytes after validation: status=%d body=%q", w.Code, w.Body.String())
					}
				})
			}
		}
	}
}

func TestUploadServingSniffsPinnedFile(t *testing.T) {
	withPlatformMedia(t, nil)
	for _, kind := range []string{"upload", "flow"} {
		t.Run(kind, func(t *testing.T) {
			app := &App{Dir: t.TempDir()}
			root := filepath.Join(app.Dir, "uploads")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "document.png")
			const original = "<!DOCTYPE html><html><body>synthetic fixture</body></html>"
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			w := &swapOnHeaderWriter{ResponseRecorder: httptest.NewRecorder()}
			w.swap = func() {
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("harmless replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			servePinnedFixture(t, kind, w, httptest.NewRequest(http.MethodGet, "/document.png", nil), app, "document.png")
			if w.Code != http.StatusOK || w.Body.String() != original {
				t.Fatalf("did not serve pinned fixture: status=%d body=%q", w.Code, w.Body.String())
			}
			if got := w.ResponseRecorder.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "attachment;") {
				t.Fatalf("active pinned bytes lost attachment disposition: %q", got)
			}
		})
	}
}
