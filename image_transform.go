//go:build !cli

package main

// On-the-fly image transforms. Apps that uploaded an original via
// /api/_files (or any /uploads/* path) can request a resized /
// reformatted variant via:
//
//   GET /api/_images/transform?src=/uploads/_files/abc.jpg&w=400&fmt=webp
//
// First request: server reads source, resizes via x/image/draw to
// the requested width (height preserves aspect), encodes to the
// requested format and returns the bytes. Public derivatives are cached under
// .benmore/image-transforms after source authorization. Private derivatives
// are never stored and return Cache-Control: private, no-store.
//
// Supported formats: jpeg, png, gif (decode); jpeg, png (encode).
// webp encoding requires CGO so we transparently fall back to jpeg
// when fmt=webp is requested but the binary doesn't include a webp
// encoder - apps relying on webp should put Cloudflare's image
// transformations in front, which IS exactly the framework's
// existing default for prod deploys.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/image/draw"
)

// uploadsMaxImagePixels caps the decoded dimensions of a transform source.
// image.Decode allocates ~W*H*4 bytes for an RGBA buffer, so a tiny
// compressed file declaring huge dimensions (a "decompression bomb") can
// OOM the process. We reject anything above ~40 megapixels (160MB RGBA)
// using DecodeConfig - which reads only the header - BEFORE the full
// Decode. Invariant: we never allocate a decode buffer for an image whose
// declared pixel count we have not bounded.
const uploadsMaxImagePixels = 40 * 1000 * 1000 // ~40 MP

// uploadsTransformSem bounds simultaneous image decodes. Each decode holds
// a multi-hundred-MB buffer; without a ceiling a burst of concurrent
// transform requests multiplies that and exhausts memory. Sized small on
// purpose - transforms are cached after the first hit, so steady-state
// concurrency is low.
var uploadsTransformSem = make(chan struct{}, 4)

const imageTransformCacheBytes = 64 << 20
const imageTransformCacheEntries = 256

var imageTransformCacheMu sync.Mutex

// Transform parameters are visitor-controlled. Bound the cache independently
// of upload quotas so public requests cannot fill an app's runtime directory.
func cacheImageTransform(root *os.Root, name string, data []byte) {
	if len(data) > imageTransformCacheBytes {
		return
	}
	imageTransformCacheMu.Lock()
	defer imageTransformCacheMu.Unlock()
	if err := root.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return
	}
	dir, err := root.Open(filepath.Dir(name))
	if err != nil {
		return
	}
	entries, readErr := dir.Readdir(imageTransformCacheEntries + 1)
	dir.Close()
	if readErr != nil && readErr != io.EOF {
		return
	}
	if len(entries) >= imageTransformCacheEntries {
		return
	}
	total := int64(len(data))
	for _, entry := range entries {
		total += entry.Size()
		if total > imageTransformCacheBytes {
			return
		}
	}
	tmp := name + "." + generateToken(12)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	defer root.Remove(tmp)
	if writeErr == nil && closeErr == nil {
		_ = root.Rename(tmp, name)
	}
}

// RegisterImageTransformRoute applies source authorization before every cache
// lookup. Private derivatives are never persisted or shared through HTTP caches.
func RegisterImageTransformRoute(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /api/_images/transform", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		src := r.URL.Query().Get("src")
		if !strings.HasPrefix(src, "/uploads/") || path.Clean(src) != src || strings.ContainsAny(src, "\\\x00") {
			httpError(w, "missing or invalid src (must be /uploads/...)", http.StatusBadRequest)
			return
		}
		// Width is the only dimension param - height auto-scales so
		// transforms never distort. Cap at 2000 to keep memory bounded.
		w_ := parseDim(r.URL.Query().Get("w"), 0, 2000)
		h_ := parseDim(r.URL.Query().Get("h"), 0, 2000)
		fmt_ := strings.ToLower(r.URL.Query().Get("fmt"))
		ext := fmt_
		if ext == "" {
			ext = strings.ToLower(strings.TrimPrefix(path.Ext(src), "."))
		}
		switch ext {
		case "", "jpg", "jpeg", "webp":
			ext = "jpg" // webp requests use the JPEG fallback, including cache hits
		case "png", "gif":
		default:
			httpError(w, "unsupported image format", http.StatusBadRequest)
			return
		}
		quality := parseDim(r.URL.Query().Get("q"), 0, 100)
		if quality == 0 {
			quality = 82
		}

		private := isPrivateUploadPath(src)
		if private {
			if !ValidateSignedURL(strings.TrimPrefix(src, "/uploads/"), r) {
				httpError(w, "forbidden - invalid or expired signed URL", http.StatusForbidden)
				return
			}
		}

		uploadsRoot := filepath.Join(app.Dir, "uploads")
		sourcePath, ok := resolveServableFile(uploadsRoot, filepath.Join(app.Dir, strings.TrimPrefix(src, "/")))
		if !ok || strings.HasPrefix(src, "/uploads/_transforms/") {
			httpError(w, "source not found", http.StatusNotFound)
			return
		}
		realRoot, err := filepath.EvalSymlinks(uploadsRoot)
		if err != nil {
			httpError(w, "source not found", http.StatusNotFound)
			return
		}
		realRoot, err = filepath.Abs(realRoot)
		if err != nil {
			httpError(w, "source not found", http.StatusNotFound)
			return
		}
		rel, err := filepath.Rel(realRoot, sourcePath)
		if err != nil || strings.HasPrefix(filepath.ToSlash(rel), "_transforms/") {
			httpError(w, "source not found", http.StatusNotFound)
			return
		}
		if isPrivateUploadPath("uploads/" + filepath.ToSlash(rel)) {
			private = true
			if !ValidateSignedURL(strings.TrimPrefix(src, "/uploads/"), r) {
				httpError(w, "forbidden - invalid or expired signed URL", http.StatusForbidden)
				return
			}
		}
		root, err := os.OpenRoot(realRoot)
		if err != nil {
			httpError(w, "source not found", http.StatusNotFound)
			return
		}
		defer root.Close()
		f, err := root.Open(rel)
		if err != nil {
			httpError(w, "source not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			httpError(w, "source not found", http.StatusNotFound)
			return
		}

		// Use a new non-public cache namespace: old uploads/_transforms files
		// may contain private derivatives produced by older versions.
		cacheKey := imageCacheKey(src+"|"+strconv.FormatInt(st.ModTime().UnixNano(), 10)+"|"+strconv.FormatInt(st.Size(), 10), w_, h_, ext, quality)
		cachePath := filepath.Join(".benmore", "image-transforms", cacheKey+"."+ext)
		appRoot, rootErr := os.OpenRoot(app.Dir)
		if rootErr == nil {
			defer appRoot.Close()
		}
		if !private && rootErr == nil {
			if data, err := appRoot.ReadFile(cachePath); err == nil {
				w.Header().Set("Content-Type", contentTypeForExt(ext))
				w.Header().Set("Cache-Control", "public, max-age=86400")
				w.Write(data)
				return
			}
		}
		// Hold the slot through resizing and encoding too: those stages still
		// retain the decoded image. Cancellation must release a waiting request.
		select {
		case uploadsTransformSem <- struct{}{}:
			defer func() { <-uploadsTransformSem }()
		case <-r.Context().Done():
			return
		}

		// Decompression-bomb guard: read ONLY the header via DecodeConfig
		// and reject before allocating any decode buffer when the declared
		// pixel count exceeds the cap. A 10KB file can declare 50000x50000
		// dimensions; image.Decode would then try to allocate ~10GB.
		cfg, _, cfgErr := image.DecodeConfig(f)
		if cfgErr != nil {
			httpError(w, "decode failed: "+cfgErr.Error(), http.StatusUnsupportedMediaType)
			return
		}
		if cfg.Width <= 0 || cfg.Height <= 0 ||
			cfg.Width > uploadsMaxImagePixels/cfg.Height {
			httpError(w, "source image too large to transform", http.StatusUnsupportedMediaType)
			return
		}
		// Rewind: DecodeConfig consumed the header bytes.
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			httpError(w, "source not seekable", http.StatusInternalServerError)
			return
		}

		// Bound concurrent decodes - each holds a large RGBA buffer, so a
		// burst of cache-miss requests must not multiply memory unbounded.
		img, _, err := image.Decode(f)
		if err != nil {
			httpError(w, "decode failed: "+err.Error(), http.StatusUnsupportedMediaType)
			return
		}

		// Resize. Preserve aspect ratio when only one dimension given.
		if w_ > 0 || h_ > 0 {
			img = resizeFit(img, w_, h_)
		}

		// Encode to the requested format. webp falls through to jpeg
		// (no CGO encoder bundled); png stays lossless; gif preserves
		// the first frame only.
		var buf bytes.Buffer
		switch ext {
		case "png":
			err = png.Encode(&buf, img)
		case "gif":
			err = gif.Encode(&buf, img, nil)
		case "webp":
			// Fall through to jpeg.
			ext = "jpg"
			fallthrough
		default:
			err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
		}
		if err != nil {
			httpError(w, "encode failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Best-effort cache write - failure doesn't fail the response.
		if !private && rootErr == nil {
			cacheImageTransform(appRoot, cachePath, buf.Bytes())
		}

		w.Header().Set("Content-Type", contentTypeForExt(ext))
		if !private {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		io.Copy(w, &buf)
	})
}

// resizeFit scales the image to fit within the given box. Zero
// dimension = unconstrained. Uses CatmullRom (sharp + good quality)
// from x/image/draw.
func resizeFit(src image.Image, maxW, maxH int) image.Image {
	srcBounds := src.Bounds()
	srcW, srcH := srcBounds.Dx(), srcBounds.Dy()
	if maxW == 0 {
		maxW = srcW
	}
	if maxH == 0 {
		maxH = srcH
	}
	// Compute the scale factor that fits both bounds.
	scale := 1.0
	if float64(srcW) > float64(maxW) {
		scale = float64(maxW) / float64(srcW)
	}
	if float64(srcH)*scale > float64(maxH) {
		scale = float64(maxH) / float64(srcH)
	}
	if scale >= 1.0 {
		return src // already smaller than the box
	}
	newW := int(float64(srcW) * scale)
	newH := int(float64(srcH) * scale)
	newW = max(1, newW)
	newH = max(1, newH)
	dst := image.NewRGBA(image.Rect(0, 0, newW, newH))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, srcBounds, draw.Over, nil)
	return dst
}

func imageCacheKey(src string, w, h int, fmt_ string, q int) string {
	parts := src + "|" + strconv.Itoa(w) + "x" + strconv.Itoa(h) + "|" + fmt_ + "|q" + strconv.Itoa(q)
	sum := sha256.Sum256([]byte(parts))
	return hex.EncodeToString(sum[:])[:16]
}

func parseDim(s string, min, max int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < min {
		return min
	}
	if max > 0 && n > max {
		return max
	}
	return n
}

func contentTypeForExt(ext string) string {
	switch strings.ToLower(strings.TrimPrefix(ext, ".")) {
	case "png":
		return "image/png"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	default:
		return "image/jpeg"
	}
}
