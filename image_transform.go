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
// requested format, writes to uploads/_transforms/<hash>.<fmt>, and
// streams the bytes back. Subsequent requests hit the cached file
// directly with a 1-year immutable Cache-Control.
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
	"path/filepath"
	"strconv"
	"strings"

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

// RegisterImageTransformRoute mounts /api/_images/transform. No auth
// gate - transforms are public by design (the source URL is itself
// the access control surface; if the user can fetch the original,
// they can fetch a variant). Apps with private images should serve
// them via signed URLs (signed_urls.go) and gate the transform
// endpoint accordingly via flows.yaml - out of scope here.
func RegisterImageTransformRoute(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /api/_images/transform", func(w http.ResponseWriter, r *http.Request) {
		src := r.URL.Query().Get("src")
		if src == "" || !strings.HasPrefix(src, "/uploads/") {
			httpError(w, "missing or invalid src (must be /uploads/...)", http.StatusBadRequest)
			return
		}
		// Width is the only dimension param - height auto-scales so
		// transforms never distort. Cap at 2000 to keep memory bounded.
		w_ := parseDim(r.URL.Query().Get("w"), 0, 2000)
		h_ := parseDim(r.URL.Query().Get("h"), 0, 2000)
		fmt_ := strings.ToLower(r.URL.Query().Get("fmt"))
		quality := parseDim(r.URL.Query().Get("q"), 0, 100)
		if quality == 0 {
			quality = 82
		}

		// Build a deterministic cache key from src + transform params so
		// identical requests dedupe to one cached file.
		cacheKey := imageCacheKey(src, w_, h_, fmt_, quality)
		ext := fmt_
		if ext == "" {
			ext = strings.TrimPrefix(filepath.Ext(src), ".")
			if ext == "" {
				ext = "jpg"
			}
		}
		cachePath := filepath.Join(app.Dir, "uploads", "_transforms", cacheKey+"."+ext)

		// Cache hit - stream the bytes.
		if data, err := os.ReadFile(cachePath); err == nil {
			w.Header().Set("Content-Type", contentTypeForExt(ext))
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			w.Write(data)
			return
		}

		// Auth gate consistent with the static /uploads/ handler in
		// server.go: public media is open (the source URL is itself the
		// access-control surface), but private-tier sources
		// (uploads/private/...) must carry a valid signed URL. Without
		// this, the transform endpoint would be an unauthenticated read
		// primitive for files that are otherwise gated behind signed URLs.
		if isPrivateUploadPath(src) {
			if !ValidateSignedURL(strings.TrimPrefix(src, "/uploads/"), r) {
				httpError(w, "forbidden - invalid or expired signed URL", http.StatusForbidden)
				return
			}
		}

		// Cache miss - load the source. filepath.Clean normalizes any
		// `..` segments so `src=/uploads/../app.yaml` resolves to a
		// path that fails the HasPrefix gate below. Without the Clean
		// step, a percent-encoded `..` chain could escape /uploads/.
		sourcePath := filepath.Clean(filepath.Join(app.Dir, strings.TrimPrefix(src, "/")))
		uploadsRoot := filepath.Join(app.Dir, "uploads")
		if sourcePath != uploadsRoot && !strings.HasPrefix(sourcePath, uploadsRoot+string(filepath.Separator)) {
			httpError(w, "source must live under /uploads/", http.StatusBadRequest)
			return
		}
		f, err := os.Open(sourcePath)
		if err != nil {
			httpError(w, "source not found", http.StatusNotFound)
			return
		}
		defer f.Close()

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
			int64(cfg.Width)*int64(cfg.Height) > uploadsMaxImagePixels {
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
		uploadsTransformSem <- struct{}{}
		img, _, err := image.Decode(f)
		<-uploadsTransformSem
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
		_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)
		_ = os.WriteFile(cachePath, buf.Bytes(), 0o644)

		w.Header().Set("Content-Type", contentTypeForExt(ext))
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
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
