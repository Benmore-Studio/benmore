//go:build !cli

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A source under the 40 MP pixel cap can still need far more memory to
// resample than to decode: x/image/draw's kernel scaler allocates a
// dstWidth x srcHeight buffer of [4]float64. A 1000x40000 grayscale PNG
// (40 MB decoded, a few KB on disk) scaled to 999 px wide needs ~1.3 GB, far
// above a hosted app's 768 MB memory limit, so one anonymous request could
// get the process killed. The transform must be refused before decoding.
func TestImageTransformRefusesOversizedResampleBuffer(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewGray(image.Rect(0, 0, 1000, 40000))); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(app.Dir, "uploads", "files", "tall.png")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterImageTransformRoute(mux, app)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/_images/transform?src=/uploads/files/tall.png&w=999&fmt=png", nil))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("oversized resample: status %d, want 415 (body %q)", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(app.Dir, ".benmore", "image-transforms")); err == nil {
		t.Error("refused transform left a cache entry")
	}
}

// Common photo shapes keep working: the estimate must stay under the budget
// for a 40 MP landscape photo and a 12 MP portrait phone photo scaled to the
// 2000 px maximum width, and for a 40 MP photo re-encoded at full size.
func TestImageTransformWorkingBytesAdmitsCommonPhotos(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  image.Config
		w    int
		ext  string
	}{
		{"40MP landscape jpeg", image.Config{ColorModel: color.YCbCrModel, Width: 7300, Height: 5477}, 2000, "jpg"},
		{"12MP portrait jpeg", image.Config{ColorModel: color.YCbCrModel, Width: 3024, Height: 4032}, 2000, "jpg"},
		{"24MP landscape png", image.Config{ColorModel: color.NRGBAModel, Width: 6000, Height: 4000}, 1600, "png"},
		{"40MP jpeg to png, no resize", image.Config{ColorModel: color.YCbCrModel, Width: 7300, Height: 5477}, 0, "png"},
		{"40MP jpeg to jpeg, no resize", image.Config{ColorModel: color.YCbCrModel, Width: 7300, Height: 5477}, 0, "jpg"},
	} {
		if got := imageTransformWorkingBytes(tc.cfg, tc.w, 0, tc.ext); got > imageTransformMemoryBudget {
			t.Errorf("%s: estimate %d MiB exceeds the %d MiB budget", tc.name, got>>20, imageTransformMemoryBudget>>20)
		}
	}
	tall := image.Config{ColorModel: color.GrayModel, Width: 1000, Height: 40000}
	if got := imageTransformWorkingBytes(tall, 999, 0, "png"); got <= imageTransformMemoryBudget {
		t.Errorf("1000x40000 -> 999 px: estimate %d MiB is within the budget", got>>20)
	}
	// The encoded output is buffered whole: a 40 MP 16-bit source re-encoded
	// to PNG at full size needs its decode plus up to twice its raw size.
	deep := image.Config{ColorModel: color.NRGBA64Model, Width: 7300, Height: 5477}
	if got := imageTransformWorkingBytes(deep, 0, 0, "png"); got <= imageTransformMemoryBudget {
		t.Errorf("40MP 16-bit -> png at full size: estimate %d MiB is within the budget", got>>20)
	}
}

// Transforms that fit the budget together run as before; one that does not
// fit beside a running transform waits for it instead of failing.
func TestImageTransformMemoryBudgetQueues(t *testing.T) {
	half := int64(imageTransformMemoryBudget/2 + 1)
	if !acquireImageTransformMemory(nil, half) {
		t.Fatal("first reservation refused")
	}
	got := make(chan bool, 1)
	go func() { got <- acquireImageTransformMemory(nil, half) }()
	select {
	case <-got:
		t.Fatal("second reservation did not wait for the first")
	case <-time.After(50 * time.Millisecond):
	}
	releaseImageTransformMemory(half)
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("queued reservation refused after release")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued reservation never woke")
	}
	releaseImageTransformMemory(half)
	done := make(chan struct{})
	close(done)
	if acquireImageTransformMemory(done, imageTransformMemoryBudget+1) {
		t.Fatal("over-budget reservation accepted")
	}
}
