//go:build !cli

package main

// serve_file downloads of media-CDN objects.
//
// `run: serve_file` answers a CDN-backed file with a redirect, so the
// response headers are the ones stored on the object: a step's
// `disposition: attachment` and `filename:` never reached the browser and a
// "Download" link opened the file inline under its storage name. CloudFront
// signed URLs can carry `response-content-disposition` to the bucket only if
// the distribution forwards that query string to the origin, which the
// framework cannot check from here, so a download is streamed through the
// app instead. The signed URL is minted for this request only (the router
// still signs it, rule 31a2) and never leaves the process.

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"
)

// serveFileCDNClient returns the client a download fetches its object with:
// the strict outbound client (dial-time address check, no environment proxy)
// that never follows a redirect. A variable so tests can reach an httptest
// TLS server, which the strict client rightly refuses (loopback).
var serveFileCDNClient = func() *http.Client {
	c := safeHTTPClientStrict(0)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

const (
	// serveFileDownloadMaxDuration bounds one streamed download. The router
	// in front of a hosted app has its own response window (about five
	// minutes), which is the practical limit there.
	serveFileDownloadMaxDuration = 30 * time.Minute
	// serveFileDownloadWriteTimeout is the deadline for each write to the
	// client. It moves forward with every chunk, so a slow but reading client
	// is never cut by the server's 30-second WriteTimeout, and one that stops
	// reading releases the request.
	serveFileDownloadWriteTimeout = 60 * time.Second
)

// streamCDNDownload streams the CDN object at cdnURL (unsigned; signed here
// when private) to the client as an attachment named filename (the object's
// own name when empty). Range requests are passed through. Errors are
// answered here; the caller stops the flow either way. The name's extension
// follows the object's (serveFileDownloadName).
func streamCDNDownload(ctx *FlowContext, cfg *PlatformMediaConfig, cdnURL string, isPrivate bool, filename string) {
	w, r := ctx.Writer, ctx.Request
	target := cdnURL
	if isPrivate {
		// The URL is used once, right now, by this process.
		signed, err := signPrivateMediaURL(ctx.App, cfg, cdnURL, serveFileSignTTL)
		if err != nil {
			serverError(w, r, ctx.App, "serve_file", err, "media signing unavailable")
			return
		}
		target = signed
	}
	// The broker's answer is trusted to be a CDN URL; check it anyway so a
	// misbehaving signer cannot point this fetch somewhere else.
	if !strings.HasPrefix(target, "https://"+cfg.CDNDomain+"/") {
		serverError(w, r, ctx.App, "serve_file", fmt.Errorf("signed media URL is not on the media CDN"), "media download unavailable")
		return
	}
	// The step's name (else the object's own) with the object's extension.
	filename = serveFileDownloadName(filename, path.Base(strings.SplitN(cdnURL, "?", 2)[0]))

	fetchCtx, cancel := context.WithTimeout(r.Context(), serveFileDownloadMaxDuration)
	defer cancel()
	method := http.MethodGet
	if r.Method == http.MethodHead {
		method = http.MethodHead
	}
	upstream, err := http.NewRequestWithContext(fetchCtx, method, target, nil)
	if err != nil {
		serverError(w, r, ctx.App, "serve_file", err, "media download unavailable")
		return
	}
	for _, h := range []string{"Range", "If-Range"} {
		if v := r.Header.Get(h); v != "" {
			upstream.Header.Set(h, v)
		}
	}
	resp, err := serveFileCDNClient().Do(upstream)
	if err != nil {
		serverError(w, r, ctx.App, "serve_file", err, "media download unavailable")
		return
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent, http.StatusRequestedRangeNotSatisfiable:
	case http.StatusForbidden, http.StatusNotFound:
		// A missing object and an unsigned private one look the same.
		http.Error(w, "Not found", http.StatusNotFound)
		return
	default:
		serverError(w, r, ctx.App, "serve_file", fmt.Errorf("media CDN answered %d", resp.StatusCode), "media download unavailable")
		return
	}

	h := w.Header()
	for _, k := range []string{"Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified"} {
		if v := resp.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "application/octet-stream")
	}
	h.Set("Content-Disposition", serveFileContentDisposition("attachment", filename))
	h.Set("X-Content-Type-Options", "nosniff")
	// The flow authorized this caller; no shared cache may keep the bytes.
	h.Set("Cache-Control", "private, no-store")
	w.WriteHeader(resp.StatusCode)
	if method == http.MethodHead {
		return
	}

	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(serveFileDownloadWriteTimeout))
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}
