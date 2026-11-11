//go:build !cli

package main

// Lifetimes of the signed links the runtime mints for private uploads.
//
// A signed URL is a bearer capability for one object, so it stays short and
// can never pass oauthMaxSignedURLTTL (6h; the presign broker enforces the
// same ceiling as mediaSignMaxTTL). Audio and video are the exception to
// "short by default": a <video>/<audio> element keeps using the URL it was
// redirected to for every range request while it plays, so a link that
// expires mid-playback stalls the player (a 403 from the CDN) even though the
// flow that authorized it would authorize again. Those get
// mediaPlaybackSignTTL unless the flow or caller asks for another lifetime.

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// serveFileSignTTL is the lifetime of a `run: serve_file` redirect to a
// private CDN object that is not audio or video: long enough for the browser
// to follow the redirect and download, short enough that a copied link dies.
const serveFileSignTTL = 2 * time.Minute

// mediaPlaybackSignTTL is the default lifetime of a signed link to a private
// audio or video file: a feature-length video with pauses plays to the end.
const mediaPlaybackSignTTL = 4 * time.Hour

// streamingMediaExts are the audio/video containers a media element plays
// from one URL with range requests. HLS/DASH manifests (.m3u8/.mpd) are not
// listed: their segments are separate objects a single signature does not
// cover.
var streamingMediaExts = map[string]bool{
	".mp4": true, ".m4v": true, ".mov": true, ".webm": true, ".ogv": true, ".mkv": true, ".3gp": true,
	".mp3": true, ".m4a": true, ".aac": true, ".wav": true, ".flac": true, ".ogg": true, ".oga": true, ".opus": true, ".weba": true,
}

// isStreamingMediaPath reports whether a stored upload path or CDN URL names
// an audio or video file (by extension, ignoring any query).
func isStreamingMediaPath(p string) bool {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return streamingMediaExts[strings.ToLower(path.Ext(p))]
}

// signedLinkTTL picks a signed link's lifetime: the requested one when set
// (requested > 0), else mediaPlaybackSignTTL for audio/video, else fallback;
// never more than oauthMaxSignedURLTTL.
func signedLinkTTL(p string, requested, fallback time.Duration) time.Duration {
	ttl := fallback
	if requested > 0 {
		ttl = requested
	} else if isStreamingMediaPath(p) {
		ttl = mediaPlaybackSignTTL
	}
	if ttl > oauthMaxSignedURLTTL {
		ttl = oauthMaxSignedURLTTL
	}
	return ttl
}

// parseSignedLinkLifetime reads serve_file's `with.expires_in`: whole seconds
// (a YAML number or a numeric string) or a Go duration ("90m", "2h"), between
// one second and oauthMaxSignedURLTTL. It is a literal: a request value must
// not choose how long a bearer link lives.
func parseSignedLinkLifetime(v any) (time.Duration, error) {
	const shape = "must be whole seconds or a duration such as \"2h\""
	maxSecs := int64(oauthMaxSignedURLTTL / time.Second)
	seconds := func(n int64) (time.Duration, error) {
		// Bounded before multiplying, so a huge number cannot wrap into range.
		if n > maxSecs {
			return 0, fmt.Errorf("must be at most %s", oauthMaxSignedURLTTL)
		}
		return time.Duration(n) * time.Second, nil
	}
	var d time.Duration
	var err error
	switch n := v.(type) {
	case int:
		d, err = seconds(int64(n))
	case int64:
		d, err = seconds(n)
	case uint64:
		if n > uint64(maxSecs) {
			return 0, fmt.Errorf("must be at most %s", oauthMaxSignedURLTTL)
		}
		d, err = seconds(int64(n))
	case float64:
		if n != float64(int64(n)) {
			return 0, fmt.Errorf(shape)
		}
		if n > float64(maxSecs) {
			return 0, fmt.Errorf("must be at most %s", oauthMaxSignedURLTTL)
		}
		d, err = seconds(int64(n))
	case string:
		s := strings.TrimSpace(n)
		if strings.Contains(s, "{{") || strings.Contains(s, "${") {
			return 0, fmt.Errorf("must be a literal, not a template: a request value may not choose how long a signed link lives")
		}
		if secs, perr := strconv.ParseInt(s, 10, 64); perr == nil {
			d, err = seconds(secs)
		} else if parsed, perr := time.ParseDuration(s); perr == nil {
			d = parsed
		} else {
			return 0, fmt.Errorf(shape)
		}
	default:
		return 0, fmt.Errorf(shape)
	}
	if err != nil {
		return 0, err
	}
	if d < time.Second {
		return 0, fmt.Errorf("must be at least 1s")
	}
	if d > oauthMaxSignedURLTTL {
		return 0, fmt.Errorf("must be at most %s", oauthMaxSignedURLTTL)
	}
	return d, nil
}

// serveFileValueProblems checks a serve_file step's `with:` values the
// runtime reads literally.
func serveFileValueProblems(with map[string]any) []string {
	v, ok := with["expires_in"]
	if !ok {
		return nil
	}
	if _, err := parseSignedLinkLifetime(v); err != nil {
		return []string{fmt.Sprintf("`with.expires_in` %s; the signed link uses the default lifetime (%s, or %s for audio/video).", err.Error(), serveFileSignTTL, mediaPlaybackSignTTL)}
	}
	return nil
}
