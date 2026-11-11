//go:build !cli

package main

// Media storage allowance: the parts the app process and the router's presign
// broker share.
//
// On the hosted platform an account may store a plan-sized amount of media
// (limits.go planTier.MediaBytes): the files its apps' users upload to the
// platform media bucket plus its apps' dashboard media libraries. The router
// keeps the account (platform_media_allowance.go) because it is the only
// process that holds the storage credential and the account database; a
// hosted app process holds neither and is not trusted for a size.
//
// How a size is known without trusting the app process: the process declares
// the length of the upload when it asks the broker for a URL, and the broker
// signs that exact Content-Length into the presigned PUT, so the store
// refuses any other body. What was charged is what was stored. A request that
// declares no size (a binary older than this protocol) gets the URL it always
// got, and the broker measures the stored object at the store once the URL
// has expired. A delete is measured the same way, at the store, before the
// broker deletes. A listing of the bucket corrects the counter on a schedule.
//
// This file holds the broker's hook (presignMediaMeter, set by the router and
// nil in every other process, so self-hosted and framework builds meter
// nothing), the typed refusal that travels back to the app process, and the
// HTTP answer the upload routes give for it.

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// mediaAllowanceCode is the `code` of an upload refused for the account's
// media allowance, in the broker's reply and in the HTTP answer. The database
// limit's answer carries "storage_limit" (storage_limit.go).
const mediaAllowanceCode = "media_storage_limit"

// presignMaxObjectBytes bounds a declared upload size: the largest object the
// store takes in one PUT.
const presignMaxObjectBytes int64 = 5 << 30

// presignPutURLTTL is how long a presigned upload URL is valid.
const presignPutURLTTL = 90 * time.Second

// mediaAllowanceError is an upload the owning account's media allowance does
// not cover. Message is the whole refusal, with the usage, the allowance and
// the way out.
type mediaAllowanceError struct {
	Message    string
	UsedBytes  int64
	LimitBytes int64
}

func (e *mediaAllowanceError) Error() string { return e.Message }

// mediaAllowanceBody is the caller-facing refusal. It follows the database
// limit's answer (storageFullBody): the same status and `error`, so a client
// that already handles "storage cap reached" handles this too, and its own
// `code`.
func mediaAllowanceBody(e *mediaAllowanceError) map[string]any {
	return withRefusalDocs(map[string]any{
		"error":       "storage cap reached",
		"code":        mediaAllowanceCode,
		"used_bytes":  e.UsedBytes,
		"limit_bytes": e.LimitBytes,
		"detail":      e.Message,
	}, mediaAllowanceCode)
}

// respondMediaAllowance writes the allowance refusal when err is one and
// reports whether it did.
func respondMediaAllowance(w http.ResponseWriter, err error) bool {
	var refused *mediaAllowanceError
	if !errors.As(err, &refused) {
		return false
	}
	httpJSON(w, storageFullStatus, mediaAllowanceBody(refused))
	return true
}

// mediaUpload is one upload the broker is asked to issue a URL for.
type mediaUpload struct {
	// Prefix is the instance prefix the object lands under (<sub> or
	// <sub>-dev), derived from the socket peer and its instance proof.
	Prefix string
	// Key is the bucket key.
	Key string
	// Size is the declared length the URL enforces, or -1 when the caller
	// declared none.
	Size int64
	// FirstParty: the router's own user asked. Counted, never refused.
	FirstParty bool
	// Measure reads the stored object's size at the store (found is false
	// when there is no such object). Used for an upload that declared none.
	Measure func() (size int64, found bool, err error)
}

// mediaUploadMeter is the router's account of what each instance prefix holds
// in the media bucket.
type mediaUploadMeter interface {
	// admit is asked before an upload URL is issued. It returns the refusal,
	// or nil after charging the upload to the prefix. A meter that cannot
	// read its counter admits: accounting must not take uploads down.
	admit(u mediaUpload) *mediaAllowanceError
	// deleted reports an object the broker removed from the store. size is
	// what the store said it held just before (0: there was none; -1: the
	// store could not say).
	deleted(prefix, key string, size int64)
}

// mediaKeyLocks serialize the broker's measure-and-delete of one object key
// while a meter is set: two deletes of the same object sent together would
// otherwise both measure it before either removed it, and both be credited.
var mediaKeyLocks [256]sync.Mutex

// lockMediaKey holds key's lock until the returned function is called.
func lockMediaKey(key string) (unlock func()) {
	h := fnv.New32a()
	h.Write([]byte(key))
	l := &mediaKeyLocks[h.Sum32()%uint32(len(mediaKeyLocks))]
	l.Lock()
	return l.Unlock
}

// presignMediaMeter is set by the router before its broker starts. Nil means
// no allowance is kept: every process but the router, and every edition
// without the platform.
var presignMediaMeter mediaUploadMeter

// presignRequireSizeEnv is the router's switch that refuses an upload request
// that declares no size. Set it once every instance runs a binary that
// declares one: until then such a request is served and measured afterwards.
// BENMORE_PLATFORM_* keys are platform-reserved, so no app can set it.
const presignRequireSizeEnv = "BENMORE_PLATFORM_MEDIA_REQUIRE_SIZE"

func presignRequireSize() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(presignRequireSizeEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// presignDeclaredSize reads the size an upload request declares: -1 when it
// declares none, an error for one the store could not hold.
func presignDeclaredSize(req presignReq) (int64, error) {
	if req.Size == nil {
		if presignRequireSize() {
			return 0, fmt.Errorf("upload size required")
		}
		return -1, nil
	}
	if *req.Size < 0 || *req.Size > presignMaxObjectBytes {
		return 0, fmt.Errorf("bad upload size")
	}
	return *req.Size, nil
}

// presignErrorReply is the broker's reply for a refused request. An
// allowance refusal carries its code and numbers so the app process can
// answer its client with them; every other error is its text.
func presignErrorReply(err error) presignResp {
	var refused *mediaAllowanceError
	if errors.As(err, &refused) {
		return presignResp{Error: refused.Message, Code: mediaAllowanceCode, UsedBytes: refused.UsedBytes, LimitBytes: refused.LimitBytes}
	}
	return presignResp{Error: err.Error()}
}

// ObjectSize asks the store how large one object is (a HEAD). found is false
// when the store has no such object. The path is put into the URL exactly as
// Delete puts it, so both name the same object.
func (s3 *S3Storage) ObjectSize(ctx context.Context, path string) (size int64, found bool, err error) {
	if ctx == nil || path == "" {
		return 0, false, errors.New("S3 head path is invalid")
	}
	awsNative := s3.Endpoint == "" || strings.Contains(s3.Endpoint, "amazonaws.com")
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s3.objectURL(path), nil)
	if err != nil {
		return 0, false, err
	}
	key, secret, token := s3.resolveCreds()
	if key != "" {
		if token != "" {
			req.Header.Set("X-Amz-Security-Token", token)
		}
		if awsNative {
			signAWSv4(req, nil, key, secret, s3.Region, "s3")
		} else {
			req.SetBasicAuth(key, secret)
		}
	}
	client := s3HTTPClient(10 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return 0, false, nil
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return 0, false, fmt.Errorf("S3 head failed: %d", resp.StatusCode)
	case resp.ContentLength < 0:
		return 0, false, errors.New("S3 head returned no length")
	}
	return resp.ContentLength, true, nil
}
