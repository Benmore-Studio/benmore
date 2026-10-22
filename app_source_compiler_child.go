//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const capturedCompilerFlag = "_benmore-captured-compile"
const capturedCompilerEnv = "BENMORE_CAPTURED_COMPILER"
const capturedCompilerOutputLimit = 8 << 20

// Only a fixed compiler operation is accepted; no application code is executed.
// The fresh child has no app/process credentials and cannot fall back to a
// disk-backed build when its finite captured filesystem is unavailable.
func init() {
	if len(os.Args) != 3 || os.Args[1] != capturedCompilerFlag || os.Getenv(capturedCompilerEnv) != "1" {
		return
	}
	if err := runCapturedCompilerChild(os.Args[2]); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(capturedCompilerResponse{Error: "captured compiler could not build this generation"})
		os.Exit(1)
	}
	os.Exit(0)
}

var capturedCompilerFiles map[string]string

// capturedCompilerRuns counts compiler children started (observability for tests).
var capturedCompilerRuns atomic.Uint64

type capturedCompilerRequest struct {
	Kind   string            `json:"kind"`
	Source string            `json:"source"`
	Hashes map[string]string `json:"hashes,omitempty"`
}
type capturedCompilerResponse struct {
	Body  []byte `json:"body,omitempty"`
	Error string `json:"error,omitempty"`
	// Inputs lists the app-relative files a "widget" build bundled.
	Inputs []string `json:"inputs,omitempty"`
}

func runCapturedCompilerChild(root string) error {
	if !filepath.IsAbs(root) {
		return fmt.Errorf("invalid compiler root")
	}
	// Only native compilation/parsing runs in this child. The compiler consumes
	// the finite digest-bound filesystem below; no application JS is executed.
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	decoder.DisallowUnknownFields()
	var request capturedCompilerRequest
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid compiler request")
	}
	source := filepath.FromSlash(request.Source)
	if !filepath.IsLocal(source) || filepath.ToSlash(filepath.Clean(source)) != request.Source || !strings.HasPrefix(request.Source, "static/") {
		return fmt.Errorf("invalid compiler source")
	}
	appRoot := filepath.Join(root, "app")
	source = filepath.Join(appRoot, source)
	staticRoot := filepath.Join(appRoot, "static")
	if len(request.Hashes) == 0 || len(request.Hashes) > 10000 {
		return fmt.Errorf("invalid compiler fingerprints")
	}
	// esbuild's existing finite filesystem keeps all native resolution metadata.
	files := make(map[string]string)
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || len(files) >= 10002 {
			return fmt.Errorf("invalid compiler capture")
		}
		info, err := entry.Info()
		if err != nil || info.Size() > (64<<20)+4-total {
			return fmt.Errorf("oversized compiler capture")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (64<<20)+5-total))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		total += int64(len(data))
		if total > (64<<20)+4 {
			return fmt.Errorf("oversized compiler capture")
		}
		rel, relErr := filepath.Rel(appRoot, path)
		if relErr == nil && filepath.IsLocal(rel) {
			if request.Hashes[filepath.ToSlash(rel)] != hashBytesSHA256(data) {
				return fmt.Errorf("compiler capture digest mismatch")
			}
		} else if (path != filepath.Join(root, "package.json") && path != filepath.Join(root, "tsconfig.json")) || string(data) != "{}" {
			return fmt.Errorf("invalid compiler capture membership")
		}
		files[path] = string(data)
		return nil
	})
	if err != nil {
		return err
	}
	for name, digest := range request.Hashes {
		local := filepath.FromSlash(name)
		if !filepath.IsLocal(local) || filepath.ToSlash(filepath.Clean(local)) != name {
			return fmt.Errorf("invalid compiler fingerprint path")
		}
		_, exists := files[filepath.Join(appRoot, local)]
		if (digest != "") != exists {
			return fmt.Errorf("compiler capture membership mismatch")
		}
	}
	capturedCompilerFiles = files
	var body []byte
	var inputs []string
	switch request.Kind {
	case "widget":
		var absolute []string
		body, absolute, err = compileWidgetBundle(source, staticRoot)
		for _, file := range absolute {
			if rel, relErr := filepath.Rel(appRoot, file); relErr == nil {
				inputs = append(inputs, filepath.ToSlash(rel))
			}
		}
	case "browser":
		body, err = compileTSXOrTS(source, staticRoot)
	case "compute":
		_, err = compileComputeModule(source, staticRoot, request.Hashes)
		if err == nil {
			computeCacheMu.RLock()
			entry := computeCache[source]
			if entry != nil {
				body = entry.source
			}
			computeCacheMu.RUnlock()
			if len(body) == 0 {
				return fmt.Errorf("missing compiled source")
			}
		}
	default:
		return fmt.Errorf("invalid compiler operation")
	}
	if err != nil {
		return err
	}
	if len(body) > capturedCompilerOutputLimit {
		return fmt.Errorf("compiled output exceeds limit")
	}
	return json.NewEncoder(os.Stdout).Encode(capturedCompilerResponse{Body: body, Inputs: inputs})
}

// ponytail: one bounded child per reviewed build; only add worker reuse if
// measured startup cost warrants the extra lifecycle and generation ownership.
func compileCapturedAppSource(parent context.Context, kind, appRoot, source string, hashes map[string]string) ([]byte, error) {
	response, err := compileCapturedAppSourceDetailed(parent, kind, appRoot, source, hashes)
	if err != nil {
		return nil, err
	}
	return response.Body, nil
}

func compileCapturedAppSourceDetailed(parent context.Context, kind, appRoot, source string, hashes map[string]string) (capturedCompilerResponse, error) {
	if err := parent.Err(); err != nil {
		return capturedCompilerResponse{}, err
	}
	// One process-wide budget for compiles (tsxCompileSlots): each child is a
	// whole process holding the staged tree in memory.
	release, slotErr := acquireCompileSlot(parent)
	if slotErr != nil {
		return capturedCompilerResponse{}, slotErr
	}
	defer release()
	capturedCompilerRuns.Add(1)
	appRoot, err := filepath.EvalSymlinks(appRoot)
	if err != nil {
		return capturedCompilerResponse{}, fmt.Errorf("invalid captured compiler root")
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return capturedCompilerResponse{}, fmt.Errorf("invalid captured compiler source")
	}
	relative, err := filepath.Rel(appRoot, source)
	if err != nil || !filepath.IsLocal(relative) {
		return capturedCompilerResponse{}, fmt.Errorf("invalid captured compiler source")
	}
	request, err := json.Marshal(capturedCompilerRequest{Kind: kind, Source: filepath.ToSlash(relative), Hashes: hashes})
	if err != nil || len(request) > 1<<20 {
		return capturedCompilerResponse{}, fmt.Errorf("captured compiler request exceeds limit")
	}
	self, err := os.Executable()
	if err != nil {
		return capturedCompilerResponse{}, fmt.Errorf("captured compiler unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, self, capturedCompilerFlag, filepath.Dir(appRoot))
	command.Dir = appRoot
	// Keep race detection enabled without its default one-second exit delay.
	// Every compiler callback is joined before the child returns.
	command.Env = []string{capturedCompilerEnv + "=1", "LANG=C", "GORACE=atexit_sleep_ms=0"}
	command.Stdin = bytes.NewReader(request)
	// JSON encodes the body as base64; reserve its exact bounded expansion.
	out := &cappedBuffer{limit: ((capturedCompilerOutputLimit+2)/3)*4 + 256, cancel: cancel}
	command.Stdout = out
	command.Stderr = io.Discard
	runErr := command.Run()
	if out.truncated {
		return capturedCompilerResponse{}, fmt.Errorf("captured compiler output exceeds limit")
	}
	if err := ctx.Err(); err != nil {
		return capturedCompilerResponse{}, err
	}
	if runErr != nil {
		return capturedCompilerResponse{}, fmt.Errorf("captured compiler unavailable or invalid generation")
	}
	var response capturedCompilerResponse
	if err := json.Unmarshal(out.buf.Bytes(), &response); err != nil || response.Error != "" || len(response.Body) == 0 {
		return capturedCompilerResponse{}, fmt.Errorf("captured compiler returned invalid output")
	}
	return response, nil
}
