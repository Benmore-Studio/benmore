//go:build !cli

package main

// Opt-in runtime profiling (net/http/pprof) for app, router and host
// processes.
//
// Off unless BENMORE_PPROF_ADDR is set. Then:
//   - the address must be a loopback IP literal or "localhost" with an
//     explicit port; any other address (including ":6060", which binds every
//     interface) is refused and nothing listens;
//   - BENMORE_PPROF_TOKEN must be set (at least pprofMinTokenLen bytes); every
//     request presents it as `Authorization: Bearer <token>` and is compared in
//     constant time, else 401;
//   - the handlers live on their own mux and listener, never on an app,
//     router or host mux.
//
// Usage on the host:
//
//	curl -H "Authorization: Bearer $BENMORE_PPROF_TOKEN" \
//	  http://127.0.0.1:6060/debug/pprof/profile?seconds=30 > cpu.pprof
//
// Importing net/http/pprof also registers its handlers on
// http.DefaultServeMux; no server in this binary serves DefaultServeMux.

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"
)

const pprofMinTokenLen = 16

var pprofStartOnce sync.Once

// startPprofListener starts the opt-in profiling listener once per process.
// Configuration errors are logged and leave profiling off; they never stop
// the server.
func startPprofListener() {
	pprofStartOnce.Do(func() {
		addr := strings.TrimSpace(os.Getenv("BENMORE_PPROF_ADDR"))
		if addr == "" {
			return
		}
		ln, err := listenPprof(addr, os.Getenv("BENMORE_PPROF_TOKEN"))
		if err != nil {
			log.Printf("  pprof: disabled: %v", err)
			return
		}
		srv := &http.Server{
			Handler:           pprofHandler(os.Getenv("BENMORE_PPROF_TOKEN")),
			ReadHeaderTimeout: 10 * time.Second,
		}
		log.Printf("  pprof: listening on %s (loopback, token required)", ln.Addr())
		safeGo("pprof.serve", func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("  pprof: %v", err)
			}
		})
	})
}

// listenPprof validates the configuration and binds the listener.
func listenPprof(addr, token string) (net.Listener, error) {
	if err := pprofAddrAllowed(addr); err != nil {
		return nil, err
	}
	if len(token) < pprofMinTokenLen {
		return nil, fmt.Errorf("BENMORE_PPROF_TOKEN must be set to at least %d characters", pprofMinTokenLen)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	// "localhost" is resolved by the system; confirm what was bound.
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		ln.Close()
		return nil, fmt.Errorf("BENMORE_PPROF_ADDR %q resolved to non-loopback %s", addr, ln.Addr())
	}
	return ln, nil
}

// pprofAddrAllowed accepts only a loopback host with an explicit port.
func pprofAddrAllowed(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("BENMORE_PPROF_ADDR %q: %v", addr, err)
	}
	if port == "" {
		return fmt.Errorf("BENMORE_PPROF_ADDR %q: a port is required", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("BENMORE_PPROF_ADDR %q: profiling binds only a loopback address (127.0.0.1, ::1 or localhost)", addr)
}

// pprofHandler serves net/http/pprof behind a bearer token.
func pprofHandler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if token == "" || subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="pprof"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
