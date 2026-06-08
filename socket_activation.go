package main

// systemd socket activation — the foundation of zero-downtime binary deploys.
//
// When the process is launched by a systemd `.socket` unit, systemd binds the
// listening sockets itself and passes them as fds starting at 3 (the
// LISTEN_FDS / LISTEN_PID protocol). Because the socket is owned by SYSTEMD —
// not this process — it stays bound across a binary swap + `systemctl restart`:
// the new process inherits the SAME listening socket, so connections queue in
// the kernel backlog during the sub-second handoff instead of being refused.
// That is what lets us swap the binary on disk and restart the server with no
// dropped connections.
//
// Inert when not socket-activated (no LISTEN_FDS): systemdListener returns nil
// and callers fall back to binding the port themselves. Harmless in local dev
// and in the open-source `serve` build — a self-hoster can opt into the same
// zero-downtime behavior by running under a systemd `.socket` unit.

import (
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

var (
	sdOnce      sync.Once
	sdListeners map[int]net.Listener
)

func initSystemdListeners() {
	sdListeners = map[int]net.Listener{}
	if os.Getenv("LISTEN_FDS") == "" {
		return // not socket-activated
	}
	// LISTEN_PID, when present, names the process systemd handed the fds to.
	// Honor it so a stray inherited env var in a child can't misfire.
	if pidStr := os.Getenv("LISTEN_PID"); pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err == nil && pid != os.Getpid() {
			return
		}
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		fd := 3 + i
		f := os.NewFile(uintptr(fd), "systemd-socket-"+strconv.Itoa(fd))
		if f == nil {
			continue
		}
		ln, err := net.FileListener(f)
		f.Close() // FileListener dups the fd; release our copy
		if err != nil {
			continue
		}
		if ta, ok := ln.Addr().(*net.TCPAddr); ok {
			sdListeners[ta.Port] = ln
			log.Printf("  socket activation: inherited systemd listener on :%d", ta.Port)
		}
	}
}

// systemdListener returns the systemd-passed listener for the given TCP port,
// or nil if the process wasn't socket-activated for that port.
func systemdListener(port int) net.Listener {
	sdOnce.Do(initSystemdListeners)
	return sdListeners[port]
}

// portFromAddr extracts the numeric port from an http.Server Addr like ":443".
func portFromAddr(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
