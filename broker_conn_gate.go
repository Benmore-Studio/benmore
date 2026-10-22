package main

import (
	"log"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

// The email, SMS and presign brokers listen on world- or group-connectable
// unix sockets in the ROUTER, and authorize by peer uid only after a
// connection exists. Each accepted connection got a bare goroutine: no
// concurrency bound (one tenant process can hold thousands of connections,
// each buffering up to 35 MiB of request in router memory) and no recover (a
// panic in any handler terminates the router for every tenant). The gate
// bounds concurrent connections per peer uid and overall, and contains handler
// panics to their connection.
type brokerConnGate struct {
	mu        sync.Mutex
	total     int
	perUID    map[int]int
	maxTotal  int
	maxPerUID int
	ownUID    int // the router's own uid (first-party callers): bounded overall, not per uid
	// reserved slots only the router's own uid may take, so tenants filling
	// every other slot cannot starve first-party mail (OTP, password reset).
	reserved int
	lastLog  time.Time
}

func newBrokerConnGate(maxTotal, maxPerUID int) *brokerConnGate {
	return &brokerConnGate{perUID: map[int]int{}, maxTotal: maxTotal, maxPerUID: maxPerUID, ownUID: os.Getuid()}
}

func (g *brokerConnGate) acquire(uid int) (release func(), ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	perUID, total := g.maxPerUID, g.maxTotal-g.reserved
	if uid == g.ownUID {
		perUID, total = g.maxTotal, g.maxTotal
	}
	if g.total >= total || g.perUID[uid] >= perUID {
		return nil, false
	}
	g.total++
	g.perUID[uid]++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.total--
			if g.perUID[uid]--; g.perUID[uid] <= 0 {
				delete(g.perUID, uid)
			}
		})
	}, true
}

// serve runs handle for conn on its own goroutine, or closes conn when the
// peer (or the broker) is over its connection budget. A peer whose uid cannot
// be read shares one bucket (-1); the handler still performs its own identity
// check and refuses it.
func (g *brokerConnGate) serve(name string, conn *net.UnixConn, handle func()) {
	uid, err := peerUID(conn)
	if err != nil {
		uid = -1
	}
	release, ok := g.acquire(uid)
	if !ok {
		conn.Close()
		g.mu.Lock()
		quiet := time.Since(g.lastLog) < 30*time.Second
		if !quiet {
			g.lastLog = time.Now()
		}
		g.mu.Unlock()
		if !quiet {
			log.Printf("%s: connection refused, too many concurrent connections (uid %d)", name, uid)
		}
		return
	}
	go func() {
		defer release()
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC in %s connection handler: %v\n%s", name, rec, debug.Stack())
				conn.Close()
			}
		}()
		handle()
	}()
}
