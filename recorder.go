//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Session recording - captures DOM state, clicks, navigation, and mutations.
// Dev mode only by default. Production requires explicit opt-in.
//
// app.yaml config:
//   recording:
//     enabled: "true"          # default: dev mode only
//     production: "false"      # must explicitly enable for prod
//     mask_inputs: "true"      # mask sensitive fields (default: true)

// RecordingSession stores a captured user session.
type RecordingSession struct {
	ID        string           `json:"id"`
	StartedAt string           `json:"started_at"`
	URL       string           `json:"url"`
	Events    []RecordingEvent `json:"events"`
	bytes     int              // request bytes accepted, for maxRecordingSessionBytes
}

// RecordingEvent is a single captured event.
type RecordingEvent struct {
	Type      string `json:"type"`      // "snapshot", "click", "navigate", "mutation", "scroll", "input", "resize"
	Timestamp int64  `json:"timestamp"` // ms since session start
	Data      any    `json:"data"`
}

// Bounds on the anonymous recording beacon: it is unauthenticated, and each
// app keeps its buffers in memory.
const (
	maxRecordingBatchBytes       = 4 << 20
	maxRecordingIDLen            = 64
	maxRecordingEventsPerSession = 50000
	// The event count alone would allow 50000 events of a whole batch each.
	maxRecordingSessionBytes = 16 << 20
	// /_internal/ is exempt from the app's general rate limiter, so the
	// beacon has its own per-client budget. The recorder flushes at most
	// every 5 seconds per open page (plus twice on unload), about 12 a
	// minute; 240 leaves room for many tabs or visitors behind one address.
	recordingBeaconsPerMinute = 240
	// Decoding a batch costs many times its wire size; at most this many
	// batches per app are decoded at once.
	maxRecordingConcurrentDecodes = 4
)

// countingReader counts the bytes a request body yields.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// RecordingStore holds one app's captured sessions. It used to be a process
// global, so in a `benmore host` process every app shared one buffer and one
// app's admin could read the DOM snapshots and input events (PII) another
// app's recorder posted. It now lives on App.Recordings.
type RecordingStore struct {
	mu       sync.RWMutex
	sessions map[string]*RecordingSession
	// decodeSlots bounds the beacon batches being decoded at once.
	decodeSlots chan struct{}
}

func newRecordingStore() *RecordingStore {
	return &RecordingStore{
		sessions:    make(map[string]*RecordingSession),
		decodeSlots: make(chan struct{}, maxRecordingConcurrentDecodes),
	}
}

// recordingStore returns the app's store, creating it on first use.
func (app *App) recordingStore() *RecordingStore {
	if app.Recordings == nil {
		app.Recordings = newRecordingStore()
	}
	return app.Recordings
}

// IsRecordingEnabled checks if recording is enabled for this app.
func IsRecordingEnabled(app *App, devMode bool) bool {
	if app.Design == nil {
		return devMode // default: on in dev, off in prod
	}
	rec := app.Design.Recording
	if rec == nil {
		return devMode
	}
	if rec["enabled"] == "false" {
		return false
	}
	if !devMode && rec["production"] != "true" {
		return false // prod requires explicit opt-in
	}
	return true
}

// RecorderScript returns the JS snippet to inject into pages.
// This is a lightweight recorder that captures:
// - Initial DOM snapshot (full HTML)
// - Click events (target selector + position)
// - Navigation (URL changes)
// - DOM mutations (added/removed/changed nodes)
// - Scroll position changes
// - Input changes (masked for sensitive fields)
// - Window resize
func RecorderScript(app *App, devMode bool) string {
	if !IsRecordingEnabled(app, devMode) {
		return ""
	}

	maskInputs := true
	if app.Design != nil && app.Design.Recording != nil {
		if app.Design.Recording["mask_inputs"] == "false" {
			maskInputs = false
		}
	}

	return fmt.Sprintf(`
<script>
(function(){
  var sid = 'rec_' + Date.now() + '_' + Math.random().toString(36).substr(2,6);
  var startTime = Date.now();
  var events = [];
  var maskInputs = %v;
  var sensitiveFields = ['password','credit','card','cvv','ssn','secret','token'];
  var maxEvents = 5000;
  var flushInterval = 5000;

  function ts(){ return Date.now() - startTime; }

  function isSensitive(el){
    if(!el) return false;
    var name = (el.name||'').toLowerCase();
    var type = (el.type||'').toLowerCase();
    if(type === 'password') return true;
    for(var i=0;i<sensitiveFields.length;i++){
      if(name.indexOf(sensitiveFields[i])>=0) return true;
    }
    return false;
  }

  // Secret surfaces. An element inside [data-bm-mask] (or sdui's
  // [data-bm-sensitive]) is never recorded by value: snapshots replace its
  // content, and its input, click and attribute events carry '***'. Sensitive
  // inputs also lose their value attribute in snapshots and mutations, and
  // credential-named URL parameters (a reset link's token) lose their value.
  var maskSel = '[data-bm-mask],[data-bm-sensitive]';
  function inMask(el){
    return !!(el && el.closest && el.closest(maskSel));
  }
  function maskedField(el){
    return inMask(el) || (maskInputs && isSensitive(el));
  }
  function maskURL(u){
    return String(u||'').replace(/([?&#;])([^=&#;]*)=([^&#;]*)/g,function(m,sep,k){
      var n=k.toLowerCase();
      for(var i=0;i<sensitiveFields.length;i++){
        if(n.indexOf(sensitiveFields[i])>=0) return sep+k+'=***';
      }
      return m;
    });
  }
  var otpauthRe = /otpauth(:|%%3a)[^"'<>\s]*/gi;
  function maskElement(el){
    var keep = {'class':1,'style':1,'id':1,'data-bm-mask':1,'data-bm-sensitive':1};
    var names = [];
    for(var i=0;i<el.attributes.length;i++) names.push(el.attributes[i].name);
    for(var j=0;j<names.length;j++) if(!keep[names[j]]) el.removeAttribute(names[j]);
    el.textContent = '***';
  }
  function snapshotHTML(){
    var root = document.documentElement;
    var fields = maskInputs ? root.querySelectorAll('input[value],textarea') : [];
    var sensitive = false;
    for(var i=0;i<fields.length&&!sensitive;i++) sensitive = isSensitive(fields[i]);
    var html;
    if(!sensitive && !root.querySelectorAll(maskSel).length){
      html = root.outerHTML;
    } else {
      // Mask a copy owned by an inert document, so nothing in it loads.
      var copy = document.implementation.createHTMLDocument('').importNode(root, true);
      var masked = copy.querySelectorAll(maskSel);
      for(var m=0;m<masked.length;m++) maskElement(masked[m]);
      var copies = maskInputs ? copy.querySelectorAll('input[value],textarea') : [];
      for(var c=0;c<copies.length;c++){
        if(!isSensitive(copies[c])) continue;
        if(copies[c].tagName==='TEXTAREA') copies[c].textContent='***';
        else copies[c].setAttribute('value','***');
      }
      html = copy.outerHTML;
    }
    return html.replace(otpauthRe,'otpauth:***');
  }

  function getSelector(el){
    if(!el||!el.tagName) return '';
    var parts=[];
    while(el&&el.tagName){
      var s=el.tagName.toLowerCase();
      if(el.id){s+='#'+el.id;parts.unshift(s);break}
      if(el.className&&typeof el.className==='string'){
        var cls=el.className.trim().split(/\s+/).slice(0,2).join('.');
        if(cls)s+='.'+cls;
      }
      var parent=el.parentElement;
      if(parent){
        var idx=Array.from(parent.children).indexOf(el);
        if(idx>0)s+=':nth-child('+(idx+1)+')';
      }
      parts.unshift(s);
      el=parent;
      if(parts.length>4)break;
    }
    return parts.join(' > ');
  }

  function record(type,data){
    if(events.length>=maxEvents)return;
    events.push({type:type,timestamp:ts(),data:data});
  }

  // Initial DOM snapshot
  record('snapshot',{
    url:maskURL(location.href),
    title:document.title,
    html:snapshotHTML(),
    width:window.innerWidth,
    height:window.innerHeight
  });

  // Click tracking
  document.addEventListener('click',function(e){
    var masked = inMask(e.target);
    var link = e.target.closest('a');
    record('click',{
      selector:getSelector(e.target),
      tag:e.target.tagName.toLowerCase(),
      text:masked?'***':(e.target.innerText||'').substring(0,40),
      x:e.clientX,y:e.clientY,
      href:masked?'***':maskURL(link?link.getAttribute('href'):'').replace(otpauthRe,'otpauth:***'),
      action:maskURL(e.target.getAttribute('hx-get')||e.target.getAttribute('hx-post')||e.target.getAttribute('hx-delete')||'')
    });
  },true);

  // Input tracking (masked for sensitive fields)
  document.addEventListener('input',function(e){
    var val = e.target.value;
    if(maskedField(e.target)) val = '***';
    record('input',{
      selector:getSelector(e.target),
      name:e.target.name||'',
      value:val
    });
  },true);

  // Scroll tracking (throttled)
  var scrollTimer;
  window.addEventListener('scroll',function(){
    clearTimeout(scrollTimer);
    scrollTimer=setTimeout(function(){
      record('scroll',{x:window.scrollX,y:window.scrollY});
    },200);
  },true);

  // Resize tracking
  var resizeTimer;
  window.addEventListener('resize',function(){
    clearTimeout(resizeTimer);
    resizeTimer=setTimeout(function(){
      record('resize',{width:window.innerWidth,height:window.innerHeight});
    },200);
  });

  // DOM mutation tracking
  var observer = new MutationObserver(function(mutations){
    mutations.forEach(function(m){
      if(m.type==='childList'&&(m.addedNodes.length||m.removedNodes.length)){
        record('mutation',{
          type:'childList',
          target:getSelector(m.target),
          added:m.addedNodes.length,
          removed:m.removedNodes.length
        });
      } else if(m.type==='attributes'){
        var hide = inMask(m.target) || (m.attributeName==='value' && maskInputs && isSensitive(m.target));
        record('mutation',{
          type:'attributes',
          target:getSelector(m.target),
          attr:m.attributeName,
          value:hide?'***':(m.target.getAttribute(m.attributeName)||'').substring(0,100)
        });
      }
    });
  });
  observer.observe(document.body,{childList:true,attributes:true,subtree:true,attributeFilter:['class','style','value','checked','disabled','hidden']});

  // Navigation tracking (SPA-style via HTMX)
  document.addEventListener('htmx:afterSwap',function(e){
    record('navigate',{url:maskURL(location.href),target:getSelector(e.detail.target)});
  });

  // Flush events to server periodically
  function flush(){
    if(events.length===0)return;
    var payload={id:sid,events:events.splice(0)};
    navigator.sendBeacon('/_internal/recording',JSON.stringify(payload));
  }
  setInterval(flush,flushInterval);
  window.addEventListener('beforeunload',flush);
  // Final snapshot before unload
  window.addEventListener('beforeunload',function(){
    record('snapshot',{url:maskURL(location.href),html:snapshotHTML(),width:window.innerWidth,height:window.innerHeight});
    flush();
  });
})();
</script>`, maskInputs)
}

// RegisterRecordingRoutes adds the recording endpoints.
//
// SECURITY: the routes are only registered when recording is actually
// enabled for this app. Previously they were wired unconditionally, so
// `GET /_internal/recordings` was always live AND unauthenticated - any
// anonymous caller could read captured session data (DOM snapshots, input
// events = PII) whenever an app set `recording.production: true`, and could
// POST arbitrary events to the buffer even with recording off. Now: no
// recording config → no routes (404). The read endpoints below additionally
// require an admin session (captured sessions are sensitive; only the app
// operator should read them).
func RegisterRecordingRoutes(mux appRouteRegistrar, app *App) {
	if !IsRecordingEnabled(app, app.DevMode) {
		return
	}
	requireAdmin := func(w http.ResponseWriter, r *http.Request) bool {
		s := getSession(app, r)
		if s == nil || !s.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return false
		}
		return true
	}
	// Receive recording events. Anonymous, so it is budgeted per client
	// address and the number of batches decoded at once is capped (the
	// buffered sessions themselves are bounded below).
	beaconLimiter := NewRateLimiterStoppable(recordingBeaconsPerMinute, time.Minute, app.Stop)
	mux.HandleFunc("POST /_internal/recording", func(w http.ResponseWriter, r *http.Request) {
		if ok, retry, _ := beaconLimiter.Check("ip:" + clientRateBucket(clientIP(r))); !ok {
			setRetryAfter(w, retry)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		store := app.recordingStore()
		select {
		case store.decodeSlots <- struct{}{}:
			defer func() { <-store.decodeSlots }()
		default:
			setRetryAfter(w, time.Second)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var payload struct {
			ID     string           `json:"id"`
			Events []RecordingEvent `json:"events"`
		}
		body := &countingReader{r: http.MaxBytesReader(w, r.Body, maxRecordingBatchBytes)}
		if err := json.NewDecoder(body).Decode(&payload); err != nil ||
			payload.ID == "" || len(payload.ID) > maxRecordingIDLen {
			w.WriteHeader(400)
			return
		}

		store.mu.Lock()
		session, ok := store.sessions[payload.ID]
		if !ok {
			session = &RecordingSession{
				ID:        payload.ID,
				StartedAt: time.Now().UTC().Format(time.RFC3339),
			}
			store.sessions[payload.ID] = session
		}
		// The beacon is anonymous (any visitor's browser posts it), so one
		// session's buffer is bounded: past the cap further events drop.
		if room := maxRecordingEventsPerSession - len(session.Events); room > 0 && session.bytes+body.n <= maxRecordingSessionBytes {
			session.bytes += body.n
			if len(payload.Events) > room {
				payload.Events = payload.Events[:room]
			}
			session.Events = append(session.Events, payload.Events...)
		}

		// Cap at 10 sessions, prune oldest
		if len(store.sessions) > 10 {
			var oldest string
			var oldestTime time.Time
			for id, s := range store.sessions {
				t, _ := time.Parse(time.RFC3339, s.StartedAt)
				if oldest == "" || t.Before(oldestTime) {
					oldest = id
					oldestTime = t
				}
			}
			delete(store.sessions, oldest)
		}
		store.mu.Unlock()

		w.WriteHeader(204)
	})

	// Get all recording sessions
	mux.HandleFunc("GET /_internal/recordings", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		store := app.recordingStore()
		store.mu.RLock()
		defer store.mu.RUnlock()

		var sessions []*RecordingSession
		for _, s := range store.sessions {
			sessions = append(sessions, s)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessions)
	})

	// Get single session
	mux.HandleFunc("GET /_internal/recording/", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		id := r.URL.Path[len("/_internal/recording/"):]
		store := app.recordingStore()
		store.mu.RLock()
		session, ok := store.sessions[id]
		store.mu.RUnlock()
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(session)
	})

	// Get latest DOM snapshot (for screenshot tool / design tool)
	mux.HandleFunc("GET /_internal/latest-snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		store := app.recordingStore()
		store.mu.RLock()
		defer store.mu.RUnlock()

		var latest *RecordingEvent
		for _, s := range store.sessions {
			for i := len(s.Events) - 1; i >= 0; i-- {
				if s.Events[i].Type == "snapshot" {
					latest = &s.Events[i]
					break
				}
			}
		}
		if latest == nil {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(latest)
	})
}
