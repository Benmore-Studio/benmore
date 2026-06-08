//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Session recording — captures DOM state, clicks, navigation, and mutations.
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
}

// RecordingEvent is a single captured event.
type RecordingEvent struct {
	Type      string `json:"type"`      // "snapshot", "click", "navigate", "mutation", "scroll", "input", "resize"
	Timestamp int64  `json:"timestamp"` // ms since session start
	Data      any    `json:"data"`
}

var (
	recordingSessions   = make(map[string]*RecordingSession)
	recordingSessionsMu sync.RWMutex
)

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
    url:location.href,
    title:document.title,
    html:document.documentElement.outerHTML,
    width:window.innerWidth,
    height:window.innerHeight
  });

  // Click tracking
  document.addEventListener('click',function(e){
    record('click',{
      selector:getSelector(e.target),
      tag:e.target.tagName.toLowerCase(),
      text:(e.target.innerText||'').substring(0,40),
      x:e.clientX,y:e.clientY,
      href:e.target.closest('a')?e.target.closest('a').getAttribute('href'):'',
      action:e.target.getAttribute('hx-get')||e.target.getAttribute('hx-post')||e.target.getAttribute('hx-delete')||''
    });
  },true);

  // Input tracking (masked for sensitive fields)
  document.addEventListener('input',function(e){
    var val = e.target.value;
    if(maskInputs && isSensitive(e.target)) val = '***';
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
        record('mutation',{
          type:'attributes',
          target:getSelector(m.target),
          attr:m.attributeName,
          value:(m.target.getAttribute(m.attributeName)||'').substring(0,100)
        });
      }
    });
  });
  observer.observe(document.body,{childList:true,attributes:true,subtree:true,attributeFilter:['class','style','value','checked','disabled','hidden']});

  // Navigation tracking (SPA-style via HTMX)
  document.addEventListener('htmx:afterSwap',function(e){
    record('navigate',{url:location.href,target:getSelector(e.detail.target)});
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
    record('snapshot',{url:location.href,html:document.documentElement.outerHTML,width:window.innerWidth,height:window.innerHeight});
    flush();
  });
})();
</script>`, maskInputs)
}

// RegisterRecordingRoutes adds the recording endpoints.
//
// SECURITY: the routes are only registered when recording is actually
// enabled for this app. Previously they were wired unconditionally, so
// `GET /_internal/recordings` was always live AND unauthenticated — any
// anonymous caller could read captured session data (DOM snapshots, input
// events = PII) whenever an app set `recording.production: true`, and could
// POST arbitrary events to the buffer even with recording off. Now: no
// recording config → no routes (404). The read endpoints below additionally
// require an admin session (captured sessions are sensitive; only the app
// operator should read them).
func RegisterRecordingRoutes(mux *http.ServeMux, app *App) {
	if !IsRecordingEnabled(app, app.DevMode) {
		return
	}
	requireAdmin := func(w http.ResponseWriter, r *http.Request) bool {
		s := getSession(app, r)
		if s == nil || !s.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return false
		}
		return true
	}
	// Receive recording events
	mux.HandleFunc("POST /_internal/recording", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			ID     string           `json:"id"`
			Events []RecordingEvent `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(400)
			return
		}

		recordingSessionsMu.Lock()
		session, ok := recordingSessions[payload.ID]
		if !ok {
			session = &RecordingSession{
				ID:        payload.ID,
				StartedAt: time.Now().UTC().Format(time.RFC3339),
			}
			recordingSessions[payload.ID] = session
		}
		session.Events = append(session.Events, payload.Events...)

		// Cap at 10 sessions, prune oldest
		if len(recordingSessions) > 10 {
			var oldest string
			var oldestTime time.Time
			for id, s := range recordingSessions {
				t, _ := time.Parse(time.RFC3339, s.StartedAt)
				if oldest == "" || t.Before(oldestTime) {
					oldest = id
					oldestTime = t
				}
			}
			delete(recordingSessions, oldest)
		}
		recordingSessionsMu.Unlock()

		w.WriteHeader(204)
	})

	// Get all recording sessions
	mux.HandleFunc("GET /_internal/recordings", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		recordingSessionsMu.RLock()
		defer recordingSessionsMu.RUnlock()

		var sessions []*RecordingSession
		for _, s := range recordingSessions {
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
		recordingSessionsMu.RLock()
		session, ok := recordingSessions[id]
		recordingSessionsMu.RUnlock()
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
		recordingSessionsMu.RLock()
		defer recordingSessionsMu.RUnlock()

		var latest *RecordingEvent
		for _, s := range recordingSessions {
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
