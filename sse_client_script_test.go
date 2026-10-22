//go:build !cli

package main

import (
	"testing"

	"github.com/dop251/goja"
)

// Run the shipped scripts against a small DOM and EventSource. Browser-owned
// reconnects keep the same object/listeners; close() cancels them. Fatal HTTP
// responses (including an expired session's 401) already leave it CLOSED:
// https://html.spec.whatwg.org/multipage/server-sent-events.html#processing-model
func sseClientScriptVM(t *testing.T, scripts ...string) *goja.Runtime {
	t.Helper()
	vm := goja.New()
	_, err := vm.RunString(`
var window = this, sources = [], refreshes = [], reloads = 0, timers = [];
var elements = [
  {id: 'tasks', live: true, table: 'tasks'},
  {id: 'notes', live: false, table: 'notes'},
  {id: 'summary', live: true},
  {id: 'static'}
];
var document = {
  querySelectorAll: function(selector) {
    return elements.filter(function(el) {
      return selector.split(',').some(function(part) {
        part = part.trim();
        if (part === '[data-live]') return el.live === true;
        if (part === '[data-live-table]') return el.table !== undefined;
        var match = /^\[data-live-table="([^"]*)"\]$/.exec(part);
        if (match) return el.table === match[1];
        throw new Error('unexpected selector: ' + part);
      });
    });
  },
  querySelector: function(selector) { return this.querySelectorAll(selector)[0] || null; }
};
var htmx = {trigger: function(el, event) {
  if (event !== 'refresh') throw new Error('unexpected event: ' + event);
  refreshes.push(el.id);
}};
var location = {reload: function() { reloads++; }};
function setTimeout(fn) { timers.push(fn); }
function EventSource(url) {
  this.url = url;
  this.readyState = 1;
  this.listeners = {};
  sources.push(this);
}
EventSource.CONNECTING = 0;
EventSource.OPEN = 1;
EventSource.CLOSED = 2;
EventSource.prototype.close = function() { this.readyState = 2; };
EventSource.prototype.addEventListener = function(name, listener) {
  (this.listeners[name] || (this.listeners[name] = [])).push(listener);
};
EventSource.prototype.emit = function(name, data) {
  var event = {data: data};
  (this.listeners[name] || []).forEach(function(listener) { listener(event); });
  if (typeof this['on' + name] === 'function') this['on' + name](event);
};
EventSource.prototype.disconnect = function(terminal) {
  this.readyState = terminal ? 2 : 0;
  this.emit('error');
};
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range scripts {
		if _, err := vm.RunString(script); err != nil {
			t.Fatalf("SSE client script failed: %v", err)
		}
	}
	return vm
}

func TestSSEClientsPreserveNativeReconnect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scripts []string
	}{
		{"live", []string{SSEClientScript}},
		{"reload", []string{DevReloadClientScript}},
		{"live_then_reload", []string{SSEClientScript, DevReloadClientScript}},
		{"reload_then_live", []string{DevReloadClientScript, SSEClientScript}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := sseClientScriptVM(t, tc.scripts...)
			_, err := vm.RunString(`
if (sources.length !== 1) throw new Error('scripts must share one stream');
var source = sources[0];
var before = Object.keys(source.listeners).map(function(name) { return [name, source.listeners[name].length]; });
source.disconnect(false);
if (source.readyState !== EventSource.CONNECTING) throw new Error('stream rotation or network loss permanently closed the stream');
source.readyState = EventSource.OPEN;
source.emit('open');
source.disconnect(false);
if (source.readyState !== EventSource.CONNECTING) throw new Error('second disconnect cancelled reconnect');
var after = Object.keys(source.listeners).map(function(name) { return [name, source.listeners[name].length]; });
if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('reconnect duplicated listeners');
source.disconnect(true);
if (source.readyState !== EventSource.CLOSED) throw new Error('fatal response reopened the stream');
if (sources.length !== 1 || timers.length !== 0) throw new Error('script retries bypass native terminal failure');
`)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSSEClientHandlesGenericRefresh(t *testing.T) {
	vm := sseClientScriptVM(t, SSEClientScript)
	if err := vm.Set("genericRefresh", realtimeSSEGenericRefresh); err != nil {
		t.Fatal(err)
	}
	_, err := vm.RunString(`
sources[0].emit('change', genericRefresh);
if (JSON.stringify(refreshes) !== '["tasks","notes","summary"]') {
  throw new Error('generic refresh did not refresh every live component once: ' + JSON.stringify(refreshes));
}
refreshes = [];
sources[0].emit('change', JSON.stringify({table: 'tasks', action: 'update'}));
if (JSON.stringify(refreshes) !== '["tasks"]') throw new Error('table event refreshed unrelated components');
refreshes = [];
sources[0].emit('change', JSON.stringify({table: '', action: 'update'}));
sources[0].emit('change', 'not json');
if (refreshes.length !== 0) throw new Error('invalid event refreshed components');
`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSharedSSEStreamStillDeliversLiveAndReloadEvents(t *testing.T) {
	vm := sseClientScriptVM(t, SSEClientScript, DevReloadClientScript, DevReloadClientScript)
	_, err := vm.RunString(`
if (sources.length !== 1) throw new Error('scripts must share one stream');
sources[0].emit('change', JSON.stringify({table: 'tasks', action: 'update'}));
sources[0].emit('reload', '{}');
sources[0].emit('reload', '{}');
if (JSON.stringify(refreshes) !== '["tasks"]') throw new Error('live event lost on shared stream');
if (timers.length !== 1) throw new Error('reload scheduled more than once');
timers[0]();
if (reloads !== 1) throw new Error('reload event lost on shared stream');
`)
	if err != nil {
		t.Fatal(err)
	}
}
