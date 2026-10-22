//go:build !cli

package main

// Per-run cache of the flattened `{{ }}` lookup table (flatDataForCtx).
//
// Every template string a flow resolves - each respond field, api header,
// json leaf, condition - used to re-flatten ALL of ctx.Data plus the env
// snapshot. Inside a for_each that is O(templates x data) per iteration,
// and the data usually includes the list being iterated, so a request with
// a large body or a large query result made the run quadratic.
//
// ctx.Data has writers in many files (step outputs, flattenIntoCtx,
// sql_dynamic overlays, error handlers, ...), so the cache does not rely on
// each of them remembering to invalidate it. It keeps a shallow snapshot of
// the top-level map it was built from and is reused only while every
// top-level entry is still the identical value: the same scalar, or the
// same map/slice (same backing pointer and length). Any assignment, delete
// or addition at the top level, or an in-place insert into a top-level map,
// rebuilds it. The env snapshot is compared by content.
//
// Not detected: replacing a value under an existing key INSIDE a nested map
// (same object, same length). No framework writer does that - step outputs,
// set, parse, for_each, sql_dynamic overlays and the error handler all
// assign new values at the top level - and new code must keep it that way
// (assign a new map instead of editing one in place). A compute step is the
// exception: goja writes through the native maps and slices it is handed, so
// a function that edits its argument (or sorts an array in place) changes
// ctx.Data without changing any identity; execStepCompute invalidates.
//
// The returned map is shared by every caller in the run and must be treated
// as read-only; a caller that needs to add keys clones it first.

import (
	"maps"
	"reflect"
	"sync"
	"unsafe"
)

type flowFlatCache struct {
	mu    sync.Mutex
	flat  map[string]any
	shape map[string]flowValueID // identity of each ctx.Data entry at build time
	env   map[string]string      // env snapshot at build time
	built bool
}

// flowValueID is a value's identity at one moment: a scalar's value, or a
// map/slice/pointer's address plus (for maps and slices) its length then.
// The length is recorded, not re-read, so an insert into a map that is
// still the same object is seen as a change.
type flowValueID struct {
	typ    reflect.Type
	ptr    unsafe.Pointer
	n      int
	scalar any
	ok     bool
}

func flowIdentity(v any) flowValueID {
	if v == nil {
		return flowValueID{ok: true}
	}
	rv := reflect.ValueOf(v)
	id := flowValueID{typ: rv.Type(), ok: true}
	switch rv.Kind() {
	case reflect.Map, reflect.Slice:
		id.ptr, id.n = rv.UnsafePointer(), rv.Len()
	case reflect.Pointer:
		id.ptr = rv.UnsafePointer()
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		id.scalar = v
	default:
		// Structs, funcs, channels...: never treated as unchanged, which
		// only costs a rebuild.
		id.ok = false
	}
	return id
}

func (a flowValueID) same(b flowValueID) bool {
	return a.ok && b.ok && a.typ == b.typ && a.ptr == b.ptr && a.n == b.n && a.scalar == b.scalar
}

// lookup returns the cached table when data and env still match what it was
// built from.
func (c *flowFlatCache) lookup(data map[string]any, env map[string]string) (map[string]any, bool) {
	if !c.built || len(c.shape) != len(data) || !maps.Equal(c.env, env) {
		return nil, false
	}
	for k, v := range data {
		old, ok := c.shape[k]
		if !ok || !old.same(flowIdentity(v)) {
			return nil, false
		}
	}
	return c.flat, true
}

// invalidate drops the cached table, for a step that may have edited
// ctx.Data's nested maps or slices in place.
func (c *flowFlatCache) invalidate() {
	c.mu.Lock()
	c.flat, c.shape, c.env, c.built = nil, nil, nil, false
	c.mu.Unlock()
}

func (c *flowFlatCache) store(data map[string]any, env map[string]string, flat map[string]any) {
	shape := make(map[string]flowValueID, len(data))
	for k, v := range data {
		shape[k] = flowIdentity(v)
	}
	c.flat, c.shape, c.env, c.built = flat, shape, env, true
}
