//go:build !cli

package main

// Nesting bounds for `run: compute`.
//
// goja's built-ins that walk a nested value do it by recursing in Go, and a
// Go stack overflow is fatal to the whole process: it cannot be recovered,
// and neither the JS call-stack cap (SetMaxCallStackSize) nor vm.Interrupt
// applies inside a native call. A script that builds a structure millions of
// levels deep (`for (...) a = [a]`) and then returns it, or hands it to
// JSON.stringify, String()/join or flat(Infinity), therefore crashed the app
// process instead of failing its step. The bounds here keep every one of
// those walks at most computeMaxNesting levels deep:
//
//   - the args handed to the function and the value it returns are measured
//     (without recursion) before goja converts them;
//   - JSON.stringify measures its argument the same way;
//   - Array.prototype.join / toString / toLocaleString are re-entered through
//     a counting wrapper at every level of nesting;
//   - Array.prototype.flat never recurses deeper than the bound.
//
// A value past the bound is a RangeError in the script (catchable) or a
// failed step, never a crash. runComputeInVM also recovers a panic from the
// conversion itself (a getter that throws while the result is exported).
//
// RESIDUAL: this bounds the built-ins that recurse over plain arrays and
// objects. Other native walks over structures a script builds on purpose
// (millions of nested Proxy or bound-function layers, deeply nested Map/Set
// values on export) and memory exhaustion (goja has no heap cap) can still
// end the process; only running compute in its own process removes those.

import (
	"fmt"
	"reflect"

	"github.com/dop251/goja"
)

// computeMaxNesting is the deepest array/object nesting a compute call may
// take in, return, or pass to a recursive built-in. Go's JSON decoder stops
// at the same depth, so no value that arrived as JSON is affected.
const computeMaxNesting = 10000

// computeGoNestingNodes bounds the walk of a Go value that is not a tree.
const computeGoNestingNodes = 16 << 20

// computeNestingExceeds reports whether v holds a chain of nested arrays /
// plain objects longer than limit. It walks depth-first with an explicit
// stack (no Go recursion) and remembers each finished object's height, so a
// value shared by several parents is walked once and still counts along the
// longest path. Property reads can run script getters and Proxy traps: call
// it inside the VM (or under Runtime.Try).
func computeNestingExceeds(v goja.Value, limit int) bool {
	root, ok := v.(*goja.Object)
	if !ok || root == nil || !computeNestedContainer(root) {
		return false
	}
	type frame struct {
		obj    *goja.Object
		keys   []string
		next   int
		height int // longest finished chain below obj
	}
	const inProgress = -1
	heights := map[*goja.Object]int{root: inProgress}
	stack := []frame{{obj: root, keys: root.Keys()}}
	for len(stack) > 0 {
		if len(stack) > limit {
			return true
		}
		top := &stack[len(stack)-1]
		if top.next >= len(top.keys) {
			h := top.height + 1
			heights[top.obj] = h
			stack = stack[:len(stack)-1]
			if len(stack) > 0 {
				if parent := &stack[len(stack)-1]; h > parent.height {
					parent.height = h
				}
			}
			continue
		}
		key := top.keys[top.next]
		top.next++
		child, ok := top.obj.Get(key).(*goja.Object)
		if !ok || child == nil || !computeNestedContainer(child) {
			continue
		}
		if h, seen := heights[child]; seen {
			if h == inProgress {
				continue // a cycle: the built-ins detect it themselves
			}
			if len(stack)+h > limit {
				return true
			}
			if h > top.height {
				top.height = h
			}
			continue
		}
		heights[child] = inProgress
		stack = append(stack, frame{obj: child, keys: child.Keys()})
	}
	return false
}

// computeNestedContainer reports an object the recursive built-ins descend
// into: arrays and plain objects (including Go maps and slices goja wraps).
func computeNestedContainer(o *goja.Object) bool {
	if _, callable := goja.AssertFunction(o); callable {
		return false
	}
	switch o.ClassName() {
	case "Array", "Object":
		return true
	}
	return false
}

// computeGoNestingExceeds is computeNestingExceeds for the Go value passed
// into a compute call (maps, slices, pointers and interfaces). A cyclic
// value reads as infinitely deep.
func computeGoNestingExceeds(v any, limit int) bool {
	type frame struct {
		val   reflect.Value
		depth int
	}
	stack := []frame{{reflect.ValueOf(v), 0}}
	visited := 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited++; visited > computeGoNestingNodes {
			return true
		}
		val := f.val
		for val.IsValid() && (val.Kind() == reflect.Interface || val.Kind() == reflect.Pointer) {
			if val.IsNil() {
				break
			}
			val = val.Elem()
		}
		if !val.IsValid() {
			continue
		}
		switch val.Kind() {
		case reflect.Map:
			if f.depth+1 > limit {
				return true
			}
			iter := val.MapRange()
			for iter.Next() {
				if computeGoMayNest(iter.Value()) {
					stack = append(stack, frame{iter.Value(), f.depth + 1})
				}
			}
		case reflect.Slice, reflect.Array:
			if val.Type().Elem().Kind() == reflect.Uint8 {
				continue
			}
			if f.depth+1 > limit {
				return true
			}
			for i := 0; i < val.Len(); i++ {
				if computeGoMayNest(val.Index(i)) {
					stack = append(stack, frame{val.Index(i), f.depth + 1})
				}
			}
		case reflect.Struct:
			if f.depth+1 > limit {
				return true
			}
			for i := 0; i < val.NumField(); i++ {
				if computeGoMayNest(val.Field(i)) {
					stack = append(stack, frame{val.Field(i), f.depth + 1})
				}
			}
		}
	}
	return false
}

// computeGoMayNest reports a Go value that can hold further values.
func computeGoMayNest(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer, reflect.Map, reflect.Slice, reflect.Array, reflect.Struct:
		return true
	}
	return false
}

// computeHardenJS guards the two built-ins that recurse internally over a
// nested value: JSON.stringify measures its argument first (`tooDeep` is
// computeNestingExceeds bound to the limit), and flat(), asked for more than
// LIMIT levels, flattens LIMIT and refuses a result that is still nested.
// A toJSON or replacer that keeps producing new objects is script code on
// every level, so the step timeout interrupts it.
const computeHardenJS = `(function (tooDeep, LIMIT) {
  var proto = Array.prototype;
  var nativeFlat = proto.flat;
  if (typeof nativeFlat === 'function') {
    Object.defineProperty(proto, 'flat', {
      value: function (levels) {
        if (levels === undefined || !(Number(levels) > LIMIT)) return nativeFlat.apply(this, arguments);
        var out = nativeFlat.call(this, LIMIT);
        if (out.some(Array.isArray)) throw new RangeError('flat: array nested more than ' + LIMIT + ' levels deep');
        return out;
      },
      writable: true, enumerable: false, configurable: true
    });
  }

  var nativeStringify = JSON.stringify;
  Object.defineProperty(JSON, 'stringify', {
    value: function (value) {
      if (tooDeep(value)) throw new RangeError('JSON.stringify: value nested more than ' + LIMIT + ' levels deep');
      return nativeStringify.apply(JSON, arguments);
    },
    writable: true, enumerable: false, configurable: true
  });
})`

var computeHardenProgram = goja.MustCompile("benmore:compute-harden", computeHardenJS, true)

// hardenComputeBuiltins bounds the built-ins that recurse natively over
// nested arrays and objects. It runs once per VM, before the module.
//
// Array.prototype.join / toString / toLocaleString convert each element with
// ToString, which for a nested array looks the method up on the prototype
// again: the wrappers below are therefore re-entered once per level of
// nesting and count it. They are Go functions, not script, so they add no JS
// frame and arrays up to the bound convert exactly as before.
func hardenComputeBuiltins(vm *goja.Runtime) error {
	rangeError, ok := goja.AssertConstructor(vm.Get("RangeError"))
	if !ok {
		return fmt.Errorf("compute: hardening built-ins: RangeError is not a constructor")
	}
	throwRange := func(msg string) {
		obj, err := rangeError(nil, vm.ToValue(msg))
		if err != nil {
			panic(vm.NewTypeError(msg))
		}
		panic(obj)
	}
	arrayProto := vm.Get("Array").ToObject(vm).Get("prototype").ToObject(vm)
	for _, name := range []string{"join", "toString", "toLocaleString"} {
		native, ok := goja.AssertFunction(arrayProto.Get(name))
		if !ok {
			continue
		}
		depth := 0 // per method: toString and join are both entered at each level
		wrapper := func(call goja.FunctionCall) goja.Value {
			if depth >= computeMaxNesting {
				throwRange(fmt.Sprintf("array nested more than %d levels deep", computeMaxNesting))
			}
			depth++
			defer func() { depth-- }()
			v, err := native(call.This, call.Arguments...)
			if err != nil {
				panic(err) // a script exception, an interrupt: rethrown as is
			}
			return v
		}
		if err := arrayProto.DefineDataProperty(name, vm.ToValue(wrapper), goja.FLAG_TRUE, goja.FLAG_TRUE, goja.FLAG_FALSE); err != nil {
			return fmt.Errorf("compute: hardening built-ins: %w", err)
		}
	}

	install, err := vm.RunProgram(computeHardenProgram)
	if err != nil {
		return fmt.Errorf("compute: hardening built-ins: %w", err)
	}
	call, ok := goja.AssertFunction(install)
	if !ok {
		return fmt.Errorf("compute: hardening built-ins: installer is not a function")
	}
	tooDeep := func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(computeNestingExceeds(call.Argument(0), computeMaxNesting))
	}
	if _, err := call(goja.Undefined(), vm.ToValue(tooDeep), vm.ToValue(computeMaxNesting)); err != nil {
		return fmt.Errorf("compute: hardening built-ins: %w", err)
	}
	return nil
}
