//go:build !cli

package main

import (
	"testing"

	"github.com/dop251/goja"
)

// The layout appends DefaultJS after the page's own script. It must not
// replace a helper the page already defined (the workspace's div modals broke
// with "d.close is not a function"), and its own modal helpers must tolerate
// a non-<dialog> element.
func TestDefaultJSKeepsPageDefinedHelpers(t *testing.T) {
	vm := goja.New()
	if _, err := vm.RunString(`
var window = this, classes = {};
var document = {
  addEventListener: function() {},
  querySelector: function() { return null; },
  getElementById: function(id) { return { classList: { remove: function(c) { classes[id] = 'removed ' + c; }, add: function() {} } }; }
};
function closeModal(id) { return 'page:' + id; }
`); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(DefaultJS); err != nil {
		t.Fatalf("DefaultJS failed: %v", err)
	}
	if got := vm.Get("closeModal").Export(); got == nil {
		t.Fatal("closeModal missing")
	}
	v, err := vm.RunString(`closeModal('publish-modal')`)
	if err != nil || v.String() != "page:publish-modal" {
		t.Fatalf("page closeModal was replaced: %v %v", v, err)
	}
	for _, name := range []string{"openModal", "switchTab", "showToast", "filterTable", "sortTable", "toggleAccordion"} {
		if fn, ok := goja.AssertFunction(vm.Get(name)); !ok || fn == nil {
			t.Errorf("DefaultJS no longer provides %s", name)
		}
	}
	if _, err := vm.RunString(`openModal('div-modal'); window.__opened = true`); err != nil {
		t.Fatalf("openModal threw on a non-dialog element: %v", err)
	}
}
