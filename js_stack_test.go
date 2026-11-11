//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestParseJSStack(t *testing.T) {
	for _, stack := range []string{
		"TypeError: broken\n    at crash (https://app.example/static/app.js?v=abc&token=secret:12:34)\n    at async outer (https://app.example/static/app.js?v=abc:2:3)",
		"crash@https://app.example/static/app.js?v=abc&token=secret:12:34\nouter@https://app.example/static/app.js?v=abc:2:3",
	} {
		frames := parseJSStack(stack, "app.example")
		if len(frames) != 2 {
			t.Fatalf("frames: %+v", frames)
		}
		f := frames[1]
		if f.Line != 12 || f.Col != 34 || f.Version != "abc" || !f.InApp || f.Function != "crash" || f.AbsPath != "https://app.example/static/app.js" {
			t.Fatalf("crashing frame: %+v", f)
		}
		if frames[0].Line != 2 {
			t.Fatal("frames not oldest first")
		}
	}
	frames := parseJSStack("Error\n at /static/a.js?v=good:1:2\n@https://foreign.example/static/a.js:3:4\n at eval (eval at test (https://app.example/static/a.js:1:2), <anonymous>:3:4)\n at native\n at https://app.example/static/b.js?v=bad-value:5:6", "app.example")
	if len(frames) != 3 || frames[0].Version != "" || frames[1].InApp || !frames[2].InApp {
		t.Fatalf("special frames: %+v", frames)
	}
	if got := parseJSStack(strings.Repeat(" at /static/a.js:1:2\n", 100), ""); len(got) != 50 {
		t.Fatalf("cap: %d", len(got))
	}
}
