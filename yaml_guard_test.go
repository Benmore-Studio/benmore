package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func flatYAML(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "k%d: v\n", i)
	}
	return b.String()
}

// yaml.v3 decodes a mapping in time quadratic in its key count. 150,000 keys
// fit in a 1.7 MB file and take over 20 s to decode.
func TestYAMLGuardRefusesQuadraticMappingsQuickly(t *testing.T) {
	doc := flatYAML(150_000)
	start := time.Now()
	var out map[string]any
	err := yamlUnmarshal([]byte(doc), &out)
	if err == nil {
		t.Fatal("pathological mapping was decoded")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("guard took %v; it must be linear", took)
	}
}

// The router runs this on every write_file/edit_file of app.yaml, flows, cron
// and the rest. Before the guard a 1.7 MB app.yaml held the request for >20 s.
func TestValidateOnWriteBoundsPathologicalYAML(t *testing.T) {
	doc := flatYAML(150_000)
	for _, path := range []string{"app.yaml", "flows/a.yaml", "cron.yaml", "hooks.yaml", "env.yaml"} {
		start := time.Now()
		msg := ValidateOnWriteIn(t.TempDir(), path, doc)
		took := time.Since(start)
		if !strings.Contains(msg, "too many keys") || !strings.Contains(msg, writeRejectionFooter) {
			t.Errorf("%s: missing resource refusal or recovery guidance: %q", path, msg)
		}
		t.Logf("%s: validation took %v", path, took)
		if took > 5*time.Second {
			t.Errorf("%s: validation took %v", path, took)
		}
	}
}

func TestYAMLGuardRefusesManyMediumMappings(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "m%d:\n", i)
		for j := 0; j < 2000; j++ {
			fmt.Fprintf(&b, "  k%d: v\n", j)
		}
	}
	var out map[string]any
	if err := yamlUnmarshal([]byte(b.String()), &out); err == nil {
		t.Fatal("summed quadratic cost across mappings was not bounded")
	}
}

func TestYAMLGuardAcceptsRealisticLargeInputs(t *testing.T) {
	var out map[string]string
	if err := yamlUnmarshal([]byte(flatYAML(10_000)), &out); err != nil || len(out) != 10_000 {
		t.Fatalf("a 10,000-key translation file must load: %v (%d keys)", err, len(out))
	}
	var multi []map[string]any
	if err := yamlUnmarshal([]byte("- a: 1\n- b: [1, 2, 3]\n"), &multi); err != nil || len(multi) != 2 {
		t.Fatalf("ordinary document: %v %v", err, multi)
	}
}

func TestYAMLGuardDoesNotExpandAliasesAndKeepsSyntaxErrors(t *testing.T) {
	laughs := "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
	if err := checkYAMLShape([]byte(laughs)); err != nil {
		t.Fatalf("alias document rejected by the shape guard: %v", err)
	}
	var out map[string]any
	if err := yamlUnmarshal([]byte("a: [unclosed"), &out); err == nil {
		t.Fatal("syntax error not reported")
	}
}

func TestYAMLGuardChecksEveryDocumentAndSize(t *testing.T) {
	if err := checkYAMLShape([]byte("a: 1\n---\n" + flatYAML(150_000))); err == nil {
		t.Error("second document escaped the guard")
	}
	if err := checkYAMLShape([]byte(strings.Repeat("# c\n", yamlMaxBytes/4+1))); err == nil {
		t.Error("oversized document accepted")
	}
}
