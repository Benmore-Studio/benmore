//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The generated health_fast test bounds the FASTEST of a few requests, so one
// slow scheduling moment on a busy machine cannot fail a correct app
// (TestGeneratedTestsTreatAppOwnedPageRoutesAsExpected failed that way under
// the race detector: one request took 34 ms). These tests pin the other half:
// the bound still means something.

// timedTestServer answers GET /health with status after sleeping what delay
// returns for the request's number (1 for the first), and counts requests.
func timedTestServer(t *testing.T, status int, delay func(n int32) time.Duration) (base string, requests *atomic.Int32) {
	t.Helper()
	requests = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay(requests.Add(1)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, requests
}

func generatedHealthFastStep(t *testing.T) AppTestStep {
	t.Helper()
	tc, ok := generatePerformanceTests(&App{}).Tests["health_fast"]
	if !ok || len(tc.Steps) != 1 || !tc.Anon {
		t.Fatalf("health_fast must be one anonymous step, got %+v", tc)
	}
	step := tc.Steps[0]
	if step.Get != "/health" || step.Expect.Status != http.StatusOK || step.Expect.MaxDuration != "10ms" {
		t.Fatalf("health_fast must still ask for GET /health, 200, within 10ms: %+v", step)
	}
	if step.DurationAttempts != healthFastAttempts || healthFastAttempts < 2 {
		t.Fatalf("health_fast must be measured over several requests, got %d", step.DurationAttempts)
	}
	return step
}

// A /health that takes 50 ms on every request is slow, however often it is
// asked: the generated test fails, and says what each request took.
func TestGeneratedHealthFastFailsAHandlerThatIsSlowOnEveryRequest(t *testing.T) {
	base, requests := timedTestServer(t, http.StatusOK, func(int32) time.Duration { return 50 * time.Millisecond })
	result, _ := executeTestStepRaw(nil, base, http.DefaultClient, nil, "", true, generatedHealthFastStep(t))
	if result.Pass {
		t.Fatalf("a /health that sleeps 50ms on every request passed a 10ms bound: %+v", result)
	}
	if got := requests.Load(); got != healthFastAttempts {
		t.Errorf("the step must use every attempt before it fails: %d requests, want %d", got, healthFastAttempts)
	}
	msg := result.Message
	times, rest, found := strings.Cut(strings.TrimPrefix(msg, "Took "), " in ")
	if !found || !strings.HasPrefix(msg, "Took ") || !strings.HasSuffix(rest, "max allowed 10ms") {
		t.Fatalf("the failure must list the times and the bound, got %q", msg)
	}
	listed := strings.Split(times, ", ")
	if len(listed) != healthFastAttempts {
		t.Fatalf("the failure must report every request's time (%d), got %q", healthFastAttempts, msg)
	}
	for _, s := range listed {
		if d, err := time.ParseDuration(s); err != nil || d < 50*time.Millisecond {
			t.Errorf("reported time %q is not a time of a 50ms request (%v): %q", s, err, msg)
		}
	}
}

// The step passes at the first request within the bound and sends no more;
// a step from a test file (no attempts) is still one request, measured once.
func TestDurationAttemptsStopAtTheFirstRequestWithinTheBound(t *testing.T) {
	// The first two requests are slow, the rest answer at once. The bound is
	// wide so that a loaded machine does not make the fast ones miss it.
	slowTwice := func(n int32) time.Duration {
		if n <= 2 {
			return 450 * time.Millisecond
		}
		return 0
	}
	expect := AppTestExpect{Status: http.StatusOK, MaxDuration: "400ms"}

	base, requests := timedTestServer(t, http.StatusOK, slowTwice)
	result, body := executeTestStepRaw(nil, base, http.DefaultClient, nil, "", true, AppTestStep{Get: "/health", Expect: expect, DurationAttempts: 5})
	if !result.Pass || requests.Load() != 3 {
		t.Errorf("fastest of 5 must pass on the third request: pass=%v requests=%d message=%q", result.Pass, requests.Load(), result.Message)
	}
	if !strings.Contains(string(body), "healthy") {
		t.Errorf("the step must return the body of the request that passed, got %q", body)
	}

	base, requests = timedTestServer(t, http.StatusOK, slowTwice)
	result, _ = executeTestStepRaw(nil, base, http.DefaultClient, nil, "", true, AppTestStep{Get: "/health", Expect: expect})
	if result.Pass || requests.Load() != 1 || !strings.HasPrefix(result.Message, "Took ") || !strings.HasSuffix(result.Message, ", max allowed 400ms") || strings.Contains(result.Message, " in ") {
		t.Errorf("a step without attempts is one request and fails on its time: pass=%v requests=%d message=%q", result.Pass, requests.Load(), result.Message)
	}
}

// Only time is measured again. A wrong answer fails at the first request,
// with the reason for the answer, even when it was also slow.
func TestDurationAttemptsNeverRepeatAWrongAnswer(t *testing.T) {
	base, requests := timedTestServer(t, http.StatusServiceUnavailable, func(int32) time.Duration { return 50 * time.Millisecond })
	result, _ := executeTestStepRaw(nil, base, http.DefaultClient, nil, "", true, generatedHealthFastStep(t))
	if result.Pass || requests.Load() != 1 || !strings.Contains(result.Message, "Expected status 200, got 503") {
		t.Errorf("a 503 must fail on its status after one request: pass=%v requests=%d message=%q", result.Pass, requests.Load(), result.Message)
	}
}

// The attempts are the generator's, not a key of a test file: no spelling of
// it in YAML sets the field, and the strict reader refuses the key.
func TestDurationAttemptsIsNotATestFileKey(t *testing.T) {
	src := "get: /health\nduration_attempts: 5\ndurationattempts: 5\nDurationAttempts: 5\nexpect: {max_duration: 10ms}\n"
	var step AppTestStep
	if err := yaml.Unmarshal([]byte(src), &step); err != nil {
		t.Fatal(err)
	}
	if step.Get != "/health" || step.DurationAttempts != 0 {
		t.Fatalf("a test file must not be able to set the attempts: %+v", step)
	}
	file := []byte("slow:\n  anon: true\n  steps:\n    - get: /health\n      duration_attempts: 5\n      expect: {max_duration: 10ms}\n")
	_, problems, fileProblem := readAppTestFile(file)
	if got := problems["slow"]; fileProblem != "" || len(got) != 1 || got[0].Kind != "unknown_key" || got[0].Key != "duration_attempts" {
		t.Fatalf("the strict reader must refuse `duration_attempts` as a key it does not read, got %+v (%s)", got, fileProblem)
	}
}
