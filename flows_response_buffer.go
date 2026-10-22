//go:build !cli

package main

import (
	"bytes"
	"fmt"
	"net/http"
)

const flowResponseBufferLimit = 1 << 20

// flowResponseBuffer keeps transactional HTTP output private until commit.
type flowResponseBuffer struct {
	header http.Header
	body   bytes.Buffer
	status int
	err    error
}

func newFlowResponseBuffer() *flowResponseBuffer {
	return &flowResponseBuffer{header: make(http.Header)}
}

func (b *flowResponseBuffer) Header() http.Header { return b.header }

func (b *flowResponseBuffer) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *flowResponseBuffer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	if b.err != nil {
		return 0, b.err
	}
	if b.body.Len()+len(p) > flowResponseBufferLimit {
		b.err = fmt.Errorf("transactional flow response exceeds %d bytes", flowResponseBufferLimit)
		return 0, b.err
	}
	return b.body.Write(p)
}

func (b *flowResponseBuffer) flushTo(w http.ResponseWriter) {
	for key, values := range b.header {
		if key == "Vary" {
			// A respond step's Vary adds to the one the framework set
			// before the flow ran (CORS: Origin), as it does unbuffered.
			w.Header()[key] = append(w.Header()[key], values...)
			continue
		}
		w.Header()[key] = append([]string(nil), values...)
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}

func flowHasPurgeCurrentUser(steps []FlowStep) bool {
	for _, step := range steps {
		if step.Type == "purge_current_user" || flowHasPurgeCurrentUser(step.Steps) || flowHasPurgeCurrentUser(step.ElseSteps) || flowHasPurgeCurrentUser(step.OnError) {
			return true
		}
	}
	return false
}

// flowValidateTransactionalResponse rejects steps that stream bytes directly
// from a file, which cannot be safely held until a transaction commits.
func flowValidateTransactionalResponse(flow *Flow) error {
	if flow == nil || !flow.Transaction || flow.Trigger.Type != "http" {
		return nil
	}
	var walk func([]FlowStep) error
	walk = func(steps []FlowStep) error {
		for _, step := range steps {
			if step.Type == "serve_file" {
				return fmt.Errorf("flow %q: serve_file cannot be used in a transactional HTTP flow because responses are buffered until commit", flow.Name)
			}
			for _, nested := range [][]FlowStep{step.Steps, step.ElseSteps, step.OnError} {
				if err := walk(nested); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(flow.Steps)
}
