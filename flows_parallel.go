//go:build !cli

package main

import (
	"fmt"
	"maps"
	"reflect"
	"strings"
	"sync"
)

// A parallel branch receives its own execution state. App and the captured actor
// are immutable here; Writes is explicitly concurrency-safe and must retain
// durable writes even when another branch fails. Mutexes/caches are never copied.
func newParallelFlowContext(parent *FlowContext) *FlowContext {
	child := &FlowContext{
		App: parent.App, Request: parent.Request, Writer: parent.Writer,
		Session: parent.Session, apiClient: parent.apiClient, privateResponse: parent.privateResponse,
		Data: cloneComputeArg(parent.Data).(map[string]any), Params: maps.Clone(parent.Params),
		RequestKeys: maps.Clone(parent.RequestKeys), SecretKeys: maps.Clone(parent.SecretKeys),
		NullParams: maps.Clone(parent.NullParams), requestStepSources: maps.Clone(parent.requestStepSources),
		Tx: parent.Tx, Writes: parent.Writes, mcpReadConn: parent.mcpReadConn, mcpReadKey: parent.mcpReadKey,
		command: parent.command, parallelOutputs: make(map[string]bool), parallelTxMu: parent.transactionMutex(),
		reachedSteps: maps.Clone(parent.reachedSteps),
	}
	if child.Data == nil {
		child.Data = make(map[string]any)
	}
	if child.Params == nil {
		child.Params = make(map[string]string)
	}
	if parent.lazyShadow != nil {
		child.lazyShadow = &flowLazyShadow{pending: maps.Clone(parent.lazyShadow.pending)}
	}
	return child
}

func (ctx *FlowContext) transactionMutex() *sync.Mutex {
	if ctx.parallelTxMu != nil {
		return ctx.parallelTxMu
	}
	return &ctx.TxMu
}

// Remember actual output assignments as well as value differences. A later
// branch setting an existing key back to its input value still owns that output.
func (ctx *FlowContext) noteParallelOutputs(step *FlowStep) {
	if ctx.parallelOutputs == nil {
		return
	}
	switch step.Type {
	case "parallel", "if", "for_each":
		return // nested steps and each actual loop assignment record outputs
	default:
		ctx.markParallelOutput(step.Name)
		if step.Type == "set" {
			for name := range step.Set {
				ctx.markParallelOutput(name)
			}
		}
	}
}

func (ctx *FlowContext) markParallelOutput(name string) {
	if ctx.parallelOutputs == nil || name == "" {
		return
	}
	for key := range ctx.Data {
		if key == name || strings.HasPrefix(key, name+".") {
			ctx.parallelOutputs[key] = true
		}
	}
}

// Apply only this branch's changes against the common input, so an unchanged
// input key in a later branch cannot undo an earlier branch's output.
func mergeParallelMap[V any](dst, before, after map[string]V, assigned map[string]bool) (map[string]V, map[string]bool) {
	if dst == nil {
		dst = make(map[string]V)
	}
	changed := make(map[string]bool)
	for key, old := range before {
		value, exists := after[key]
		if !exists {
			delete(dst, key)
			changed[key] = true
		} else if assigned[key] || !reflect.DeepEqual(old, value) {
			dst[key] = value
			changed[key] = true
		}
	}
	for key, value := range after {
		if _, exists := before[key]; !exists {
			dst[key] = value
			changed[key] = true
		}
	}
	return dst, changed
}

func mergeParallelFlowContext(parent, before, child *FlowContext) {
	for name := range child.reachedSteps {
		if parent.reachedSteps == nil {
			parent.reachedSteps = make(map[string]bool)
		}
		parent.reachedSteps[name] = true
	}
	// Assigning a whole output replaces its flattened namespace too. Some
	// descendants may have been introduced only by an earlier sibling, so
	// comparing against the common input alone cannot find their removals.
	cleared := make(map[string]bool)
	for key := range parent.Data {
		for i := 0; i < len(key); i++ {
			if key[i] == '.' && child.parallelOutputs[key[:i]] {
				delete(parent.Data, key)
				cleared[key] = true
				break
			}
		}
	}
	var changed map[string]bool
	parent.Data, changed = mergeParallelMap(parent.Data, before.Data, child.Data, child.parallelOutputs)
	for key := range cleared {
		changed[key] = true
	}
	parent.Params, _ = mergeParallelMap(parent.Params, before.Params, child.Params, nil)
	parent.NullParams, _ = mergeParallelMap(parent.NullParams, before.NullParams, child.NullParams, nil)
	parent.requestStepSources, _ = mergeParallelMap(parent.requestStepSources, before.requestStepSources, child.requestStepSources, nil)
	// Provenance must come from the branch whose value won the merge; otherwise
	// a sibling's authored URL could certify a different request-derived value.
	for key := range changed {
		if source, exists := child.requestStepSources[key]; exists {
			parent.requestStepSources[key] = source
		} else {
			delete(parent.requestStepSources, key)
		}
		if parent.parallelOutputs != nil {
			parent.parallelOutputs[key] = true
		}
	}
	for key, tainted := range child.RequestKeys {
		if tainted {
			parent.markTainted(key)
		}
	}
	for key, secret := range child.SecretKeys {
		if secret {
			parent.markSecret(key)
		}
	}
	if parent.lazyShadow != nil && child.lazyShadow != nil {
		for key := range parent.lazyShadow.pending {
			if !child.lazyShadow.pending[key] {
				delete(parent.lazyShadow.pending, key)
			}
		}
	}
	parent.privateResponse = parent.privateResponse || child.privateResponse
}

// Independent branches cannot consume one HTTP request body or write one HTTP
// response. Refuse these shapes before starting any sibling, including nested
// control steps and handlers. Direct children's retry/on_error stay ignored,
// matching the established parallel dispatch contract.
func flowValidateParallelHTTP(flow *Flow) error {
	if flow == nil {
		return nil
	}
	var walk func([]FlowStep, bool, bool) error
	walk = func(steps []FlowStep, inside, direct bool) error {
		for _, step := range steps {
			if inside && (step.Type == "respond" || step.Type == "redirect" || step.Type == "serve_file" || step.Type == "parse" && step.Parse == "body") {
				return fmt.Errorf("parallel: %s step %s shares the HTTP request or response; move it before or after the parallel block", step.Type, quoteForHint(step.Name))
			}
			if err := walk(step.Steps, inside || step.Type == "parallel", step.Type == "parallel"); err != nil {
				return err
			}
			if err := walk(step.ElseSteps, inside, false); err != nil {
				return err
			}
			if !direct {
				if err := walk(step.OnError, inside, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(flow.Steps, false, false)
}
