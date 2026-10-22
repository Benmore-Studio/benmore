//go:build !cli

package main

import "sync"

// workerStopGeneration snapshots the current generation before an untracked
// worker is spawned. A delayed goroutine must not join a later reload's channel.
// Callers must not hold app.mu. Nil/closed channels retain their existing meaning;
// this does not initialize a generation or change shutdown tracking/draining.
func (app *App) workerStopGeneration() <-chan struct{} {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.Stop
}

// startWorker captures the current stop generation before spawning. Shutdown
// waits for this work before closing SQLite; reload closes the old generation.
// The returned completion channel is useful when a caller must await one task.
func (app *App) startWorker(name string, fn func(<-chan struct{})) <-chan struct{} {
	return app.startTrackedWorker(&app.workerWG, name, fn)
}

// startJobRunner is startWorker for workers that run app code of unbounded
// length; Shutdown waits for them only up to jobDrainTimeout (see App.jobWG).
func (app *App) startJobRunner(name string, fn func(<-chan struct{})) <-chan struct{} {
	return app.startTrackedWorker(&app.jobWG, name, fn)
}

func (app *App) startTrackedWorker(wg *sync.WaitGroup, name string, fn func(<-chan struct{})) <-chan struct{} {
	done := make(chan struct{})
	app.workerMu.Lock()
	if app.shuttingDown {
		app.workerMu.Unlock()
		close(done)
		return done
	}
	app.mu.Lock()
	if app.Stop == nil {
		app.Stop = make(chan struct{})
	}
	stop := app.Stop
	app.mu.Unlock()
	wg.Add(1)
	app.workerMu.Unlock()
	safeGo(name, func() {
		defer wg.Done()
		defer close(done)
		fn(stop)
	})
	return done
}
