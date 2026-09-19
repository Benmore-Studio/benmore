//go:build !cli

package main

// startWorker captures the current stop generation before spawning. Shutdown
// waits for this work before closing SQLite; reload closes the old generation.
// The returned completion channel is useful when a caller must await one task.
func (app *App) startWorker(name string, fn func(<-chan struct{})) <-chan struct{} {
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
	app.workerWG.Add(1)
	app.workerMu.Unlock()
	safeGo(name, func() {
		defer app.workerWG.Done()
		defer close(done)
		fn(stop)
	})
	return done
}
