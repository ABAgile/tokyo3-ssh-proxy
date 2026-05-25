package recording

import "time"

// SetClock overrides a Recorder's clock for tests. Lets tests inject
// a deterministic "now" so event timestamps are reproducible. Not
// exported in production code — only via this _test.go file.
func SetClock(r *Recorder, now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}
