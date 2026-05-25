// Package recording captures the PTY traffic flowing through one SSH
// session into an asciinema v2 cast file, which lets the certd portal
// (and asciinema-player elsewhere) replay the session bit-for-bit
// including escape sequences, colours, and resize events.
//
// asciinema v2 format:
//
//	{"version":2,"width":80,"height":24,"timestamp":1234567890,"title":"…"}
//	[0.123, "o", "data"]
//	[1.234, "r", "100x40"]
//	…
//
// Line 1 is a JSON header; subsequent lines are JSON arrays with
// elapsed seconds since session start, an event-type tag, and the
// data payload. The format is line-delimited (NDJSON) so a recording
// can be streamed and tail-replayed.
//
// This package owns format + persistence; the proxy session handler
// wires it up by tee'ing target→user data into [Recorder.Output] and
// forwarding window-change requests to [Recorder.Resize].
package recording

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// EventType tags each line in the asciinema cast. The format
// recognises "i" (input from user), "o" (output from target), and
// "r" (resize); ssh-proxyd records "o" + "r" by default — user input
// is omitted to keep audit recordings free of passwords typed into
// `sudo` prompts and similar.
type EventType string

const (
	EventOutput EventType = "o"
	EventResize EventType = "r"
)

// Header is the first line of an asciinema cast. Field tags match the
// format spec; absent fields default to the asciinema-player's
// defaults at replay time.
type Header struct {
	Version   int    `json:"version"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Title     string `json:"title,omitempty"`
	Idle      *struct {
		// asciinema v2 supports an idle_time_limit; certd's portal
		// can apply this at replay time, so we leave the field
		// unused here.
	} `json:"-"`
}

// Recorder buffers asciinema events for one session and persists the
// completed cast via [Sink] on [Close]. Safe for concurrent reads but
// each Output / Resize call must be serialized by the caller (the
// session-handler goroutines naturally provide this since one PTY
// stream flows through one io.Copy).
type Recorder struct {
	header  Header
	started time.Time
	now     func() time.Time // overridable for tests
	encoded io.Writer        // buffer being written to
	mu      sync.Mutex
	closed  bool
}

// New starts a recording. width / height are the initial terminal
// dimensions from the pty-req; title is shown in the asciinema
// player chrome. now is the session start; subsequent events record
// elapsed time relative to it.
//
// dest is the destination the cast is written to as it grows. For
// tests pass a bytes.Buffer; for production wire the Sink so dest is
// a file or remote upload stream.
func New(dest io.Writer, width, height int, title string, started time.Time) (*Recorder, error) {
	if dest == nil {
		return nil, errors.New("dest is required")
	}
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("invalid dimensions %dx%d", width, height)
	}
	r := &Recorder{
		header: Header{
			Version:   2,
			Width:     width,
			Height:    height,
			Timestamp: started.Unix(),
			Title:     title,
		},
		started: started,
		now:     time.Now,
		encoded: dest,
	}
	if err := r.writeHeader(); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}
	return r, nil
}

// writeHeader serialises the first line of the cast. Called once
// from New.
func (r *Recorder) writeHeader() error {
	b, err := json.Marshal(r.header)
	if err != nil {
		return err
	}
	if _, err := r.encoded.Write(b); err != nil {
		return err
	}
	_, err = r.encoded.Write([]byte("\n"))
	return err
}

// Output appends an "o" event for bytes the target sent to the user.
// Returns immediately on already-closed; never returns an error
// up the io chain (the session handler treats audit/recording as
// observational, not session-blocking).
func (r *Recorder) Output(p []byte) {
	if len(p) == 0 {
		return
	}
	_ = r.writeEvent(EventOutput, string(p))
}

// Resize appends an "r" event for a window-change. Width and height
// are in character cells; the player switches to the new dimensions
// at replay time.
func (r *Recorder) Resize(width, height int) {
	if width <= 0 || height <= 0 {
		return
	}
	_ = r.writeEvent(EventResize, fmt.Sprintf("%dx%d", width, height))
}

// writeEvent appends a single event line.
func (r *Recorder) writeEvent(kind EventType, payload string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	elapsed := r.now().Sub(r.started).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	// asciinema events are [elapsed, kind, payload] JSON arrays.
	arr := []any{round6(elapsed), string(kind), payload}
	b, err := json.Marshal(arr)
	if err != nil {
		return err
	}
	if _, err := r.encoded.Write(b); err != nil {
		return err
	}
	_, err = r.encoded.Write([]byte("\n"))
	return err
}

// Close marks the recording done. Subsequent Output / Resize calls
// are no-ops. Safe to call multiple times.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// round6 trims the elapsed-seconds float to 6 decimal places (about
// 1 microsecond), matching what the asciinema reference recorder
// emits. Without trimming, Go's default JSON marshal can produce
// 17-digit floats that bloat the file and confuse some replayers.
func round6(v float64) float64 {
	const mult = 1e6
	return float64(int64(v*mult+0.5)) / mult
}
