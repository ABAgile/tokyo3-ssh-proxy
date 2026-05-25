package recording_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
)

// fakeClock returns a func suitable for [recording.Recorder.now] that
// advances by step each time it's called.
func fakeClock(start time.Time, step time.Duration) func() time.Time {
	t := start
	return func() time.Time {
		t = t.Add(step)
		return t
	}
}

func TestNew_RejectsBadArgs(t *testing.T) {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

	t.Run("nil dest", func(t *testing.T) {
		_, err := recording.New(nil, 80, 24, "x", now)
		if err == nil || !strings.Contains(err.Error(), "dest is required") {
			t.Errorf("err = %v, want 'dest is required'", err)
		}
	})
	t.Run("zero width", func(t *testing.T) {
		_, err := recording.New(&bytes.Buffer{}, 0, 24, "x", now)
		if err == nil || !strings.Contains(err.Error(), "invalid dimensions") {
			t.Errorf("err = %v, want 'invalid dimensions'", err)
		}
	})
	t.Run("negative height", func(t *testing.T) {
		_, err := recording.New(&bytes.Buffer{}, 80, -1, "x", now)
		if err == nil || !strings.Contains(err.Error(), "invalid dimensions") {
			t.Errorf("err = %v, want 'invalid dimensions'", err)
		}
	})
}

func TestRecorder_HeaderShape(t *testing.T) {
	var buf bytes.Buffer
	started := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

	_, err := recording.New(&buf, 100, 40, "alice@db-1", started)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lines := strings.SplitN(buf.String(), "\n", 2)
	var hdr struct {
		Version   int    `json:"version"`
		Width     int    `json:"width"`
		Height    int    `json:"height"`
		Timestamp int64  `json:"timestamp"`
		Title     string `json:"title"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatalf("decode header: %v; raw=%q", err, lines[0])
	}
	if hdr.Version != 2 {
		t.Errorf("version = %d, want 2", hdr.Version)
	}
	if hdr.Width != 100 || hdr.Height != 40 {
		t.Errorf("dims = %dx%d, want 100x40", hdr.Width, hdr.Height)
	}
	if hdr.Title != "alice@db-1" {
		t.Errorf("title = %q", hdr.Title)
	}
	if hdr.Timestamp != started.Unix() {
		t.Errorf("timestamp = %d, want %d", hdr.Timestamp, started.Unix())
	}
}

func TestRecorder_OutputEventsHaveElapsedTime(t *testing.T) {
	var buf bytes.Buffer
	started := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	r, err := recording.New(&buf, 80, 24, "", started)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Override the clock so each event records a deterministic
	// 0.5-second delta. New takes a "started" baseline; the clock
	// is overridden after construction via the package's test seam.
	overrideClock(r, fakeClock(started, 500*time.Millisecond))

	r.Output([]byte("hello"))
	r.Output([]byte("world"))

	// Skip the header line; the remaining lines are events.
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 (header + 2 events); buf=%q", len(lines), buf.String())
	}
	var ev1 [3]any
	if err := json.Unmarshal([]byte(lines[1]), &ev1); err != nil {
		t.Fatalf("decode event 1: %v; raw=%s", err, lines[1])
	}
	if ev1[0].(float64) != 0.5 {
		t.Errorf("event 1 elapsed = %v, want 0.5", ev1[0])
	}
	if ev1[1].(string) != "o" {
		t.Errorf("event 1 kind = %v, want o", ev1[1])
	}
	if ev1[2].(string) != "hello" {
		t.Errorf("event 1 payload = %v, want hello", ev1[2])
	}
	var ev2 [3]any
	_ = json.Unmarshal([]byte(lines[2]), &ev2)
	if ev2[0].(float64) != 1.0 {
		t.Errorf("event 2 elapsed = %v, want 1.0", ev2[0])
	}
}

func TestRecorder_OutputEmptyIgnored(t *testing.T) {
	var buf bytes.Buffer
	r, _ := recording.New(&buf, 80, 24, "", time.Now())
	before := buf.Len()
	r.Output(nil)
	r.Output([]byte{})
	if buf.Len() != before {
		t.Errorf("empty Output wrote %d bytes", buf.Len()-before)
	}
}

func TestRecorder_ResizeEvent(t *testing.T) {
	var buf bytes.Buffer
	started := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	r, _ := recording.New(&buf, 80, 24, "", started)
	overrideClock(r, fakeClock(started, 250*time.Millisecond))

	r.Resize(120, 36)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	var ev [3]any
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev[1].(string) != "r" {
		t.Errorf("kind = %v, want r", ev[1])
	}
	if ev[2].(string) != "120x36" {
		t.Errorf("payload = %v, want 120x36", ev[2])
	}
}

func TestRecorder_ResizeRejectsBadDims(t *testing.T) {
	var buf bytes.Buffer
	r, _ := recording.New(&buf, 80, 24, "", time.Now())
	before := buf.Len()
	r.Resize(0, 24)
	r.Resize(80, -1)
	if buf.Len() != before {
		t.Errorf("invalid resize wrote %d bytes", buf.Len()-before)
	}
}

func TestRecorder_CloseStopsWrites(t *testing.T) {
	var buf bytes.Buffer
	r, _ := recording.New(&buf, 80, 24, "", time.Now())
	before := buf.Len()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r.Output([]byte("nope"))
	r.Resize(120, 40)
	if buf.Len() != before {
		t.Errorf("post-close write produced %d bytes", buf.Len()-before)
	}
	// Idempotent.
	if err := r.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// overrideClock is a test-only seam. The Recorder's clock field is
// unexported but accessible via this helper in the same package
// (recording_test, but using the exported helper below).
func overrideClock(r *recording.Recorder, now func() time.Time) {
	recording.SetClock(r, now)
}
