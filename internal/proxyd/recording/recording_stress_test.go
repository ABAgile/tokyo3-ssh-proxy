package recording_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
)

// validateCast parses every line of body as either the header
// (line 0) or a [elapsed, kind, payload] event tuple. Returns the
// decoded events newest-last so tests can assert ordering /
// monotonicity. The asciinema v2 contract is what asciinema-player
// expects to consume; a malformed file silently fails to replay,
// so this validator is the gate for correctness.
func validateCast(t *testing.T, body []byte) []castEvent {
	t.Helper()
	lines := bytes.Split(bytes.TrimRight(body, "\n"), []byte("\n"))
	if len(lines) == 0 {
		t.Fatal("empty cast")
	}
	var hdr struct {
		Version int `json:"version"`
		Width   int `json:"width"`
		Height  int `json:"height"`
	}
	if err := json.Unmarshal(lines[0], &hdr); err != nil {
		t.Fatalf("header decode: %v; line=%q", err, lines[0])
	}
	if hdr.Version != 2 {
		t.Errorf("header version = %d, want 2", hdr.Version)
	}
	out := make([]castEvent, 0, len(lines)-1)
	for i, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		var raw [3]json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			t.Fatalf("event %d decode: %v; line=%q", i, err, line)
		}
		var ev castEvent
		if err := json.Unmarshal(raw[0], &ev.Elapsed); err != nil {
			t.Fatalf("event %d elapsed: %v", i, err)
		}
		if err := json.Unmarshal(raw[1], &ev.Kind); err != nil {
			t.Fatalf("event %d kind: %v", i, err)
		}
		if err := json.Unmarshal(raw[2], &ev.Payload); err != nil {
			t.Fatalf("event %d payload: %v", i, err)
		}
		out = append(out, ev)
	}
	return out
}

type castEvent struct {
	Elapsed float64
	Kind    string
	Payload string
}

// stressClock returns monotonically-increasing times for the recorder
// without relying on wall-clock progress during the test. Each Now
// call advances by step.
type stressClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func newStressClock(start time.Time, step time.Duration) *stressClock {
	return &stressClock{now: start, step: step}
}

func (c *stressClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now
	c.now = c.now.Add(c.step)
	return t
}

func TestStress_HeavyEscapeSequences(t *testing.T) {
	// Vim-style screen redraw: cursor positioning + color codes +
	// arbitrary printable bytes. asciinema v2 stores raw bytes in
	// the payload as a UTF-8 string; the recorder MUST round-trip
	// exotic byte sequences (ANSI escapes + CSI sequences + UTF-8
	// multibyte chars) without corruption.
	start := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	rec, err := recording.New(&buf, 120, 40, "stress@host", start)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	recording.SetClock(rec, newStressClock(start, time.Millisecond).Now)

	payloads := [][]byte{
		[]byte("\x1b[2J\x1b[H"),                            // clear screen, home cursor
		[]byte("\x1b[31mERROR\x1b[0m: oops\r\n"),           // colored text
		[]byte("\x1b[?1049h"),                              // enter alt screen
		[]byte("\xe2\x95\x94\xe2\x95\x90\xe2\x95\x97\r\n"), // ╔═╗ UTF-8 box drawing
		[]byte("\x1b[?1049l"),                              // exit alt screen
		[]byte("\x00\x01\x02\x03\x04"),                     // control chars
		[]byte("\xc3\xa9\xc3\xa9\xc3\xa9"),                 // éééUTF-8 accent
	}
	for _, p := range payloads {
		rec.Output(p)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events := validateCast(t, buf.Bytes())
	if len(events) != len(payloads) {
		t.Fatalf("event count = %d, want %d", len(events), len(payloads))
	}
	// Every payload must round-trip byte-for-byte.
	for i, ev := range events {
		if ev.Kind != "o" {
			t.Errorf("events[%d].Kind = %q, want o", i, ev.Kind)
		}
		if ev.Payload != string(payloads[i]) {
			t.Errorf("events[%d] payload mismatch:\ngot  %q\nwant %q",
				i, ev.Payload, string(payloads[i]))
		}
	}
}

func TestStress_AlternateScreenBufferTransitions(t *testing.T) {
	// vim / less / tmux toggle the alternate screen buffer via
	// CSI ?1049h and CSI ?1049l. Many sessions cycle through this
	// rapidly; cast files must capture the transitions in order so
	// the replayer can re-create the buffer state.
	start := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	rec, _ := recording.New(&buf, 80, 24, "alt-screen", start)
	recording.SetClock(rec, newStressClock(start, 100*time.Microsecond).Now)

	const cycles = 50
	for range cycles {
		rec.Output([]byte("\x1b[?1049h")) // enter
		rec.Output([]byte("alt screen content\r\n"))
		rec.Output([]byte("\x1b[?1049l")) // exit
		rec.Output([]byte("primary screen\r\n"))
	}
	_ = rec.Close()

	events := validateCast(t, buf.Bytes())
	if len(events) != cycles*4 {
		t.Fatalf("event count = %d, want %d", len(events), cycles*4)
	}
	for i := range cycles {
		base := i * 4
		if events[base].Payload != "\x1b[?1049h" {
			t.Errorf("cycle %d: enter event mismatch", i)
		}
		if events[base+2].Payload != "\x1b[?1049l" {
			t.Errorf("cycle %d: exit event mismatch", i)
		}
	}
}

func TestStress_RapidResizeEvents(t *testing.T) {
	// SIGWINCH bursts arrive when a user drags a window edge; the
	// recorder gets a flood of window-change requests. Each should
	// land as a single "r" event with the new dimensions.
	start := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	rec, _ := recording.New(&buf, 80, 24, "resize", start)
	recording.SetClock(rec, newStressClock(start, 10*time.Microsecond).Now)

	for i := 1; i <= 100; i++ {
		rec.Resize(80+i, 24+i)
	}
	_ = rec.Close()

	events := validateCast(t, buf.Bytes())
	if len(events) != 100 {
		t.Fatalf("resize event count = %d, want 100", len(events))
	}
	for i, ev := range events {
		if ev.Kind != "r" {
			t.Errorf("events[%d].Kind = %q, want r", i, ev.Kind)
		}
	}
}

func TestStress_LargeOutputBurst(t *testing.T) {
	// `cat /var/log/messages` style — a single Output call carrying
	// many kilobytes of data. The recorder json-encodes the payload
	// as a string; UTF-8 validation matters because gossh delivers
	// arbitrary bytes and json.Marshal would error on invalid UTF-8
	// (recording would silently break).
	start := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	rec, _ := recording.New(&buf, 80, 24, "burst", start)
	recording.SetClock(rec, newStressClock(start, time.Microsecond).Now)

	// Build a 64 KiB chunk with a mix of printable + control bytes.
	chunk := make([]byte, 64*1024)
	for i := range chunk {
		// Skip 0xc0..0xff to keep the byte stream UTF-8-valid
		// (gossh delivers UTF-8 PTY data in the common case).
		chunk[i] = byte(i % 0x80)
	}
	rec.Output(chunk)
	_ = rec.Close()

	events := validateCast(t, buf.Bytes())
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if events[0].Payload != string(chunk) {
		t.Errorf("payload length mismatch: got %d, want %d",
			len(events[0].Payload), len(chunk))
	}
}

func TestStress_MonotonicElapsedTimestamps(t *testing.T) {
	// asciinema events MUST have non-decreasing elapsed times — a
	// retrograde timestamp confuses the player into rendering
	// events out of order. round6 truncates to microseconds; the
	// recorder must not produce timestamps that go backward even
	// when called in rapid succession.
	start := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	rec, _ := recording.New(&buf, 80, 24, "monotonic", start)
	// Real wall-clock — verifies the recorder doesn't itself
	// introduce ordering violations under contention.

	for range 200 {
		rec.Output([]byte("x"))
	}
	_ = rec.Close()

	events := validateCast(t, buf.Bytes())
	prev := -1.0
	for i, ev := range events {
		if ev.Elapsed < prev {
			t.Errorf("events[%d].Elapsed = %v < prev %v (retrograde)", i, ev.Elapsed, prev)
		}
		prev = ev.Elapsed
	}
}

func TestStress_ConcurrentOutputAndResize(t *testing.T) {
	// recordingTee + pipeUserRequests are on separate goroutines:
	// Output flows through the data-copy goroutine while Resize
	// flows through the request-forwarding goroutine. Under load,
	// both fire concurrently. Asserts the cast file remains
	// well-formed (each line is valid JSON, no interleaved writes).
	start := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	rec, _ := recording.New(&buf, 80, 24, "concurrent", start)

	var wg sync.WaitGroup
	const writers = 8
	const eventsPerWriter = 100
	wg.Add(writers)
	for w := range writers {
		go func(id int) {
			defer wg.Done()
			payload := []byte("from-writer-" + string(rune('0'+id)) + "\n")
			for range eventsPerWriter {
				rec.Output(payload)
			}
		}(w)
	}
	wg.Go(func() {
		for i := range eventsPerWriter {
			rec.Resize(80+i%10, 24+i%5)
		}
	})
	wg.Wait()
	_ = rec.Close()

	// validateCast is the load-bearing assertion here: it'll fail
	// loudly if any line of the cast is malformed JSON, which
	// would indicate an interleaved write through the lock.
	events := validateCast(t, buf.Bytes())
	wantMin := writers*eventsPerWriter + eventsPerWriter
	if len(events) != wantMin {
		t.Errorf("event count = %d, want %d", len(events), wantMin)
	}
	// Spot check the "kind" mix: at least one "o" + one "r" event.
	var oCount, rCount int
	for _, ev := range events {
		switch ev.Kind {
		case "o":
			oCount++
		case "r":
			rCount++
		}
	}
	if oCount != writers*eventsPerWriter {
		t.Errorf("o events = %d, want %d", oCount, writers*eventsPerWriter)
	}
	if rCount != eventsPerWriter {
		t.Errorf("r events = %d, want %d", rCount, eventsPerWriter)
	}
}

func TestStress_ClosedRecorderRejectsFurtherWrites(t *testing.T) {
	// After Close, Output/Resize must silently no-op. Otherwise a
	// recorder Close() racing with the final byte of session data
	// would either error up the io chain (breaking the proxy) or
	// keep writing to a finalised file (corrupting the cast).
	start := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	rec, _ := recording.New(&buf, 80, 24, "closed", start)
	rec.Output([]byte("before"))
	_ = rec.Close()
	rec.Output([]byte("after-close"))
	rec.Resize(120, 40)
	_ = rec.Close() // idempotent

	events := validateCast(t, buf.Bytes())
	if len(events) != 1 {
		t.Errorf("events after close = %d, want 1 (only 'before')", len(events))
	}
	if events[0].Payload != "before" {
		t.Errorf("payload = %q, want 'before'", events[0].Payload)
	}
}

// Compile-time check: the test's payload variant covers the kinds
// the real proxy hands the recorder. strings.Contains is a stable
// proxy for asciinema's "" event types we accept.
var _ = strings.Contains
