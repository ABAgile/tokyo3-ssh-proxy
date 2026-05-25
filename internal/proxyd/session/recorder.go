package session

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
)

// channelRecorder is the per-channel adapter that turns SSH protocol
// observations (pty-req, window-change, target → user data) into
// asciinema events. The underlying [recording.Recorder] is created
// lazily on the first pty-req — non-PTY exec sessions skip recording
// since there's no terminal to replay.
//
// All methods are safe to call from multiple goroutines; the Proxier
// invokes StartIfNeeded + Resize from the request-forwarding
// goroutine and writeOutput (via [recordingTee.Write]) from the
// data-copy goroutine.
type channelRecorder struct {
	sink recording.Sink
	user string
	host string
	log  *slog.Logger

	mu        sync.Mutex
	rec       *recording.Recorder
	cast      io.WriteCloser
	sessionID string
	startedAt time.Time
	closed    bool
}

// newChannelRecorder builds a recorder bound to sink. Lazy
// initialisation means the cast file is only opened when a pty-req
// arrives (so non-PTY exec sessions don't litter the cast directory).
func newChannelRecorder(sink recording.Sink, user, host string, log *slog.Logger) *channelRecorder {
	if log == nil {
		log = slog.Default()
	}
	return &channelRecorder{
		sink: sink,
		user: user,
		host: host,
		log:  log,
	}
}

// StartIfNeeded opens the cast file and begins recording the first
// time it's called with non-zero dimensions. Subsequent calls are
// no-ops — pty-req should only happen once per session, but we
// tolerate clients that resend it.
func (r *channelRecorder) StartIfNeeded(width, height int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rec != nil || r.closed {
		return nil
	}
	r.sessionID = uuid.NewString()
	r.startedAt = time.Now().UTC()
	cast, err := r.sink.OpenCast(context.Background(), recording.CastMeta{
		SessionID: r.sessionID,
		User:      r.user,
		Target:    r.host,
		Started:   r.startedAt,
	})
	if err != nil {
		return err
	}
	title := r.user + "@" + r.host
	rec, err := recording.New(cast, width, height, title, r.startedAt)
	if err != nil {
		_ = cast.Close()
		return err
	}
	r.cast = cast
	r.rec = rec
	r.log.Info("session recording started",
		"session_id", r.sessionID,
		"user", r.user, "target", r.host,
		"width", width, "height", height,
	)
	return nil
}

// writeOutput appends an asciinema "o" event for bytes the target
// sent to the user. Called from [recordingTee.Write]; safe to invoke
// before [StartIfNeeded] (pre-PTY output is dropped).
func (r *channelRecorder) writeOutput(p []byte) {
	r.mu.Lock()
	rec := r.rec
	r.mu.Unlock()
	if rec == nil {
		return
	}
	rec.Output(p)
}

// Resize appends an asciinema "r" event.
func (r *channelRecorder) Resize(width, height int) {
	r.mu.Lock()
	rec := r.rec
	r.mu.Unlock()
	if rec == nil {
		return
	}
	rec.Resize(width, height)
}

// Close finalises the underlying cast file. Idempotent.
func (r *channelRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.rec != nil {
		_ = r.rec.Close()
	}
	if r.cast != nil {
		err := r.cast.Close()
		r.cast = nil
		r.rec = nil
		if err != nil {
			r.log.Warn("close cast file", "session_id", r.sessionID, "err", err)
		} else {
			r.log.Info("session recording closed", "session_id", r.sessionID)
		}
		return err
	}
	return nil
}

// recordingTee wraps an [io.Writer] and also feeds each chunk into a
// [channelRecorder]. The recorder may be nil at construction; writes
// pass through unchanged.
type recordingTee struct {
	w   io.Writer
	rec *channelRecorder
}

// Write satisfies [io.Writer]. The underlying writer's count + err
// is what the io.Copy caller observes; recording errors never affect
// the wire.
func (t *recordingTee) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if n > 0 && t.rec != nil {
		// Record only the bytes that made it onto the wire — partial
		// writes are rare for SSH channels but harmless to mirror.
		t.rec.writeOutput(p[:n])
	}
	return n, err
}
