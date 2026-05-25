package session

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
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
	sink        recording.Sink
	user        string
	host        string
	log         *slog.Logger
	audit       audit.Sink
	sessionAttr recordingAuditAttr

	mu        sync.Mutex
	rec       *recording.Recorder
	cast      io.WriteCloser
	location  string
	sessionID string
	startedAt time.Time
	closed    bool
}

// recordingAuditAttr carries the connection-level attribution
// channelRecorder needs to emit recording.completed events into the
// shared audit stream. Empty values are tolerated — they just produce
// a less-attributable Entry.
type recordingAuditAttr struct {
	Principals string
	Target     string
	RemoteUser string
	ClientIP   string
}

// newChannelRecorder builds a recorder bound to sink. Lazy
// initialisation means the cast file is only opened when a pty-req
// arrives (so non-PTY exec sessions don't litter the cast directory).
// auditSink is nil-safe; pass [audit.NoopSink] when audit is disabled.
// sessionID ties the recording's audit events back to the same
// SessionID the SSH server stamped on session.opened / .closed.
func newChannelRecorder(sink recording.Sink, sessionID, user, host string, attr recordingAuditAttr, auditSink audit.Sink, log *slog.Logger) *channelRecorder {
	if log == nil {
		log = slog.Default()
	}
	if auditSink == nil {
		auditSink = audit.NoopSink
	}
	return &channelRecorder{
		sink:        sink,
		user:        user,
		host:        host,
		log:         log,
		audit:       auditSink,
		sessionAttr: attr,
		sessionID:   sessionID,
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
	if r.sessionID == "" {
		// Fall back to a fresh UUID when the SSH server didn't seed
		// one — keeps the dev path working when audit is unwired.
		r.sessionID = uuid.NewString()
	}
	r.startedAt = time.Now().UTC()
	cast, location, err := r.sink.OpenCast(context.Background(), recording.CastMeta{
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
	r.location = location
	r.log.Info("session recording started",
		"session_id", r.sessionID,
		"user", r.user, "target", r.host,
		"width", width, "height", height,
		"location", location,
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

// Close finalises the underlying cast file and emits a
// recording.completed audit event when a recording was actually
// produced (i.e., a pty-req fired). Idempotent.
func (r *channelRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	hadRecording := r.rec != nil
	if r.rec != nil {
		_ = r.rec.Close()
	}
	var closeErr error
	if r.cast != nil {
		closeErr = r.cast.Close()
		if closeErr != nil {
			r.log.Warn("close cast file", "session_id", r.sessionID, "err", closeErr)
		} else {
			r.log.Info("session recording closed", "session_id", r.sessionID, "location", r.location)
		}
	}
	if hadRecording {
		r.emitCompleted()
	}
	r.cast = nil
	r.rec = nil
	return closeErr
}

// emitCompleted publishes the recording.completed audit Entry. Run
// only when a real recording was produced (lazy-start path fired);
// no-PTY sessions skip both the cast file and the audit event.
func (r *channelRecorder) emitCompleted() {
	duration := time.Since(r.startedAt).Seconds()
	if duration < 0 {
		duration = 0
	}
	metadata := map[string]any{
		"duration_seconds": round6(duration),
		"started_at":       r.startedAt.UTC(),
	}
	md, _ := json.Marshal(metadata)
	entry := audit.Entry{
		ID:            uuid.NewString(),
		Action:        audit.ActionRecordingComplete,
		SessionID:     r.sessionID,
		User:          r.user,
		Principals:    r.sessionAttr.Principals,
		Target:        r.sessionAttr.Target,
		RemoteUser:    r.sessionAttr.RemoteUser,
		ClientIP:      r.sessionAttr.ClientIP,
		RecordingPath: r.location,
		Metadata:      string(md),
		OccurredAt:    time.Now().UTC(),
	}
	if err := r.audit.Append(context.Background(), entry); err != nil {
		r.log.Warn("audit recording.completed append failed", "session_id", r.sessionID, "err", err)
	}
}

// round6 trims a duration value to ~microsecond precision for the
// audit metadata. Matches the trimming the asciinema recorder
// applies to event timestamps.
func round6(v float64) float64 {
	const mult = 1e6
	return float64(int64(v*mult+0.5)) / mult
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
