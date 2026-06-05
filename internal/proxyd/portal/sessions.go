package portal

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
)

// SessionStore is the source for the /sessions page. Implementations
// must be safe for concurrent reads — the portal calls Sessions() on
// every render while the underlying tracker may be appending new
// entries from its subscriber goroutine.
type SessionStore interface {
	Sessions() []Session
}

// Session is the portal's view of one recorded SSH session,
// hydrated from a recording.completed audit Entry on the ssh_audit
// JetStream stream. The field names match the JSON shape ssh-proxyd's
// audit package publishes.
type Session struct {
	// SessionID is ssh-proxyd's per-connection UUID — same value
	// across session.opened / session.closed / recording.completed.
	SessionID string `json:"session_id"`
	// User is the cert KeyID of the human (e.g.,
	// "user:alice@example.com").
	User string `json:"user,omitempty"`
	// Target is the host the user reached ("db-1.prod:22").
	Target string `json:"target,omitempty"`
	// RemoteUser is the principal the proxy authenticated to the
	// target as.
	RemoteUser string `json:"remote_user,omitempty"`
	// Principals is the comma-separated set of Unix usernames the
	// cert authorized.
	Principals string `json:"principals,omitempty"`
	// ClientIP is the originating user's IP.
	ClientIP string `json:"client_ip,omitempty"`
	// RecordingPath points at the asciinema cast file on disk.
	RecordingPath string `json:"recording_path,omitempty"`
	// CompletedAt is when recording.completed fired.
	CompletedAt time.Time `json:"occurred_at"`
	// Duration is the recording's wall-clock length, parsed out of
	// the Metadata JSON blob (recording.completed includes
	// `duration_seconds`).
	Duration time.Duration `json:"-"`
}

// SessionTracker subscribes to a [journal.Source] (a JetStream tail
// of ssh-proxyd's own ssh_audit stream) and maintains a bounded ring
// of the most-recent recording.completed events. The tracker is the
// [SessionStore] the /sessions page renders from.
//
// The subscriber goroutine is owned by [SessionTracker.Run] — call
// it once after construction; cancel ctx to stop. Concurrent reads
// via [Sessions] are safe.
type SessionTracker struct {
	src     journal.Source
	max     int
	log     *slog.Logger
	subject string // informational only; for log lines

	mu       sync.RWMutex
	sessions []Session // newest first
}

// SessionTrackerConfig wires a tracker.
type SessionTrackerConfig struct {
	// Source is the journal source the tracker subscribes to.
	// Required.
	Source journal.Source

	// MaxSessions caps the in-memory ring. 0 ⇒ DefaultMaxSessions.
	MaxSessions int

	// SubjectLabel is the audit subject used purely for log
	// attribution (e.g., "ssh.audit.events"). Empty is acceptable.
	SubjectLabel string

	// Log is the structured logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// DefaultMaxSessions is the per-tracker recent-sessions cap. Old
// entries fall out of the buffer when newer ones arrive; the page
// surfaces the latest activity rather than the full history.
const DefaultMaxSessions = 200

// NewSessionTracker validates cfg and returns a tracker. Source is
// the only hard requirement.
func NewSessionTracker(cfg SessionTrackerConfig) (*SessionTracker, error) {
	if cfg.Source == nil {
		return nil, errSessionSourceRequired
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = DefaultMaxSessions
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &SessionTracker{
		src:     cfg.Source,
		max:     cfg.MaxSessions,
		log:     cfg.Log,
		subject: cfg.SubjectLabel,
	}, nil
}

// Run subscribes to the journal source, decodes each inbound payload
// as a recording.completed event, and appends to the in-memory ring.
// Returns when ctx is cancelled or the source's channel closes. The
// tracker tolerates malformed payloads and non-recording-completed
// events — they're skipped silently (logged at debug) rather than
// crashing the loop.
func (t *SessionTracker) Run(ctx context.Context) error {
	// Backfill the latest MaxSessions records, then tail. Persistent
	// JetStream streams retain history far longer than the in-memory
	// cap, so this hydrates the page with whatever was published
	// before ssh-proxyd started.
	ch, err := t.src.Subscribe(ctx, t.max, 0)
	if err != nil {
		return err
	}
	t.log.Info("session tracker subscribed", "subject", t.subject, "replay", t.max)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			t.ingest(msg)
		}
	}
}

// Sessions returns a copy of the current recent-sessions ring,
// newest first. Safe to call from request handlers while [Run] is
// active.
func (t *SessionTracker) Sessions() []Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Session, len(t.sessions))
	copy(out, t.sessions)
	return out
}

// ingest decodes one journal message, filters to
// recording.completed, and prepends to the ring (newest first).
// Buffer is trimmed to MaxSessions after each append.
func (t *SessionTracker) ingest(msg journal.Msg) {
	var raw struct {
		Action        string    `json:"action"`
		SessionID     string    `json:"session_id"`
		User          string    `json:"user"`
		Target        string    `json:"target"`
		RemoteUser    string    `json:"remote_user"`
		Principals    string    `json:"principals"`
		ClientIP      string    `json:"client_ip"`
		RecordingPath string    `json:"recording_path"`
		Metadata      string    `json:"metadata"`
		OccurredAt    time.Time `json:"occurred_at"`
	}
	if err := json.Unmarshal(msg.Data, &raw); err != nil {
		t.log.Debug("session tracker: decode failed", "err", err, "seq", msg.Seq)
		return
	}
	if raw.Action != audit.ActionRecordingComplete {
		return // not a session-list event
	}
	sess := Session{
		SessionID:     raw.SessionID,
		User:          raw.User,
		Target:        raw.Target,
		RemoteUser:    raw.RemoteUser,
		Principals:    raw.Principals,
		ClientIP:      raw.ClientIP,
		RecordingPath: raw.RecordingPath,
		CompletedAt:   raw.OccurredAt,
	}
	if raw.Metadata != "" {
		var md struct {
			DurationSeconds float64 `json:"duration_seconds"`
		}
		if err := json.Unmarshal([]byte(raw.Metadata), &md); err == nil && md.DurationSeconds > 0 {
			sess.Duration = time.Duration(md.DurationSeconds * float64(time.Second))
		}
	}

	t.mu.Lock()
	// Newest first; prepend by shifting. For the small N here (~200)
	// a simple slice prepend is cheap and avoids ring-buffer
	// bookkeeping.
	t.sessions = append([]Session{sess}, t.sessions...)
	if len(t.sessions) > t.max {
		t.sessions = t.sessions[:t.max]
	}
	t.mu.Unlock()
}

// errSessionSourceRequired keeps NewSessionTracker's error stable
// across go vet's recommendations about exported errors.
var errSessionSourceRequired = sessionTrackerErr("source is required")

type sessionTrackerErr string

func (e sessionTrackerErr) Error() string { return string(e) }
