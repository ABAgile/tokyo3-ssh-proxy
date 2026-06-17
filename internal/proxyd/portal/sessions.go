package portal

import (
	"encoding/json"
	"log/slog"
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
// of the most-recent recording.completed events. It wraps a
// [journal.Tracker]; the tracker is the [SessionStore] the /sessions
// page renders from.
//
// The subscriber goroutine is owned by the embedded Run — call it once
// after construction; cancel ctx to stop. Concurrent reads via
// [Sessions] are safe.
type SessionTracker struct {
	*journal.Tracker[Session]
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

// decodeSession decodes one journal message, filters to
// recording.completed, and parses duration_seconds out of the
// Metadata blob. Returns ok=false on a JSON failure or any action
// other than recording.completed.
func decodeSession(msg journal.Msg) (Session, bool) {
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
		return Session{}, false
	}
	if raw.Action != audit.ActionRecordingComplete {
		return Session{}, false // not a session-list event
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
	return sess, true
}

// NewSessionTracker validates cfg and returns a tracker. Source is
// the only hard requirement.
func NewSessionTracker(cfg SessionTrackerConfig) (*SessionTracker, error) {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = DefaultMaxSessions
	}
	t, err := journal.NewTracker(journal.TrackerConfig[Session]{
		Source: cfg.Source,
		Max:    cfg.MaxSessions,
		Log:    cfg.Log,
		Label:  "ssh_audit/sessions",
		Decode: decodeSession,
		// Less nil ⇒ arrival-order prepend: the ssh_audit stream
		// publishes recording.completed events in completion order, so
		// arrival order already matches recency.
	})
	if err != nil {
		return nil, err
	}
	return &SessionTracker{t}, nil
}

// Sessions returns a copy of the current recent-sessions ring,
// newest first. Safe to call from request handlers while Run is
// active. Satisfies [SessionStore].
func (t *SessionTracker) Sessions() []Session { return t.Snapshot() }
