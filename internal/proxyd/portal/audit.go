package portal

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// AuditStore is the source for the /audit page. Implementations must
// be safe for concurrent reads — the portal calls Events() on every
// render while the underlying tracker may be appending new entries
// from its subscriber goroutine.
type AuditStore interface {
	Events() []AuditEvent
}

// AuditEvent is the portal's view of one record from ssh-proxyd's
// ssh_audit stream (session lifecycle, channel, recording, and
// port-forward events).
type AuditEvent struct {
	// ID is the event's unique identifier (UUID).
	ID string

	// Action is the dotted event name (e.g., "ssh.session.opened").
	Action string

	// OccurredAt is the producer-side timestamp.
	OccurredAt time.Time

	// Actor is who performed the action — the cert KeyID (User).
	Actor string

	// Subject is what the action acted on — the Target host.
	Subject string

	// IP is the originating network address (ClientIP).
	IP string

	// SessionID ties events that participate in a session lifecycle.
	SessionID string

	// Reason is set on denial events (e.g., channel.rejected) with the
	// policy explanation.
	Reason string

	// Detail is the action-specific JSON blob (Metadata field).
	// Rendered as a <pre> so operators can read the full payload
	// without an external JetStream tool.
	Detail string
}

// AuditTracker subscribes to ssh-proxyd's ssh_audit stream and
// maintains a bounded ring of the latest events, newest first. It
// wraps a [journal.Tracker]; the subscriber goroutine is owned by the
// embedded Run — call once after construction.
type AuditTracker struct {
	*journal.Tracker[AuditEvent]
}

// AuditTrackerConfig wires a tracker.
type AuditTrackerConfig struct {
	// Source is the journal source to subscribe to. Required.
	Source journal.Source

	// MaxEvents caps the in-memory ring. 0 ⇒ DefaultMaxAuditEvents.
	MaxEvents int

	// Log is the structured logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// DefaultMaxAuditEvents is the recent-events cap. Old entries fall out
// of the buffer when newer ones arrive; the portal surfaces the latest
// activity rather than the full history.
const DefaultMaxAuditEvents = 500

// decodeAuditEvent decodes one journal message into an AuditEvent.
// Returns ok=false on a JSON failure or a record missing the bare
// minimum (action / occurred_at) needed to render a useful row.
func decodeAuditEvent(msg journal.Msg) (AuditEvent, bool) {
	var raw struct {
		ID         string    `json:"id"`
		Action     string    `json:"action"`
		OccurredAt time.Time `json:"occurred_at"`
		User       string    `json:"user,omitempty"`
		Target     string    `json:"target,omitempty"`
		ClientIP   string    `json:"client_ip,omitempty"`
		SessionID  string    `json:"session_id,omitempty"`
		Reason     string    `json:"reason,omitempty"`
		Metadata   string    `json:"metadata,omitempty"`
	}
	if err := json.Unmarshal(msg.Data, &raw); err != nil {
		return AuditEvent{}, false
	}
	if raw.Action == "" || raw.OccurredAt.IsZero() {
		// Malformed in a less obvious way — skip rather than render a
		// row with no useful content.
		return AuditEvent{}, false
	}
	return AuditEvent{
		ID:         raw.ID,
		Action:     raw.Action,
		OccurredAt: raw.OccurredAt,
		Actor:      raw.User,
		Subject:    raw.Target,
		IP:         raw.ClientIP,
		SessionID:  raw.SessionID,
		Reason:     raw.Reason,
		Detail:     raw.Metadata,
	}, true
}

// NewAuditTracker validates cfg and returns a tracker.
func NewAuditTracker(cfg AuditTrackerConfig) (*AuditTracker, error) {
	t, err := journal.NewTracker(journal.TrackerConfig[AuditEvent]{
		Source: cfg.Source,
		Max:    cfg.MaxEvents,
		Log:    cfg.Log,
		Label:  "ssh_audit",
		Decode: decodeAuditEvent,
		Less:   func(a, b AuditEvent) bool { return a.OccurredAt.After(b.OccurredAt) },
	})
	if err != nil {
		return nil, err
	}
	return &AuditTracker{t}, nil
}

// Events returns a snapshot of the current event ring, newest first.
// Safe to call from request handlers while Run is active. Satisfies
// [AuditStore].
func (t *AuditTracker) Events() []AuditEvent { return t.Snapshot() }
