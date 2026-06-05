package portal

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"sync"
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
// maintains a bounded ring of the latest events, newest first.
// Construct via [NewAuditTracker]; the subscriber goroutine is owned
// by [AuditTracker.Run] — call once after construction.
type AuditTracker struct {
	src journal.Source
	max int
	log *slog.Logger

	mu     sync.RWMutex
	events []AuditEvent // newest first
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

// NewAuditTracker validates cfg and returns a tracker.
func NewAuditTracker(cfg AuditTrackerConfig) (*AuditTracker, error) {
	if cfg.Source == nil {
		return nil, errors.New("source is required")
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = DefaultMaxAuditEvents
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &AuditTracker{
		src: cfg.Source,
		max: cfg.MaxEvents,
		log: cfg.Log,
	}, nil
}

// Run subscribes to the source and ingests until ctx cancels or the
// source's channel closes. Per-message decode failures are logged at
// debug and ignored.
func (t *AuditTracker) Run(ctx context.Context) error {
	ch, err := t.src.Subscribe(ctx, t.max, 0)
	if err != nil {
		return err
	}
	t.log.Info("audit tracker subscribed", "replay", t.max)
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

// Events returns a snapshot of the current event ring, newest first.
// Safe to call from request handlers while Run is active.
func (t *AuditTracker) Events() []AuditEvent {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]AuditEvent, len(t.events))
	copy(out, t.events)
	return out
}

// ingest decodes one journal message into an AuditEvent and inserts it
// into the ring. The ring stays sorted newest-first by OccurredAt — a
// re-sort is cheap at len ≤ MaxEvents.
func (t *AuditTracker) ingest(msg journal.Msg) {
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
		t.log.Debug("audit tracker: decode failed", "seq", msg.Seq, "err", err)
		return
	}
	if raw.Action == "" || raw.OccurredAt.IsZero() {
		// Malformed in a less obvious way — skip rather than render a
		// row with no useful content.
		return
	}

	ev := AuditEvent{
		ID:         raw.ID,
		Action:     raw.Action,
		OccurredAt: raw.OccurredAt,
		Actor:      raw.User,
		Subject:    raw.Target,
		IP:         raw.ClientIP,
		SessionID:  raw.SessionID,
		Reason:     raw.Reason,
		Detail:     raw.Metadata,
	}

	t.mu.Lock()
	t.events = append(t.events, ev)
	// Sort newest-first. The ring is small (≤ MaxEvents) and growth is
	// one-per-message, so sort.Slice is plenty.
	sort.Slice(t.events, func(i, j int) bool {
		return t.events[i].OccurredAt.After(t.events[j].OccurredAt)
	})
	if len(t.events) > t.max {
		t.events = t.events[:t.max]
	}
	t.mu.Unlock()
}
