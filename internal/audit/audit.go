// Package audit defines the audit event types for ssh-proxyd.
//
// Write path (ssh-proxyd serve):
//
//	handleConn / Proxier → journal.EncodedSink[Entry].Append →
//	JetStream "ssh_audit" stream (authoritative store)
//
// The JetStream stream is the tamper-resistant authoritative record
// (DenyDelete, DenyPurge, FileStorage, ~13-month retention to clear
// PCI-DSS 10.5 with a roll-over buffer); there is no separate
// projection database. The certd portal tails this stream + certd's
// own ca_audit stream to render an end-to-end audit timeline for
// every session.
//
// Transport + marshalling live in tokyo3-base/journal — this package
// owns only the Entry shape and the wire-config constants.
package audit

import (
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// Wire-format constants for the audit journal. Subject is what
// ssh-proxyd publishes to; StreamName is the JetStream stream that
// covers it. StreamMaxAge is the retention floor (12-month PCI
// requirement + one-month buffer for clean roll-over).
const (
	Subject      = "ssh.audit.events"
	StreamName   = "ssh_audit"
	StreamMaxAge = 400 * 24 * time.Hour
)

// Action names — dotted lowercase. Each event lands as exactly one of
// these in [Entry.Action] so consumers can filter without re-parsing
// metadata.
const (
	ActionSessionOpened     = "ssh.session.opened"
	ActionSessionClosed     = "ssh.session.closed"
	ActionChannelRejected   = "ssh.channel.rejected"
	ActionRecordingComplete = "ssh.recording.completed"
	ActionPortForwardOpened = "ssh.port_forward.opened"
	ActionPortForwardClosed = "ssh.port_forward.closed"
)

// Sink is the typed JSON-encoding journal sink ssh-proxyd uses to
// publish [Entry]s. Construct with
// `journal.NewJSONSink[Entry](innerSink)`; the alias is purely an
// ergonomic shortcut.
type Sink = *journal.EncodedSink[Entry]

// NoopSink discards every event. Used in tests and dev environments
// where the audit journal is not configured. Safe for concurrent use.
var NoopSink Sink = journal.NewJSONSink[Entry](journal.NoopSink{})

// Entry is one audit event in canonical form. Serialised as JSON and
// stored verbatim in JetStream.
//
//   - SessionID is the proxy-assigned UUID tying related events
//     (opened → closed → recording.completed) together.
//   - User is the cert KeyID of the bearer ("user:alice@example.com")
//     so audit can attribute back to the human in certd's identity
//     records.
//   - Principals is the comma-separated set of Unix usernames the
//     cert authorised.
//   - Target identifies the host the user reached ("db-1.prod:22").
//   - RemoteUser is the principal the proxy authenticated to the
//     target as.
//   - ClientIP is the originating user's IP.
//   - RecordingPath is set on [ActionRecordingComplete] events with
//     the cast file's location.
//   - Reason is populated on rejection events with the deny message.
//   - Metadata is a pre-serialised JSON object holding
//     action-specific detail.
type Entry struct {
	ID            string    `json:"id"`
	Action        string    `json:"action"`
	SessionID     string    `json:"session_id,omitempty"`
	User          string    `json:"user,omitempty"`
	Principals    string    `json:"principals,omitempty"`
	Target        string    `json:"target,omitempty"`
	RemoteUser    string    `json:"remote_user,omitempty"`
	ClientIP      string    `json:"client_ip,omitempty"`
	RecordingPath string    `json:"recording_path,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Metadata      string    `json:"metadata,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
}
