package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
)

// BenchmarkEntryAppend_Noop measures the per-event cost of building
// + JSON-encoding an audit.Entry without any broker round-trip. The
// proxy emits one entry per session.opened / .closed / channel
// event; aggregate cost matters under load.
func BenchmarkEntryAppend_Noop(b *testing.B) {
	sink := audit.NoopSink
	entry := audit.Entry{
		ID:            "evt-bench",
		Action:        audit.ActionSessionOpened,
		SessionID:     "sess-abc-123",
		User:          "user:alice@example.com",
		Principals:    "alice,deployer",
		Target:        "db-1.prod.internal:22",
		RemoteUser:    "alice",
		ClientIP:      "10.0.0.42",
		RecordingPath: "/var/lib/ssh-proxyd/casts/2026-05-26/sess-abc-123.cast",
		Metadata:      `{"role":"eng-prod","extra":"context"}`,
		OccurredAt:    time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = sink.Append(context.Background(), entry)
	}
}

// BenchmarkEntryAppend_DiscardSink runs against a capture sink that
// pushes the encoded bytes into a slice the loop discards each
// iteration — exercises JSON encoding without journal-sink type
// dispatch noise.
func BenchmarkEntryAppend_DiscardSink(b *testing.B) {
	sink := journal.NewJSONSink[audit.Entry](discardSink{})
	entry := audit.Entry{
		ID:         "evt-bench",
		Action:     audit.ActionPortForwardClosed,
		SessionID:  "sess-abc-123",
		User:       "user:alice@example.com",
		Target:     "internal-target:5432",
		ClientIP:   "10.0.0.42",
		Metadata:   `{"bytes_in":4096,"bytes_out":8192,"duration_seconds":3.5}`,
		OccurredAt: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = sink.Append(context.Background(), entry)
	}
}

// discardSink is the journal.Sink test double for benchmarks —
// accepts each payload and immediately drops it.
type discardSink struct{}

func (discardSink) Append(context.Context, []byte) error { return nil }
func (discardSink) Close() error                         { return nil }

// Compile-time check: discardSink satisfies the journal.Sink shape
// the encoded sink expects.
var _ journal.Sink = discardSink{}
