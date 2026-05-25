package ssh_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"
	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
)

// captureSink is the journal.Sink test double that retains each
// published payload. Wrap with journal.NewJSONSink[audit.Entry] to
// get an audit.Sink the proxy can publish through.
type captureSink struct {
	mu  sync.Mutex
	raw [][]byte
}

func (s *captureSink) Append(_ context.Context, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(b))
	copy(cp, b)
	s.raw = append(s.raw, cp)
	return nil
}

func (s *captureSink) Close() error { return nil }

// entries decodes each captured payload as an audit.Entry. Fails the
// test on a bad decode — the proxy is producing the canonical JSON.
func (s *captureSink) entries(t *testing.T) []audit.Entry {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.Entry, 0, len(s.raw))
	for _, b := range s.raw {
		var e audit.Entry
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatalf("decode captured entry: %v; raw=%s", err, string(b))
		}
		out = append(out, e)
	}
	return out
}

// findActions returns the entries whose Action equals act, in order.
func (s *captureSink) findActions(t *testing.T, act string) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	for _, e := range s.entries(t) {
		if e.Action == act {
			out = append(out, e)
		}
	}
	return out
}

// newAuditTestServer wires up a Server with a fresh capture sink for
// audit. The returned tuple is server addr, the capture sink, the
// fake target sshd, and the user cert signer to dial with. Tests
// drive sessions and then assert on the entries the sink captured.
func newAuditTestServer(t *testing.T) (addr string, cap *captureSink, target *fakeTarget, certSigner gossh.Signer, cleanup func()) {
	t.Helper()
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target = newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	cap = &captureSink{}
	auditSink := journal.NewJSONSink[audit.Entry](cap)

	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClientSigner),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		Audit:                 auditSink,
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		cancel()
		t.Fatal("server did not bind")
	}

	userSigner := newUserKey(t)
	certSigner = signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	return srv.Addr(), cap, target, certSigner, func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Error("server shutdown timeout")
		}
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestAudit_EmitsOpenedAndClosedForHappySession(t *testing.T) {
	addr, cap, target, certSigner, cleanup := newAuditTestServer(t)
	defer cleanup()

	client, err := dialAsUser(addr, "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sess, _ := client.NewSession()
	_, _ = sess.Output("anything")
	_ = client.Close()
	time.Sleep(50 * time.Millisecond)

	opened := cap.findActions(t, audit.ActionSessionOpened)
	closed := cap.findActions(t, audit.ActionSessionClosed)
	if len(opened) != 1 {
		t.Errorf("opened entries = %d, want 1", len(opened))
	}
	if len(closed) != 1 {
		t.Errorf("closed entries = %d, want 1", len(closed))
	}

	if len(opened) == 1 {
		o := opened[0]
		if o.SessionID == "" {
			t.Error("opened.SessionID empty")
		}
		if o.User != "user:test" {
			t.Errorf("opened.User = %q (want cert KeyID)", o.User)
		}
		if o.Principals != "alice" {
			t.Errorf("opened.Principals = %q", o.Principals)
		}
		if o.Target != target.addr {
			t.Errorf("opened.Target = %q, want %q", o.Target, target.addr)
		}
		if o.RemoteUser != "alice" {
			t.Errorf("opened.RemoteUser = %q", o.RemoteUser)
		}
		if !strings.HasPrefix(o.ClientIP, "127.0.0.1") {
			t.Errorf("opened.ClientIP = %q, want 127.0.0.1", o.ClientIP)
		}
		if o.OccurredAt.IsZero() {
			t.Error("opened.OccurredAt unset")
		}
	}

	// Same SessionID across opened + closed.
	if len(opened) == 1 && len(closed) == 1 && opened[0].SessionID != closed[0].SessionID {
		t.Errorf("opened SessionID %q != closed SessionID %q",
			opened[0].SessionID, closed[0].SessionID)
	}
}

func TestAudit_EmitsChannelRejectedOnTargetUnreachable(t *testing.T) {
	addr, cap, _, certSigner, cleanup := newAuditTestServer(t)
	defer cleanup()

	// Dial through proxy but point at a bogus target so DialTarget fails.
	client, err := dialAsUser(addr, "alice@127.0.0.1:1", gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	_, _ = client.NewSession()
	time.Sleep(50 * time.Millisecond)

	rejected := cap.findActions(t, audit.ActionChannelRejected)
	if len(rejected) != 1 {
		t.Fatalf("channel.rejected entries = %d, want 1", len(rejected))
	}
	r := rejected[0]
	if !strings.Contains(r.Reason, "target unreachable") {
		t.Errorf("Reason = %q, want to contain 'target unreachable'", r.Reason)
	}
	// metadata.stage is "target_dial" for this rejection cause.
	if !strings.Contains(r.Metadata, "target_dial") {
		t.Errorf("Metadata = %q, want 'target_dial' stage", r.Metadata)
	}
}

func TestAudit_EmitsChannelRejectedOnSignerError(t *testing.T) {
	// Build a server whose ClientSignerFunc errors. Every session
	// should land a channel.rejected event with stage=client_signer.
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	cap := &captureSink{}
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      func(context.Context, string) (gossh.Signer, error) { return nil, errors.New("certd unreachable") },
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		Audit:                 journal.NewJSONSink[audit.Entry](cap),
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})
	client, err := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	_, _ = client.NewSession()
	time.Sleep(50 * time.Millisecond)

	rejected := cap.findActions(t, audit.ActionChannelRejected)
	if len(rejected) != 1 {
		t.Fatalf("rejected = %d, want 1", len(rejected))
	}
	if !strings.Contains(rejected[0].Metadata, "client_signer") {
		t.Errorf("metadata = %q, want 'client_signer' stage", rejected[0].Metadata)
	}
	if !strings.Contains(rejected[0].Reason, "certd unreachable") {
		t.Errorf("Reason = %q, want to surface the underlying error", rejected[0].Reason)
	}
}

func TestAudit_NoEmissionWhenSinkUnset(t *testing.T) {
	// pssh.Config with Audit unset → defaults to NoopSink → no events
	// stored anywhere. Use the existing forwarding test setup (which
	// doesn't pass Audit) and verify there's no panic / no surprise.
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClientSigner),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		// Audit: nil  ← explicit
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, err := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	sess, _ := client.NewSession()
	_, _ = sess.Output("anything")
}

func TestAudit_EmitsRecordingCompletedForPTYSession(t *testing.T) {
	// PTY-session path: a pty-req fires the recorder, the close
	// finalises the cast file, and the channelRecorder must publish
	// a recording.completed entry carrying the cast path + duration.
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	sinkRoot := filepath.Join(t.TempDir(), "casts")
	recSink, err := recording.NewLocalDirSink(sinkRoot)
	if err != nil {
		t.Fatalf("NewLocalDirSink: %v", err)
	}

	cap := &captureSink{}
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClientSigner),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		RecordingSink:         recSink,
		Audit:                 journal.NewJSONSink[audit.Entry](cap),
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})
	client, err := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := sess.RequestPty("xterm-256color", 40, 120, gossh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	_, _ = sess.Output("anything")
	_ = client.Close()
	time.Sleep(100 * time.Millisecond)

	completed := cap.findActions(t, audit.ActionRecordingComplete)
	if len(completed) != 1 {
		t.Fatalf("recording.completed entries = %d, want 1", len(completed))
	}
	got := completed[0]
	if got.SessionID == "" {
		t.Error("recording.completed.SessionID empty")
	}
	if got.RecordingPath == "" {
		t.Error("recording.completed.RecordingPath empty")
	} else {
		if _, statErr := os.Stat(got.RecordingPath); statErr != nil {
			t.Errorf("RecordingPath %q does not exist on disk: %v", got.RecordingPath, statErr)
		}
		if !strings.HasPrefix(got.RecordingPath, sinkRoot) {
			t.Errorf("RecordingPath %q is not under sink root %q", got.RecordingPath, sinkRoot)
		}
	}
	if got.Target != target.addr {
		t.Errorf("recording.completed.Target = %q, want %q", got.Target, target.addr)
	}
	if got.RemoteUser != "alice" {
		t.Errorf("recording.completed.RemoteUser = %q, want alice", got.RemoteUser)
	}
	if got.Metadata == "" {
		t.Fatal("recording.completed.Metadata empty")
	}
	var md map[string]any
	if err := json.Unmarshal([]byte(got.Metadata), &md); err != nil {
		t.Fatalf("decode Metadata: %v; raw=%s", err, got.Metadata)
	}
	if _, ok := md["duration_seconds"].(float64); !ok {
		t.Errorf("Metadata missing duration_seconds: %v", md)
	}
	if _, ok := md["started_at"]; !ok {
		t.Errorf("Metadata missing started_at: %v", md)
	}

	// SessionID must match the session.opened entry so the recording
	// can be correlated back to the connection.
	opened := cap.findActions(t, audit.ActionSessionOpened)
	if len(opened) == 1 && opened[0].SessionID != got.SessionID {
		t.Errorf("recording.completed.SessionID %q != session.opened.SessionID %q",
			got.SessionID, opened[0].SessionID)
	}
}

func TestAudit_NoRecordingCompletedForNonPTYSession(t *testing.T) {
	// No pty-req → no cast file → no recording.completed event,
	// even with both sinks wired up.
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	recSink, _ := recording.NewLocalDirSink(filepath.Join(t.TempDir(), "casts"))
	cap := &captureSink{}
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClientSigner),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		RecordingSink:         recSink,
		Audit:                 journal.NewJSONSink[audit.Entry](cap),
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})
	client, _ := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(certSigner))
	defer client.Close()
	sess, _ := client.NewSession()
	_, _ = sess.Output("anything")
	_ = client.Close()
	time.Sleep(50 * time.Millisecond)

	if completed := cap.findActions(t, audit.ActionRecordingComplete); len(completed) != 0 {
		t.Errorf("non-PTY session produced %d recording.completed entries, want 0", len(completed))
	}
}

// Compile-time interface check — fails fast if captureSink drifts
// out of journal.Sink shape (which would silently disable audit
// capture in these tests).
var _ journal.Sink = (*captureSink)(nil)
