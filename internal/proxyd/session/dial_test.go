package session_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/session"
)

// stubSigner satisfies gossh.Signer with no-op surfaces — DialTarget
// only validates non-nilness before invoking Transport, so we never
// need a real key for the Transport-injection tests.
type stubSigner struct{}

func (stubSigner) PublicKey() gossh.PublicKey                       { return nil }
func (stubSigner) Sign(io.Reader, []byte) (*gossh.Signature, error) { return nil, errors.New("nope") }

func TestDialTarget_UsesInjectedTransport(t *testing.T) {
	var gotAddr string
	transport := func(_ context.Context, addr string) (net.Conn, error) {
		gotAddr = addr
		return nil, errors.New("transport sentinel")
	}

	_, err := session.DialTarget(context.Background(), session.DialConfig{
		Address:         "db-1",
		User:            "alice",
		Signer:          stubSigner{},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Transport:       transport,
	})
	if err == nil {
		t.Fatal("expected error from transport")
	}
	if !strings.Contains(err.Error(), "transport sentinel") {
		t.Errorf("err = %v, want to surface transport error", err)
	}
	// Bare hostname acquired DefaultTargetPort.
	if gotAddr != "db-1:22" {
		t.Errorf("transport saw addr %q, want db-1:22", gotAddr)
	}
}

func TestDialTarget_TransportPreservesExplicitPort(t *testing.T) {
	var gotAddr string
	_, _ = session.DialTarget(context.Background(), session.DialConfig{
		Address:         "host:2222",
		User:            "u",
		Signer:          stubSigner{},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Transport: func(_ context.Context, addr string) (net.Conn, error) {
			gotAddr = addr
			return nil, errors.New("x")
		},
	})
	if gotAddr != "host:2222" {
		t.Errorf("transport saw addr %q, want host:2222", gotAddr)
	}
}

func TestDialTarget_TransportRespectsContext(t *testing.T) {
	// Transport gets a sub-ctx that's bounded by cfg.Timeout. A
	// transport that observes ctx cancel should be able to bail
	// without waiting on the timeout itself.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := session.DialTarget(ctx, session.DialConfig{
		Address:         "host",
		User:            "u",
		Signer:          stubSigner{},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Transport: func(ctx context.Context, _ string) (net.Conn, error) {
			return nil, ctx.Err()
		},
	})
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("err = %v, want to surface context.Canceled", err)
	}
}
