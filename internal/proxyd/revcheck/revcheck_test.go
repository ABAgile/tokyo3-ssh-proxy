package revcheck_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/revcheck"
)

func TestPermissiveChecker_AlwaysFalse(t *testing.T) {
	if (revcheck.PermissiveChecker{}).IsRevoked(&gossh.Certificate{Serial: 7, KeyId: "x"}) {
		t.Error("PermissiveChecker should never revoke")
	}
	if (revcheck.PermissiveChecker{}).IsRevoked(nil) {
		t.Error("PermissiveChecker should tolerate nil")
	}
}

func TestNewPollingChecker_RequiresURL(t *testing.T) {
	_, err := revcheck.NewPollingChecker(revcheck.Config{})
	if err == nil || !strings.Contains(err.Error(), "URL is required") {
		t.Errorf("err = %v, want URL-required", err)
	}
}

// snapshotServer is a tiny httptest server that returns the latest
// snapshot the test pushes onto its channel. Each successful poll
// reads one value off the queue and returns it as JSON.
type snapshotServer struct {
	server   *httptest.Server
	requests atomic.Int32 // count of poll calls

	mu       chan struct{}
	snapshot revcheck.Snapshot
	status   int
}

func newSnapshotServer(t *testing.T) *snapshotServer {
	t.Helper()
	s := &snapshotServer{
		mu:     make(chan struct{}, 1),
		status: http.StatusOK,
	}
	s.mu <- struct{}{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		<-s.mu
		body, _ := json.Marshal(s.snapshot)
		status := s.status
		s.mu <- struct{}{}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *snapshotServer) set(snap revcheck.Snapshot) {
	<-s.mu
	s.snapshot = snap
	s.mu <- struct{}{}
}

func (s *snapshotServer) setStatus(code int) {
	<-s.mu
	s.status = code
	s.mu <- struct{}{}
}

func TestPollingChecker_FetchesAndReflectsSnapshot(t *testing.T) {
	srv := newSnapshotServer(t)
	srv.set(revcheck.Snapshot{
		CapturedAt: time.Now().UTC(),
		Entries: []revcheck.Revocation{
			{Serial: 42, Reason: "compromised"},
			{KeyID: "user:eve@example.com"},
		},
	})

	pc, err := revcheck.NewPollingChecker(revcheck.Config{
		URL:          srv.server.URL,
		PollInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPollingChecker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = pc.Run(ctx) }()

	// Wait for the first refresh to land.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, _, healthy := pc.Healthy()
		if healthy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !pc.IsRevoked(&gossh.Certificate{Serial: 42}) {
		t.Error("serial 42 should be revoked")
	}
	if !pc.IsRevoked(&gossh.Certificate{KeyId: "user:eve@example.com"}) {
		t.Error("KeyID lookup missed eve")
	}
	if pc.IsRevoked(&gossh.Certificate{Serial: 99}) {
		t.Error("serial 99 should not be revoked")
	}
}

func TestPollingChecker_KeepsLastGoodSnapshotOnFetchFailure(t *testing.T) {
	srv := newSnapshotServer(t)
	srv.set(revcheck.Snapshot{
		Entries: []revcheck.Revocation{{Serial: 7}},
	})

	pc, _ := revcheck.NewPollingChecker(revcheck.Config{
		URL:          srv.server.URL,
		PollInterval: 30 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() { _ = pc.Run(ctx) }()

	// Wait for the first successful refresh.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if pc.IsRevoked(&gossh.Certificate{Serial: 7}) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !pc.IsRevoked(&gossh.Certificate{Serial: 7}) {
		t.Fatal("initial refresh never landed")
	}

	// Switch certd to error mode; the previously-revoked serial
	// must still be refused.
	srv.setStatus(http.StatusInternalServerError)
	time.Sleep(150 * time.Millisecond) // give 4 poll cycles to fail
	if !pc.IsRevoked(&gossh.Certificate{Serial: 7}) {
		t.Error("stale snapshot dropped after fetch failures — opens revoked cert access")
	}
	_, lastErr, healthy := pc.Healthy()
	if healthy {
		t.Error("Healthy() should be false after fetch failures")
	}
	if lastErr == nil {
		t.Error("Healthy().lastErr should be populated")
	}
}

func TestPollingChecker_HandlesEmptySnapshot(t *testing.T) {
	srv := newSnapshotServer(t)
	srv.set(revcheck.Snapshot{}) // no Entries

	pc, _ := revcheck.NewPollingChecker(revcheck.Config{
		URL: srv.server.URL, PollInterval: 30 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go func() { _ = pc.Run(ctx) }()

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, _, ok := pc.Healthy(); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pc.IsRevoked(&gossh.Certificate{Serial: 1}) {
		t.Error("empty snapshot should revoke nothing")
	}
	if _, _, ok := pc.Healthy(); !ok {
		t.Error("Healthy() should be true for empty snapshot")
	}
}

func TestPollingChecker_IsRevoked_NilCert(t *testing.T) {
	pc, _ := revcheck.NewPollingChecker(revcheck.Config{URL: "http://localhost"})
	if pc.IsRevoked(nil) {
		t.Error("nil cert should not be revoked")
	}
}
