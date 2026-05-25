package routing_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	commontunnel "github.com/abagile/tokyo3-ssh-proxy/internal/common/tunnel"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/routing"
)

// twoSessions returns a live (client, server) yamux pair over net.Pipe
// plus a cleanup func. The server side is what would normally be
// registered (it represents the proxy-side handle to the inbound
// tunnel from ssh-tunneld).
func twoSessions(t *testing.T) (clientSide, serverSide *yamux.Session) {
	t.Helper()
	cConn, sConn := net.Pipe()

	type sessOrErr struct {
		s   *yamux.Session
		err error
	}
	clientCh := make(chan sessOrErr, 1)
	serverCh := make(chan sessOrErr, 1)
	go func() {
		s, err := yamux.Client(cConn, commontunnel.ClientConfig())
		clientCh <- sessOrErr{s, err}
	}()
	go func() {
		s, err := yamux.Server(sConn, commontunnel.ServerConfig())
		serverCh <- sessOrErr{s, err}
	}()
	cr, sr := <-clientCh, <-serverCh
	if cr.err != nil || sr.err != nil {
		t.Fatalf("yamux handshake: client=%v server=%v", cr.err, sr.err)
	}
	t.Cleanup(func() {
		_ = cr.s.Close()
		_ = sr.s.Close()
		_ = cConn.Close()
		_ = sConn.Close()
	})
	return cr.s, sr.s
}

func TestRegistry_RegisterLookup_RoundTrip(t *testing.T) {
	r := routing.New()
	_, sess := twoSessions(t)

	got, err := r.Register(sess, "db-1.prod", "db-1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"db-1.prod", "db-1"}) {
		t.Errorf("inserted labels = %v", got)
	}
	if r.Len() != 2 {
		t.Errorf("Len = %d, want 2", r.Len())
	}

	// Both labels resolve to the same session.
	for _, h := range []string{"db-1.prod", "db-1"} {
		s, err := r.Lookup(h)
		if err != nil {
			t.Errorf("Lookup(%q): %v", h, err)
		}
		if s != sess {
			t.Errorf("Lookup(%q) = %v, want %v", h, s, sess)
		}
	}

	// Case folding works.
	if _, err := r.Lookup("DB-1"); err != nil {
		t.Errorf("case-insensitive lookup: %v", err)
	}
	if _, err := r.Lookup("  db-1.prod  "); err != nil {
		t.Errorf("whitespace-trim lookup: %v", err)
	}
}

func TestRegistry_Lookup_NoTunnelReturnsSentinel(t *testing.T) {
	r := routing.New()
	_, err := r.Lookup("nope")
	if !errors.Is(err, routing.ErrNoTunnel) {
		t.Errorf("err = %v, want ErrNoTunnel", err)
	}
}

func TestRegistry_Register_RejectsConflictingHost(t *testing.T) {
	r := routing.New()
	_, sessA := twoSessions(t)
	_, sessB := twoSessions(t)

	if _, err := r.Register(sessA, "db-1"); err != nil {
		t.Fatalf("Register A: %v", err)
	}
	_, err := r.Register(sessB, "db-1")
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("err = %v, want conflict", err)
	}
	// SessA still resolves — rollback worked.
	if s, _ := r.Lookup("db-1"); s != sessA {
		t.Errorf("Lookup after rejected conflict returned wrong session")
	}
}

func TestRegistry_Register_AtomicOnConflict(t *testing.T) {
	r := routing.New()
	_, sessA := twoSessions(t)
	_, sessB := twoSessions(t)

	_, _ = r.Register(sessA, "host-x")
	_, err := r.Register(sessB, "host-y", "host-x") // host-x conflicts
	if err == nil {
		t.Fatal("expected conflict error")
	}
	// host-y must NOT have been registered (partial state would be a bug).
	if _, err := r.Lookup("host-y"); !errors.Is(err, routing.ErrNoTunnel) {
		t.Errorf("partial registration leaked: %v", err)
	}
}

func TestRegistry_Register_EvictsDeadSessionUnderSameLabel(t *testing.T) {
	// A tunnel that died and is reconnecting under the same host
	// label must not hit a stale "already registered" conflict —
	// otherwise the dialer loops indefinitely while waiting for the
	// listener's deferred Unregister to fire.
	r := routing.New()
	_, oldSess := twoSessions(t)
	_, newSess := twoSessions(t)

	if _, err := r.Register(oldSess, "db-1"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	_ = oldSess.Close()
	time.Sleep(10 * time.Millisecond) // yamux IsClosed flip

	if _, err := r.Register(newSess, "db-1"); err != nil {
		t.Errorf("re-register after old session died: %v", err)
	}
	if s, _ := r.Lookup("db-1"); s != newSess {
		t.Errorf("Lookup after reconnect returned wrong session")
	}
}

func TestRegistry_Register_AcceptsSameSessionAdditionalLabels(t *testing.T) {
	r := routing.New()
	_, sess := twoSessions(t)

	if _, err := r.Register(sess, "alpha"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if _, err := r.Register(sess, "beta", "alpha"); err != nil {
		t.Errorf("re-registering same session under additional labels: %v", err)
	}
	if r.Len() != 2 {
		t.Errorf("Len = %d, want 2", r.Len())
	}
}

func TestRegistry_Register_RejectsEmptyAndNilInputs(t *testing.T) {
	r := routing.New()
	if _, err := r.Register(nil, "x"); err == nil {
		t.Error("nil session should be rejected")
	}
	_, sess := twoSessions(t)
	if _, err := r.Register(sess); err == nil {
		t.Error("zero hosts should be rejected")
	}
	if _, err := r.Register(sess, ""); err == nil {
		t.Error("empty host label should be rejected")
	}
	if _, err := r.Register(sess, "   "); err == nil {
		t.Error("whitespace-only host label should be rejected")
	}
}

func TestRegistry_Unregister_DropsAllLabelsForSession(t *testing.T) {
	r := routing.New()
	_, sess := twoSessions(t)
	_, _ = r.Register(sess, "a", "b", "c")
	if r.Len() != 3 {
		t.Fatalf("Len = %d, want 3", r.Len())
	}
	r.Unregister(sess)
	if r.Len() != 0 {
		t.Errorf("Len after Unregister = %d, want 0", r.Len())
	}
	if _, err := r.Lookup("a"); !errors.Is(err, routing.ErrNoTunnel) {
		t.Errorf("post-unregister Lookup err = %v", err)
	}
}

func TestRegistry_Lookup_ScrubsDeadSession(t *testing.T) {
	r := routing.New()
	_, sess := twoSessions(t)
	_, _ = r.Register(sess, "doomed")

	// Closing the session marks it dead; the next Lookup should
	// surface ErrNoTunnel and clean the entry up.
	_ = sess.Close()
	// Give yamux a moment to flip IsClosed; closing is sync but
	// keepalive teardown may need a beat on slow runners.
	time.Sleep(10 * time.Millisecond)

	if _, err := r.Lookup("doomed"); !errors.Is(err, routing.ErrNoTunnel) {
		t.Errorf("Lookup of dead session = %v, want ErrNoTunnel", err)
	}
	if r.Len() != 0 {
		t.Errorf("Len after dead-session scrub = %d, want 0", r.Len())
	}
}

func TestRegistry_Open_ReturnsLiveStream(t *testing.T) {
	r := routing.New()
	cliSide, srvSide := twoSessions(t)
	_, _ = r.Register(srvSide, "host-1")

	// Server-side (registered) calls Open → produces a stream the
	// client side can Accept.
	acceptCh := make(chan *yamux.Stream, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := cliSide.AcceptStream()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- s
	}()

	conn, err := r.Open(context.Background(), "host-1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	select {
	case s := <-acceptCh:
		_ = s.Close()
	case err := <-errCh:
		t.Fatalf("AcceptStream: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("client never saw stream")
	}
}

func TestRegistry_Open_NoTunnelReturnsSentinel(t *testing.T) {
	r := routing.New()
	_, err := r.Open(context.Background(), "ghost")
	if !errors.Is(err, routing.ErrNoTunnel) {
		t.Errorf("err = %v, want ErrNoTunnel", err)
	}
}

func TestRegistry_Open_RespectsContextCancellation(t *testing.T) {
	r := routing.New()
	_, sess := twoSessions(t)
	_, _ = r.Register(sess, "host")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.Open(ctx, "host")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRegistry_Close_ClosesEverySessionOnce(t *testing.T) {
	r := routing.New()
	_, sessA := twoSessions(t)
	_, sessB := twoSessions(t)
	_, _ = r.Register(sessA, "a1", "a2")
	_, _ = r.Register(sessB, "b1")

	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !sessA.IsClosed() || !sessB.IsClosed() {
		t.Error("Close did not close all sessions")
	}
	// Subsequent registers fail.
	if _, err := r.Register(sessA, "z"); err == nil {
		t.Error("Register after Close should fail")
	}
	// Second Close is a no-op.
	if err := r.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestRegistry_ConcurrentRegisterLookup(t *testing.T) {
	r := routing.New()
	const n = 32

	sessions := make([]*yamux.Session, n)
	for i := 0; i < n; i++ {
		_, s := twoSessions(t)
		sessions[i] = s
	}

	var wg sync.WaitGroup
	wg.Add(n * 2)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			label := hostLabel(i)
			if _, err := r.Register(sessions[i], label); err != nil {
				t.Errorf("Register %d: %v", i, err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			// Poll until visible — racing with the Register half.
			label := hostLabel(i)
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if s, err := r.Lookup(label); err == nil {
					if s != sessions[i] {
						t.Errorf("Lookup %d returned wrong session", i)
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Errorf("Lookup %d never resolved", i)
		}(i)
	}
	wg.Wait()
	if r.Len() != n {
		t.Errorf("Len = %d, want %d", r.Len(), n)
	}
}

func hostLabel(i int) string {
	return "h" + indexString(i)
}

// indexString is a small itoa to avoid pulling in strconv in test
// only code.
func indexString(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [4]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
