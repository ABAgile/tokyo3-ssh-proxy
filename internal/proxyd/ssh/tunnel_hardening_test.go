package ssh_test

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	gossh "golang.org/x/crypto/ssh"

	commontunnel "github.com/abagile/tokyo3-ssh-proxy/internal/common/tunnel"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/routing"
	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/forward"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/tunnel"
)

// hardenedStack bundles the components the hardening tests drive.
// Mirrors the TestEndToEnd_TunnelRoutedSession setup but exposes
// each piece so tests can poke individual layers (close the live
// tunnel, swap the local sshd, etc.).
type hardenedStack struct {
	t           *testing.T
	ca          caBundle
	target      *fakeTarget
	proxyClient gossh.Signer
	registry    *routing.Registry
	tunnelAddr  string
	tunneldDial *tunnel.Dialer
	srvAddr     string
	hostLabel   string
	certSigner  gossh.Signer
}

func newHardenedStack(t *testing.T) *hardenedStack {
	t.Helper()
	ca := newCA(t)
	proxyClient := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClient.PublicKey())

	hostLabel := "db-1.prod"
	spiffeURI := "spiffe://tokyo3.example/host/" + hostLabel
	tunneldTLS, proxyTLS := mintWorkloadTLS(t, spiffeURI)

	registry := routing.New()
	t.Cleanup(func() { _ = registry.Close() })

	listener, err := routing.NewListener(routing.ListenerConfig{
		Addr:      "127.0.0.1:0",
		TLSConfig: proxyTLS,
		Registry:  registry,
		Log:       silentLogger(),
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	tunnelLn, err := tls.Listen("tcp", "127.0.0.1:0", proxyTLS)
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	t.Cleanup(func() { _ = tunnelLn.Close() })
	tunnelAddr := tunnelLn.Addr().String()
	listenerCtx, cancelListener := context.WithCancel(context.Background())
	t.Cleanup(cancelListener)
	go func() { _ = listener.Serve(listenerCtx, tunnelLn) }()

	fwd := forward.New(forward.Config{
		LocalAddr: target.addr,
		Log:       silentLogger(),
	})
	dialer, err := tunnel.New(tunnel.Config{
		Target:         tunnelAddr,
		TLSConfig:      tunneldTLS,
		Handler:        fwd.Handle,
		Log:            silentLogger(),
		InitialBackoff: 30 * time.Millisecond,
		MaxBackoff:     150 * time.Millisecond,
		BackoffJitter:  0.1,
	})
	if err != nil {
		t.Fatalf("tunnel.New: %v", err)
	}
	dialerCtx, cancelDialer := context.WithCancel(context.Background())
	t.Cleanup(cancelDialer)
	go func() { _ = dialer.Run(dialerCtx) }()

	waitForRegistration(t, registry, hostLabel, 3*time.Second)

	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClient),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		TunnelRegistry:        registry,
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	srvCtx, cancelSrv := context.WithCancel(context.Background())
	t.Cleanup(cancelSrv)
	go func() { _ = srv.ListenAndServe(srvCtx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		t.Fatal("proxy SSH server did not bind")
	}

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	return &hardenedStack{
		t:           t,
		ca:          ca,
		target:      target,
		proxyClient: proxyClient,
		registry:    registry,
		tunnelAddr:  tunnelAddr,
		tunneldDial: dialer,
		srvAddr:     srv.Addr(),
		hostLabel:   hostLabel,
		certSigner:  certSigner,
	}
}

// runEchoSession dials the proxy and round-trips one exec session,
// returning the response body so the caller can assert on it.
func (s *hardenedStack) runEchoSession() (string, error) {
	client, err := dialAsUser(s.srvAddr, "alice@"+s.hostLabel, gossh.PublicKeys(s.certSigner))
	if err != nil {
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output("anything")
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return "", err
	}
	return string(out), nil
}

// waitForRegistration polls the registry until a tunnel for label is
// registered or the deadline expires.
func waitForRegistration(t *testing.T, r *routing.Registry, label string, max time.Duration) *yamux.Session {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if s, err := r.Lookup(label); err == nil {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("registry never registered %q within %v", label, max)
	return nil
}

// waitForReplacement polls the registry until the registered session
// for label is different from `prev` (i.e., a reconnect happened).
func waitForReplacement(t *testing.T, r *routing.Registry, label string, prev *yamux.Session, max time.Duration) *yamux.Session {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if s, err := r.Lookup(label); err == nil && s != prev {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("registry never saw replacement session for %q within %v (still has previous)", label, max)
	return nil
}

func TestHardening_ReconnectsAfterTunnelPartition(t *testing.T) {
	// Kill the live tunnel out from under both sides, then verify a
	// fresh session through the same host label works once the
	// dialer has reconnected. Exercises:
	//   - dialer.Run's reconnect loop
	//   - listener's defer Unregister
	//   - registry's dead-session eviction during Register
	stack := newHardenedStack(t)

	// First session goes through the freshly-registered tunnel.
	if out, err := stack.runEchoSession(); err != nil {
		t.Fatalf("first session: %v", err)
	} else if out != echoResponse {
		t.Errorf("first session output = %q, want %q", out, echoResponse)
	}

	// Yank the live session — the dialer + listener should rebuild.
	original := waitForRegistration(t, stack.registry, stack.hostLabel, time.Second)
	_ = original.Close()

	// Wait for the registry to acquire a fresh registration under
	// the same label. waitForReplacement also asserts the new entry
	// is a different *yamux.Session pointer.
	_ = waitForReplacement(t, stack.registry, stack.hostLabel, original, 3*time.Second)

	// Second session through the new tunnel.
	if out, err := stack.runEchoSession(); err != nil {
		t.Fatalf("second session after partition: %v", err)
	} else if out != echoResponse {
		t.Errorf("second session output = %q, want %q", out, echoResponse)
	}
}

func TestHardening_LocalTargetUnreachableDoesNotKillTunnel(t *testing.T) {
	// Stand up the full stack, but the local sshd is unreachable
	// (the fake target's listener is closed before any session
	// attempt). The user-side session must fail with target-
	// unreachable, but the yamux tunnel itself must stay registered
	// — the forwarder closes only the failed stream.
	ca := newCA(t)
	proxyClient := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClient.PublicKey())

	// Close the target's listener so forwarder's dial fails for
	// every inbound stream.
	_ = target.listener.Close()

	hostLabel := "db-down"
	spiffeURI := "spiffe://tokyo3.example/host/" + hostLabel
	tunneldTLS, proxyTLS := mintWorkloadTLS(t, spiffeURI)

	registry := routing.New()
	t.Cleanup(func() { _ = registry.Close() })

	listener, _ := routing.NewListener(routing.ListenerConfig{
		Addr: "127.0.0.1:0", TLSConfig: proxyTLS, Registry: registry, Log: silentLogger(),
	})
	tunnelLn, _ := tls.Listen("tcp", "127.0.0.1:0", proxyTLS)
	t.Cleanup(func() { _ = tunnelLn.Close() })
	lctx, lcancel := context.WithCancel(context.Background())
	t.Cleanup(lcancel)
	go func() { _ = listener.Serve(lctx, tunnelLn) }()

	fwd := forward.New(forward.Config{LocalAddr: target.addr, DialTimeout: 100 * time.Millisecond, Log: silentLogger()})
	dialer, _ := tunnel.New(tunnel.Config{
		Target: tunnelLn.Addr().String(), TLSConfig: tunneldTLS,
		Handler: fwd.Handle, Log: silentLogger(),
		InitialBackoff: 30 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, BackoffJitter: 0.1,
	})
	dctx, dcancel := context.WithCancel(context.Background())
	t.Cleanup(dcancel)
	go func() { _ = dialer.Run(dctx) }()

	tunnelSess := waitForRegistration(t, registry, hostLabel, 3*time.Second)

	srv, _ := pssh.New(pssh.Config{
		Addr: "127.0.0.1:0", Log: silentLogger(),
		HostSigner: newHostSigner(t), TrustedUserCA: ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClient),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		TunnelRegistry:        registry,
	})
	sctx, scancel := context.WithCancel(context.Background())
	t.Cleanup(scancel)
	go func() { _ = srv.ListenAndServe(sctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	// User attempt fails — but client.NewSession() is what surfaces
	// the rejection (the channel-open returns ConnectionFailed).
	client, err := dialAsUser(srv.Addr(), "alice@"+hostLabel, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	_, err = client.NewSession()
	if err == nil {
		t.Error("expected NewSession to fail when local sshd is down")
	}
	_ = client.Close()

	// The tunnel itself must still be registered + live.
	stillThere, err := registry.Lookup(hostLabel)
	if err != nil {
		t.Fatalf("tunnel was unregistered after target failure: %v", err)
	}
	if stillThere != tunnelSess {
		t.Errorf("tunnel session was replaced after target failure (forwarder shouldn't kill the session)")
	}
	if stillThere.IsClosed() {
		t.Error("tunnel session reports closed after target failure")
	}
}

func TestHardening_RegistryDeadSessionEvictionUnblocksReconnect(t *testing.T) {
	// Unit-level cousin of ReconnectsAfterTunnelPartition: drive the
	// listener directly with an mTLS+yamux client, kill the session
	// from the dial side, and verify a fresh client can register
	// under the same host label even before the listener's deferred
	// Unregister has had a chance to fire.
	const hostLabel = "race-host"
	const spiffeURI = "spiffe://tokyo3.example/host/" + hostLabel
	clientTLS, serverTLS := mintWorkloadTLS(t, spiffeURI)

	registry := routing.New()
	t.Cleanup(func() { _ = registry.Close() })

	l, _ := routing.NewListener(routing.ListenerConfig{
		Addr: "127.0.0.1:0", TLSConfig: serverTLS, Registry: registry, Log: silentLogger(),
	})
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = l.Serve(ctx, ln) }()

	// First connection.
	c1, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial 1: %v", err)
	}
	s1, err := yamux.Client(c1, commontunnel.ClientConfig())
	if err != nil {
		t.Fatalf("yamux 1: %v", err)
	}
	first := waitForRegistration(t, registry, hostLabel, 2*time.Second)

	// Kill it.
	_ = s1.Close()
	_ = c1.Close()

	// Without waiting for the listener's deferred Unregister to
	// fire, immediately reconnect — Register must succeed by
	// evicting the dead session in-place.
	c2, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial 2: %v", err)
	}
	s2, err := yamux.Client(c2, commontunnel.ClientConfig())
	if err != nil {
		t.Fatalf("yamux 2: %v", err)
	}
	defer s2.Close()

	second := waitForReplacement(t, registry, hostLabel, first, 3*time.Second)
	if second == first {
		t.Error("registry did not pick up the replacement session")
	}
}
