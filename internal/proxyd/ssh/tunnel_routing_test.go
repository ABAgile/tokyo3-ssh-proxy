package ssh_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/routing"
	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/forward"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/tunnel"
)

// mintWorkloadTLS returns matched (client, server) TLS configs for
// the tunnel mTLS handshake. The client cert carries the supplied
// SPIFFE URI so the proxy's listener can derive the host label.
func mintWorkloadTLS(t *testing.T, spiffeURI string) (clientTLS, serverTLS *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("workload keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: spiffeURI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:        true,
	}
	u, _ := url.Parse(spiffeURI)
	tmpl.URIs = []*url.URL{u}

	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)

	clientTLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
	serverTLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	return
}

// TestEndToEnd_TunnelRoutedSession proves the full stack composes correctly:
// an ssh-tunneld-like agent dials the proxy listener, registers under
// a SPIFFE-derived host label, and a user SSH session through ssh-proxyd
// reaches the target sshd by way of the registered yamux tunnel instead of
// a direct TCP dial.
func TestEndToEnd_TunnelRoutedSession(t *testing.T) {
	// ── SSH-side material ─────────────────────────────────────────
	// Shared SSH CA used to sign the user's authentication cert.
	ca := newCA(t)
	// Key the proxy authenticates to the target sshd with.
	proxyClientSigner := newHostSigner(t)
	// Stand-in for the local sshd on the target host. The forwarder
	// running inside our fake tunneld will dial this address for
	// every inbound yamux stream.
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	// ── Workload mTLS material for the tunnel handshake ──────────
	// SPIFFE URI shape matches certd's host-cert issuance convention;
	// the listener's default extractor parses "/host/<fqdn>" out of it.
	const hostLabel = "db-1.prod"
	const spiffeURI = "spiffe://tokyo3.example/host/" + hostLabel
	tunneldTLS, proxyTLS := mintWorkloadTLS(t, spiffeURI)

	// ── Proxy tunnel listener ────────────────────────────────────
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
	listenerDone := make(chan error, 1)
	go func() { listenerDone <- listener.Serve(listenerCtx, tunnelLn) }()

	// ── ssh-tunneld-like agent ────────────────────────────────────
	// Forwarder dials the fake target for every inbound stream.
	fwd := forward.New(forward.Config{
		LocalAddr: target.addr,
		Log:       silentLogger(),
	})

	dialer, err := tunnel.New(tunnel.Config{
		Target:    tunnelAddr,
		TLSConfig: tunneldTLS,
		Handler:   fwd.Handle,
		Log:       silentLogger(),
		// Short backoffs so the test doesn't spend seconds idle if
		// the first dial races with the listener accept goroutine.
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
		BackoffJitter:  0.1,
	})
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}

	dialerCtx, cancelDialer := context.WithCancel(context.Background())
	t.Cleanup(cancelDialer)
	dialerDone := make(chan error, 1)
	go func() { dialerDone <- dialer.Run(dialerCtx) }()

	// Wait for the tunnel to land in the registry under the SPIFFE-
	// derived host label.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := registry.Lookup(hostLabel); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := registry.Lookup(hostLabel); err != nil {
		t.Fatalf("registry never registered %q: %v", hostLabel, err)
	}

	// ── ssh-proxyd SSH server with the registry plumbed in ───────
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClientSigner),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		TunnelRegistry:        registry,
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	srvCtx, cancelSrv := context.WithCancel(context.Background())
	t.Cleanup(cancelSrv)
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.ListenAndServe(srvCtx) }()

	deadline = time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		t.Fatal("proxy SSH server did not bind")
	}

	// ── User SSH session ─────────────────────────────────────────
	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	// Dial the proxy using the SPIFFE-derived host label as the
	// destination. The proxy looks it up in the registry, opens a
	// yamux stream toward the fake tunneld, and the forwarder pipes
	// the SSH handshake bytes to the fake target.
	client, err := dialAsUser(srv.Addr(), "alice@"+hostLabel, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("anything")
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("session.Output: %v", err)
	}
	if got := string(out); got != echoResponse {
		t.Errorf("session output = %q, want %q", got, echoResponse)
	}

	// Target saw the same remote user we passed in the SSH username.
	if target.gotUser != "alice" {
		t.Errorf("target saw user %q, want alice", target.gotUser)
	}

	// Drop client side before the t.Cleanup chain tears down the
	// server — the graceful-shutdown path waits for in-flight
	// sessions, and the client hasn't called Close yet from its
	// defer. Closing here keeps the cleanup fast and bounded.
	_ = sess.Close()
	_ = client.Close()

	// Surface stray errors from the three long-running goroutines.
	// All exits are driven by t.Cleanup running cancelSrv etc.;
	// here we just make sure no unexpected error leaked from any of
	// the .Run loops while the session was in flight.
	for i, done := range [...]chan error{srvDone, dialerDone, listenerDone} {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("background goroutine %d err = %v", i, err)
			}
		default:
			// Still running — t.Cleanup will tear it down.
		}
	}
}

// TestEndToEnd_TunnelRoutedSession_FallsBackToDirectTCPWhenUnregistered
// verifies the "tunnel-first, TCP-fallback" contract documented in
// pssh.Server.tunnelTransport. An unrelated host label gets no tunnel
// registration, so the proxy must dial the target directly — proving
// hybrid deployments (some tunneled, some direct) work without
// per-host config.
func TestEndToEnd_TunnelRoutedSession_FallsBackToDirectTCPWhenUnregistered(t *testing.T) {
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	// Registry exists but is empty — every dial should fall through.
	registry := routing.New()
	t.Cleanup(func() { _ = registry.Close() })

	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClientSigner),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		TunnelRegistry:        registry,
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ListenAndServe(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, err := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer client.Close()
	sess, _ := client.NewSession()
	defer sess.Close()
	out, _ := sess.Output("anything")
	if got := string(out); got != echoResponse {
		t.Errorf("output = %q, want %q (TCP fallback path)", got, echoResponse)
	}
}
