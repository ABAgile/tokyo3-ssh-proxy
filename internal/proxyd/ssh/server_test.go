package ssh_test

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
)

// silentLogger returns a logger that discards everything — keeps test
// output focused on assertions instead of structured-log noise.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// caBundle holds a freshly-generated user CA: an SSH signer to issue
// user certs and the matching public key for the server's trust
// anchor. Tests use one bundle per test to keep state isolated.
type caBundle struct {
	signer gossh.Signer
	pub    gossh.PublicKey
}

func newCA(t *testing.T) caBundle {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("ca keygen: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	return caBundle{signer: signer, pub: signer.PublicKey()}
}

// newHostSigner returns a fresh Ed25519 ssh.Signer suitable for use
// as the proxy's host key.
func newHostSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("host keygen: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	return signer
}

// newUserKey returns a fresh Ed25519 ssh.Signer suitable for use as a
// user's private key + public key.
func newUserKey(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("user keygen: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("user signer: %v", err)
	}
	return signer
}

// signUserCertWithSigner issues a User SSH cert binding userSigner's
// public key to principals, signed by ca's signer. Returns an
// ssh.Signer that presents the cert during client authentication.
// Validity defaults to ±1h around now; pass non-zero notBefore /
// notAfter to override (e.g., for expiry tests).
func signUserCertWithSigner(t *testing.T, ca caBundle, userSigner gossh.Signer, principals []string, notBefore, notAfter time.Time) gossh.Signer {
	t.Helper()
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}
	cert := &gossh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        gossh.UserCert,
		KeyId:           "user:test",
		ValidPrincipals: principals,
		ValidAfter:      uint64(notBefore.Unix()),
		ValidBefore:     uint64(notAfter.Unix()),
		Serial:          42,
		Permissions: gossh.Permissions{
			// Test default: grant the full standard set of permit-*
			// extensions. Tests that specifically exercise an RBAC
			// denial build their own cert with these omitted.
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-port-forwarding":  "",
				"permit-agent-forwarding": "",
				"permit-X11-forwarding":   "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := cert.SignCert(cryptorand.Reader, ca.signer); err != nil {
		t.Fatalf("sign user cert: %v", err)
	}
	certSigner, err := gossh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	return certSigner
}

// startServer brings up a Server bound to a kernel-assigned port,
// returns the address and a stop callback the test defers. The
// client-side signer + host-key callback are populated with stubs
// suitable for tests that don't reach a real target; tests that do
// pipe end-to-end use [startServerWithTarget] instead.
func startServer(t *testing.T, ca caBundle) (addr string, stop func()) {
	t.Helper()
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSigner:          newHostSigner(t), // stub — never reached when target dial fails
		TargetHostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()

	// Wait briefly for Addr() to populate.
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		cancel()
		t.Fatal("server did not bind within deadline")
	}
	return srv.Addr(), func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Fatal("server shutdown timeout")
		}
	}
}

// dialAsUser opens an SSH client connection authenticated with
// auth, against addr, requesting username.
func dialAsUser(addr string, username string, auth gossh.AuthMethod) (*gossh.Client, error) {
	cfg := &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{auth},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return gossh.Dial("tcp", addr, cfg)
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestNew_RejectsMissingConfig(t *testing.T) {
	host := newHostSigner(t)
	clientSigner := newHostSigner(t)
	ca := newCA(t)
	cb := gossh.InsecureIgnoreHostKey()
	tests := []struct {
		name string
		cfg  pssh.Config
		want string
	}{
		{
			"missing addr",
			pssh.Config{HostSigner: host, TrustedUserCA: ca.pub, ClientSigner: clientSigner, TargetHostKeyCallback: cb},
			"Addr is required",
		},
		{
			"missing host signer",
			pssh.Config{Addr: ":2222", TrustedUserCA: ca.pub, ClientSigner: clientSigner, TargetHostKeyCallback: cb},
			"HostSigner is required",
		},
		{
			"missing user ca",
			pssh.Config{Addr: ":2222", HostSigner: host, ClientSigner: clientSigner, TargetHostKeyCallback: cb},
			"TrustedUserCA is required",
		},
		{
			"missing client signer",
			pssh.Config{Addr: ":2222", HostSigner: host, TrustedUserCA: ca.pub, TargetHostKeyCallback: cb},
			"ClientSigner is required",
		},
		{
			"missing target host-key callback",
			pssh.Config{Addr: ":2222", HostSigner: host, TrustedUserCA: ca.pub, ClientSigner: clientSigner},
			"TargetHostKeyCallback is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pssh.New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestServer_AcceptsValidUserCert(t *testing.T) {
	// Handshake succeeds (cert is valid) but the target host doesn't
	// exist, so channel-open propagates "target unreachable" — this
	// proves the cert path works without needing a real backend.
	ca := newCA(t)
	addr, stop := startServer(t, ca)
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, err := dialAsUser(addr, "alice@127.0.0.1:1", gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Open a session — handshake succeeded so we know auth worked;
	// the channel is rejected because the (intentionally) bogus
	// target port can't be reached.
	_, err = client.NewSession()
	if err == nil {
		t.Fatal("expected NewSession to fail (target unreachable)")
	}
	if !strings.Contains(err.Error(), "target unreachable") {
		t.Errorf("expected target-unreachable rejection, got %v", err)
	}
}

func TestServer_RejectsMissingAtInUsername(t *testing.T) {
	// Username with no "@" can't be parsed into a target. The server
	// surfaces this as a handshake failure (early reject in
	// publicKeyCallback) so the user can't even open a session — fail
	// fast on malformed input.
	ca := newCA(t)
	addr, stop := startServer(t, ca)
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	// Bare "alice" — no "@", so publicKeyCallback returns the parse
	// error before the cert is even checked.
	_, err := dialAsUser(addr, "alice", gossh.PublicKeys(certSigner))
	if err == nil {
		t.Fatal("expected dial to fail (bad username)")
	}
}

func TestServer_RejectsUnsignedKey(t *testing.T) {
	ca := newCA(t)
	addr, stop := startServer(t, ca)
	defer stop()

	// User auths with a raw pubkey (no cert) — must be rejected
	// because the server's PublicKeyCallback only accepts certs.
	userSigner := newUserKey(t)
	_, err := dialAsUser(addr, "alice@target.invalid", gossh.PublicKeys(userSigner))
	if err == nil {
		t.Fatal("dial succeeded; server should reject non-cert keys")
	}
}

func TestServer_RejectsCertFromWrongCA(t *testing.T) {
	// Server trusts `caServer`; client presents a cert from `caOther`.
	caServer := newCA(t)
	caOther := newCA(t)
	addr, stop := startServer(t, caServer)
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, caOther, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	_, err := dialAsUser(addr, "alice@target.invalid", gossh.PublicKeys(certSigner))
	if err == nil {
		t.Fatal("dial succeeded; cert is from an untrusted CA")
	}
}

func TestServer_RejectsExpiredCert(t *testing.T) {
	ca := newCA(t)
	addr, stop := startServer(t, ca)
	defer stop()

	userSigner := newUserKey(t)
	past := time.Now().Add(-2 * time.Hour)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"},
		past, past.Add(time.Hour) /* expired an hour ago */)

	_, err := dialAsUser(addr, "alice@target.invalid", gossh.PublicKeys(certSigner))
	if err == nil {
		t.Fatal("dial succeeded; cert is expired")
	}
}

func TestServer_RejectsPrincipalMismatch(t *testing.T) {
	ca := newCA(t)
	addr, stop := startServer(t, ca)
	defer stop()

	userSigner := newUserKey(t)
	// Cert valid only for "alice"; client requests user "bob".
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	_, err := dialAsUser(addr, "bob@target.invalid", gossh.PublicKeys(certSigner))
	if err == nil {
		t.Fatal("dial succeeded; principal does not match requested user")
	}
}

func TestServer_RejectsHostCertAsUserAuth(t *testing.T) {
	// A host cert is not valid for user authentication; the server
	// must reject CertType=HostCert.
	ca := newCA(t)
	addr, stop := startServer(t, ca)
	defer stop()

	userSigner := newUserKey(t)
	cert := &gossh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        gossh.HostCert, // wrong type
		KeyId:           "host:test",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Serial:          1,
	}
	if err := cert.SignCert(cryptorand.Reader, ca.signer); err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	certSigner, err := gossh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	if _, err := dialAsUser(addr, "alice@target.invalid", gossh.PublicKeys(certSigner)); err == nil {
		t.Fatal("dial succeeded; host cert should not be accepted for user auth")
	}
}

func TestServer_GracefulShutdownWaitsForInFlight(t *testing.T) {
	// Start the server, open a connection, cancel ctx, confirm the
	// listener closes cleanly without leaking goroutines for the
	// (placeholder-rejected) in-flight session.
	ca := newCA(t)
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSigner:          newHostSigner(t),
		TargetHostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()

	// Wait for bind.
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		cancel()
		t.Fatal("server did not bind")
	}

	// Briefly connect (and close) so a handshake-in-flight goroutine
	// exists. With ssh, the connection setup is synchronous from the
	// client side, so by the time Dial returns the server's
	// handshake goroutine is already running.
	userSigner := newUserKey(t)
	cs := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})
	c, err := dialAsUser(srv.Addr(), "alice@target.invalid", gossh.PublicKeys(cs))
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()

	cancel()
	select {
	case err := <-done:
		// nil = clean shutdown via context; tolerant of net.ErrClosed
		// being wrapped in net.OpError under some Go versions.
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("ListenAndServe returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}
}
