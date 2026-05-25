package ssh_test

import (
	"context"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/revcheck"
	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
)

// stubRevoker is the test double for [revcheck.Checker]: revoked
// returns true when called.
type stubRevoker struct {
	revoked bool
}

func (s *stubRevoker) IsRevoked(*gossh.Certificate) bool { return s.revoked }

func startServerWithRevocations(t *testing.T, ca caBundle, target *fakeTarget, proxyClient gossh.Signer, checker revcheck.Checker) (addr string, stop func()) {
	t.Helper()
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClient),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		Revocations:           checker,
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
	return srv.Addr(), func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Fatal("server shutdown timeout")
		}
	}
}

func TestServer_RefusesRevokedCert(t *testing.T) {
	// User presents an otherwise-valid cert, but the Revocations
	// store reports it revoked. The handshake must fail with an
	// authentication error rather than open a session.
	ca := newCA(t)
	proxyClient := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClient.PublicKey())

	addr, stop := startServerWithRevocations(t, ca, target, proxyClient, &stubRevoker{revoked: true})
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	_, err := dialAsUser(addr, "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err == nil {
		t.Fatal("expected auth failure when cert is revoked")
	}
	// gossh surfaces revocation as a generic auth-failed; the
	// exact message comes from the CertChecker.IsRevoked path
	// ("certificate serial N revoked").
	if !strings.Contains(strings.ToLower(err.Error()), "auth") {
		t.Errorf("err = %v, want an auth-style failure", err)
	}
}

func TestServer_AcceptsCertWhenNotRevoked(t *testing.T) {
	// Sanity check: a stubRevoker returning false leaves the
	// handshake working exactly as before. Without this we'd have
	// no proof that wiring the IsRevoked callback didn't break the
	// happy path for unrevoked certs.
	ca := newCA(t)
	proxyClient := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClient.PublicKey())

	addr, stop := startServerWithRevocations(t, ca, target, proxyClient, &stubRevoker{revoked: false})
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, err := dialAsUser(addr, "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("expected handshake to succeed for unrevoked cert: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	out, _ := sess.Output("anything")
	if string(out) != echoResponse {
		t.Errorf("session output = %q, want %q", string(out), echoResponse)
	}
}

// Compile-time: stubRevoker satisfies revcheck.Checker.
var _ revcheck.Checker = (*stubRevoker)(nil)
