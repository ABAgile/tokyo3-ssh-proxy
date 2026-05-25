package ssh_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/revcheck"
	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
)

// fakeCertdRevocations stands in for certd's GET /api/v1/ssh/revocations
// endpoint. Tests push entries into snap; the next poll picks them
// up + revcheck.PollingChecker's IsRevoked starts returning true
// for matching serials/KeyIDs.
type fakeCertdRevocations struct {
	server *httptest.Server

	mu   sync.Mutex
	snap revcheck.Snapshot
}

func newFakeCertdRevocations(t *testing.T) *fakeCertdRevocations {
	t.Helper()
	f := &fakeCertdRevocations{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/ssh/revocations" {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		snap := f.snap
		snap.CapturedAt = time.Now().UTC()
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeCertdRevocations) revoke(serial uint64, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap.Entries = append(f.snap.Entries, revcheck.Revocation{
		Serial: serial, Reason: reason, Revoked: time.Now().UTC(),
	})
}

// TestEndToEnd_RevocationEnforcementPropagatesToHandshake is the
// capstone integration for the revocation loop:
//
//   - 6.2: certd records the revocation (here, the fake endpoint).
//   - 6.3: ssh-proxyd's PollingChecker tails the snapshot.
//   - SSH server's CertChecker.IsRevoked consults the checker.
//
// The test pushes a cert's serial into the fake certd, waits for the
// poll cycle to refresh, and confirms the next handshake using that
// cert is refused. Without this test the per-layer unit coverage
// could each pass while the wiring between them silently broke.
func TestEndToEnd_RevocationEnforcementPropagatesToHandshake(t *testing.T) {
	fakeCertd := newFakeCertdRevocations(t)

	// Tight poll interval so the test doesn't wait 30s for the
	// real-world default. Pre-fetch one snapshot so we know the
	// checker is healthy before the first session.
	checker, err := revcheck.NewPollingChecker(revcheck.Config{
		URL:          fakeCertd.server.URL + "/api/v1/ssh/revocations",
		PollInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPollingChecker: %v", err)
	}
	ctx := t.Context()
	go func() { _ = checker.Run(ctx) }()

	// Wait for the first refresh to land (signals the polling
	// goroutine has wired itself up to certd's HTTP server).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := checker.Healthy(); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, ok := checker.Healthy(); !ok {
		t.Fatal("PollingChecker never reported healthy")
	}

	ca := newCA(t)
	proxyClient := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClient.PublicKey())

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
	srvCtx := t.Context()
	go func() { _ = srv.ListenAndServe(srvCtx) }()
	deadline = time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		t.Fatal("proxy SSH server did not bind")
	}

	userSigner := newUserKey(t)
	// signUserCertWithSigner stamps every cert with Serial=42 —
	// the revocation set we push needs to match that number.
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	// 1. Initial session works — cert is unrevoked.
	client, err := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("initial NewSession: %v", err)
	}
	out, err := sess.Output("anything")
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("initial session: %v", err)
	}
	if string(out) != echoResponse {
		t.Errorf("initial session output = %q, want %q", string(out), echoResponse)
	}
	_ = sess.Close()
	_ = client.Close()

	// 2. Revoke the cert via the fake certd endpoint.
	fakeCertd.revoke(42, "e2e test revoked")

	// 3. Wait for the poller to pick it up. Two complete poll
	//    cycles should be sufficient; we assert via IsRevoked on
	//    a stub cert with the same Serial.
	probeCert := &gossh.Certificate{Serial: 42}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if checker.IsRevoked(probeCert) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !checker.IsRevoked(probeCert) {
		t.Fatal("PollingChecker never observed the revoked serial within the deadline")
	}

	// 4. Next session: same cert, but now the proxy's
	//    CertChecker.IsRevoked refuses it at handshake.
	_, err = dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err == nil {
		t.Fatal("expected handshake to fail after revocation")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "auth") {
		t.Errorf("err = %v, want auth-style failure", err)
	}

	// 5. Health predicate still surfaces success — the failure
	//    above happened at SSH handshake, not at the revocation-
	//    refresh layer.
	if _, _, ok := checker.Healthy(); !ok {
		t.Error("PollingChecker should still report healthy after a successful poll")
	}
}

// TestEndToEnd_RevocationByKeyID covers the alternative match path:
// the revocation set names the cert by KeyID instead of Serial. The
// SSH cert's KeyId field is what certd's audit attribution surfaces,
// so operators commonly revoke by it when the serial isn't handy.
func TestEndToEnd_RevocationByKeyID(t *testing.T) {
	fakeCertd := newFakeCertdRevocations(t)
	// Pre-populate with the KeyID the test cert helper stamps
	// every cert with ("user:test"). When the checker refreshes,
	// the very first session must already be refused.
	fakeCertd.revoke(0 /* no serial */, "by-keyid revocation")
	fakeCertd.mu.Lock()
	fakeCertd.snap.Entries[0].KeyID = "user:test"
	fakeCertd.snap.Entries[0].Serial = 0
	fakeCertd.mu.Unlock()

	checker, _ := revcheck.NewPollingChecker(revcheck.Config{
		URL:          fakeCertd.server.URL + "/api/v1/ssh/revocations",
		PollInterval: 50 * time.Millisecond,
	})
	ctx := t.Context()
	go func() { _ = checker.Run(ctx) }()

	// Wait for the snapshot to land in-memory.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if checker.IsRevoked(&gossh.Certificate{KeyId: "user:test"}) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !checker.IsRevoked(&gossh.Certificate{KeyId: "user:test"}) {
		t.Fatal("checker didn't pick up the by-KeyID revocation")
	}

	ca := newCA(t)
	proxyClient := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClient.PublicKey())
	srv, _ := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClient),
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
		Revocations:           checker,
	})
	srvCtx := t.Context()
	go func() { _ = srv.ListenAndServe(srvCtx) }()
	deadline = time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	_, err := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err == nil {
		t.Fatal("expected handshake to fail with KeyID-based revocation")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "auth") {
		t.Errorf("err = %v, want auth-style failure", err)
	}
}
