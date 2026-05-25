package hostcert_test

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/common/certclient"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/hostcert"
)

// writeHostPrivateKey writes a fresh ed25519 OpenSSH-encoded private
// key at path and returns the matching public key in
// authorized_keys form for round-trip assertions.
func writeHostPrivateKey(t *testing.T, path string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("derive signer: %v", err)
	}
	return gossh.MarshalAuthorizedKey(signer.PublicKey())
}

// stubSigner is the [hostcert.Signer] test double.
type stubSigner struct {
	mu        sync.Mutex
	calls     int32
	gotReq    certclient.SignHostRequest
	respFn    func(certclient.SignHostRequest) (*certclient.SignHostResponse, error)
	respondCh chan struct{} // optional: release one response per signal
}

func (s *stubSigner) SignHostCert(_ context.Context, req certclient.SignHostRequest) (*certclient.SignHostResponse, error) {
	s.mu.Lock()
	atomic.AddInt32(&s.calls, 1)
	s.gotReq = req
	fn := s.respFn
	s.mu.Unlock()
	if s.respondCh != nil {
		<-s.respondCh
	}
	if fn == nil {
		return &certclient.SignHostResponse{
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA-test\n",
			Serial:      1,
			KeyID:       req.KeyID,
			Principals:  req.Principals,
			ValidAfter:  time.Now().UTC(),
			ValidBefore: time.Now().UTC().Add(time.Hour),
		}, nil
	}
	return fn(req)
}

func TestNew_RejectsMissingConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  hostcert.Config
		want string
	}{
		{"no signer", hostcert.Config{HostKeyPath: "/x", CertOutputPath: "/y", KeyID: "k", Principals: []string{"p"}}, "Signer is required"},
		{"no host key path", hostcert.Config{Signer: &stubSigner{}, CertOutputPath: "/y", KeyID: "k", Principals: []string{"p"}}, "HostKeyPath is required"},
		{"no cert output", hostcert.Config{Signer: &stubSigner{}, HostKeyPath: "/x", KeyID: "k", Principals: []string{"p"}}, "CertOutputPath is required"},
		{"no key id", hostcert.Config{Signer: &stubSigner{}, HostKeyPath: "/x", CertOutputPath: "/y", Principals: []string{"p"}}, "KeyID is required"},
		{"no principals", hostcert.Config{Signer: &stubSigner{}, HostKeyPath: "/x", CertOutputPath: "/y", KeyID: "k"}, "Principal is required"},
		{"bad renew fraction", hostcert.Config{Signer: &stubSigner{}, HostKeyPath: "/x", CertOutputPath: "/y", KeyID: "k", Principals: []string{"p"}, RenewFraction: 1.5}, "RenewFraction must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hostcert.New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRenewer_SignOnce_WritesAtomically(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "ssh_host_ed25519_key")
	certPath := filepath.Join(dir, "ssh_host_ed25519_key-cert.pub")
	wantPub := writeHostPrivateKey(t, hostKeyPath)

	signer := &stubSigner{}
	var sawValidAfter, sawValidBefore time.Time
	r, err := hostcert.New(hostcert.Config{
		Signer:         signer,
		HostKeyPath:    hostKeyPath,
		CertOutputPath: certPath,
		KeyID:          "host:fakebox",
		Principals:     []string{"fakebox", "fakebox.lan"},
		RequestedTTL:   time.Hour,
		OnRenewed: func(va, vb time.Time) {
			sawValidAfter = va
			sawValidBefore = vb
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	va, vb, err := r.SignOnce(context.Background())
	if err != nil {
		t.Fatalf("SignOnce: %v", err)
	}

	// Cert file landed at the configured path with the response body.
	got, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	if !strings.HasPrefix(string(got), "ssh-ed25519-cert-v01@openssh.com") {
		t.Errorf("written cert = %q, want certd response", string(got))
	}

	// The pubkey sent to certd matches what's derived from the
	// on-disk private key.
	if string(signer.gotReq.PublicKey) != string(wantPub) {
		t.Errorf("signed pubkey mismatch:\ngot  %q\nwant %q", signer.gotReq.PublicKey, wantPub)
	}
	if signer.gotReq.KeyID != "host:fakebox" {
		t.Errorf("KeyID = %q", signer.gotReq.KeyID)
	}
	if signer.gotReq.TTLSeconds != 3600 {
		t.Errorf("TTLSeconds = %d, want 3600", signer.gotReq.TTLSeconds)
	}

	// Callback fired with the validity envelope returned by the signer.
	if sawValidAfter.IsZero() || sawValidBefore.IsZero() {
		t.Error("OnRenewed not invoked with validity envelope")
	}
	if !sawValidAfter.Equal(va) || !sawValidBefore.Equal(vb) {
		t.Errorf("OnRenewed args (%v, %v) ≠ SignOnce return (%v, %v)",
			sawValidAfter, sawValidBefore, va, vb)
	}

	// File mode is world-readable (sshd cert files conventionally are)
	// but writeable only by owner.
	info, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("cert file mode = %o, want 0644", mode)
	}

	// No leftover .tmp files in the cert dir.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".hostcert-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestRenewer_SignOnce_PropagatesSignerError(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "ssh_host_ed25519_key")
	writeHostPrivateKey(t, hostKeyPath)
	certPath := filepath.Join(dir, "ssh_host_ed25519_key-cert.pub")

	signer := &stubSigner{respFn: func(_ certclient.SignHostRequest) (*certclient.SignHostResponse, error) {
		return nil, errors.New("certd returned 403")
	}}
	r, _ := hostcert.New(hostcert.Config{
		Signer:         signer,
		HostKeyPath:    hostKeyPath,
		CertOutputPath: certPath,
		KeyID:          "host:fakebox",
		Principals:     []string{"fakebox"},
	})

	_, _, err := r.SignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "certd returned 403") {
		t.Errorf("err = %v, want signer error surfaced", err)
	}

	// On signer failure, no cert file should have been written.
	if _, err := os.Stat(certPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cert file exists after failed sign: %v", err)
	}
}

func TestRenewer_SignOnce_RejectsEmptyCert(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "k")
	writeHostPrivateKey(t, hostKeyPath)
	certPath := filepath.Join(dir, "k-cert.pub")
	signer := &stubSigner{respFn: func(req certclient.SignHostRequest) (*certclient.SignHostResponse, error) {
		return &certclient.SignHostResponse{Certificate: ""}, nil
	}}
	r, _ := hostcert.New(hostcert.Config{
		Signer: signer, HostKeyPath: hostKeyPath, CertOutputPath: certPath,
		KeyID: "k", Principals: []string{"p"},
	})
	_, _, err := r.SignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty certificate") {
		t.Errorf("err = %v, want empty-cert error", err)
	}
}

func TestRenewer_Run_LoopsAndRenews(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "k")
	writeHostPrivateKey(t, hostKeyPath)
	certPath := filepath.Join(dir, "k-cert.pub")

	// Short envelope so the renewer's MinRenewInterval floor fires
	// rapidly. With validity = 1ms, renewAfter = 0.6ms, deadline is
	// already in the past on the next iteration → MinRenewInterval
	// (50ms here) controls the cadence.
	signer := &stubSigner{respFn: func(_ certclient.SignHostRequest) (*certclient.SignHostResponse, error) {
		now := time.Now().UTC()
		return &certclient.SignHostResponse{
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA-loop\n",
			ValidAfter:  now,
			ValidBefore: now.Add(time.Millisecond),
		}, nil
	}}

	r, _ := hostcert.New(hostcert.Config{
		Signer:           signer,
		HostKeyPath:      hostKeyPath,
		CertOutputPath:   certPath,
		KeyID:            "host:loop",
		Principals:       []string{"loop"},
		MinRenewInterval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	if got := atomic.LoadInt32(&signer.calls); got < 2 {
		t.Errorf("calls = %d, want at least 2 (initial sign + at least one renew)", got)
	}
}

func TestRenewer_Run_RetryOnFailureThenSucceed(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "k")
	writeHostPrivateKey(t, hostKeyPath)
	certPath := filepath.Join(dir, "k-cert.pub")

	var calls int32
	signer := &stubSigner{respFn: func(_ certclient.SignHostRequest) (*certclient.SignHostResponse, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return nil, errors.New("transient certd outage")
		}
		now := time.Now().UTC()
		return &certclient.SignHostResponse{
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA-recovered\n",
			ValidAfter:  now,
			ValidBefore: now.Add(time.Hour),
		}, nil
	}}

	r, _ := hostcert.New(hostcert.Config{
		Signer:           signer,
		HostKeyPath:      hostKeyPath,
		CertOutputPath:   certPath,
		KeyID:            "host:recover",
		Principals:       []string{"recover"},
		MinRenewInterval: 10 * time.Millisecond,
		RetryBackoff:     20 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Errorf("calls = %d, want ≥ 2 (failure + retry)", got)
	}
	body, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	if !strings.Contains(string(body), "AAAA-recovered") {
		t.Errorf("cert file body = %q, want recovered cert", string(body))
	}
}

func TestRenewer_nextRenewalDelay_RespectsFraction(t *testing.T) {
	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "k")
	writeHostPrivateKey(t, hostKeyPath)
	certPath := filepath.Join(dir, "k-cert.pub")

	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	signer := &stubSigner{respFn: func(_ certclient.SignHostRequest) (*certclient.SignHostResponse, error) {
		return &certclient.SignHostResponse{
			Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA-x\n",
			ValidAfter:  now,
			ValidBefore: now.Add(10 * time.Hour),
		}, nil
	}}

	// renewAfter = 6h (0.6 of 10h). Now = validAfter, so the loop
	// should compute a wait close to 6h — well above the 1s floor.
	r, _ := hostcert.New(hostcert.Config{
		Signer:           signer,
		HostKeyPath:      hostKeyPath,
		CertOutputPath:   certPath,
		KeyID:            "host:k",
		Principals:       []string{"k"},
		RenewFraction:    0.6,
		MinRenewInterval: time.Second,
		Now:              func() time.Time { return now },
	})

	// We can't easily test the unexported nextRenewalDelay directly,
	// but Run with a near-instant ctx cancel exercises it once and
	// verifies the first sign succeeded — combined with the
	// 6-hour schedule choice, this also indirectly confirms we
	// don't hot-loop.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)
	if got := atomic.LoadInt32(&signer.calls); got != 1 {
		t.Errorf("calls = %d, want exactly 1 (initial sign; renewal is 6h away)", got)
	}
}
