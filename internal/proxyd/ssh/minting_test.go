package ssh_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/common/certclient"
	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
)

// mockCertd stands in for the certd HTTP service. It signs incoming
// public keys with a known CA (so the fake target can validate them)
// and counts how many times sign-user was called — proves the proxy
// actually invoked certd rather than falling back to a static key.
type mockCertd struct {
	ca        gossh.Signer
	server    *httptest.Server
	callCount atomic.Int64
}

func newMockCertd(t *testing.T, ca gossh.Signer) *mockCertd {
	t.Helper()
	m := &mockCertd{ca: ca}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ssh/sign-user" {
			http.NotFound(w, r)
			return
		}
		m.callCount.Add(1)

		var req certclient.SignUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Parse the offered pubkey, sign a user cert for it.
		pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, "bad public key: "+err.Error(), http.StatusBadRequest)
			return
		}
		ttl := req.TTLSeconds
		if ttl == 0 {
			ttl = 300
		}
		notBefore := time.Now().Add(-time.Minute)
		notAfter := time.Now().Add(time.Duration(ttl) * time.Second)
		cert := &gossh.Certificate{
			Key:             pub,
			CertType:        gossh.UserCert,
			KeyId:           req.KeyID,
			ValidPrincipals: req.Principals,
			ValidAfter:      uint64(notBefore.Unix()),
			ValidBefore:     uint64(notAfter.Unix()),
			Serial:          uint64(m.callCount.Load()),
			Permissions: gossh.Permissions{
				Extensions: map[string]string{
					"permit-pty":              "",
					"permit-port-forwarding":  "",
					"permit-agent-forwarding": "",
				},
			},
		}
		if err := cert.SignCert(cryptorand.Reader, m.ca); err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := certclient.SignUserResponse{
			Certificate: strings.TrimRight(string(gossh.MarshalAuthorizedKey(cert)), "\n"),
			Serial:      cert.Serial,
			KeyID:       cert.KeyId,
			Principals:  cert.ValidPrincipals,
			ValidAfter:  notBefore.UTC(),
			ValidBefore: notAfter.UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(m.server.Close)
	return m
}

// fakeTargetTrustingCA is like newFakeTarget but accepts ANY user
// cert signed by the given CA — used to verify the proxy actually
// authenticated with a certd-minted cert.
func fakeTargetTrustingCA(t *testing.T, allowedUser string, userCA gossh.PublicKey) *fakeTarget {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("target host keygen: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("target host signer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}

	ft := &fakeTarget{
		addr:       ln.Addr().String(),
		hostPub:    hostSigner.PublicKey(),
		listener:   ln,
		gotChannel: make(chan string, 8),
	}

	checker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), userCA.Marshal())
		},
	}
	srvCfg := &gossh.ServerConfig{
		PublicKeyCallback: func(meta gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			perms, err := checker.Authenticate(meta, key)
			if err != nil {
				return nil, err
			}
			if meta.User() != allowedUser {
				return nil, errors.New("wrong user")
			}
			ft.gotUser = meta.User()
			return perms, nil
		},
	}
	srvCfg.AddHostKey(hostSigner)

	stopCh := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go ft.serveConn(conn, srvCfg)
		}
	}()
	ft.stop = func() {
		close(stopCh)
		_ = ln.Close()
	}
	t.Cleanup(ft.stop)
	return ft
}

func TestServer_MintsPerSessionCertViaCertd(t *testing.T) {
	// Three CAs in the picture (all separate Ed25519 keys), but
	// only one matters end-to-end: the user CA. Both certd (the
	// minter) and the fake target (the validator) trust the same
	// user CA, so a fresh per-session cert minted by certd
	// authenticates the proxy → target hop.
	ca := newCA(t)

	mock := newMockCertd(t, ca.signer)

	client, err := certclient.NewClient(mock.server.URL, nil)
	if err != nil {
		t.Fatalf("certclient.NewClient: %v", err)
	}
	signerFn := func(ctx context.Context, principal string) (gossh.Signer, error) {
		// Fresh keypair per call.
		_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
		if err != nil {
			return nil, err
		}
		sshPub, _ := gossh.NewPublicKey(priv.Public())
		resp, err := client.SignUserCert(ctx, certclient.SignUserRequest{
			PublicKey:  strings.TrimRight(string(gossh.MarshalAuthorizedKey(sshPub)), "\n"),
			KeyID:      "session:test:principal:" + principal,
			Principals: []string{principal},
			TTLSeconds: 300,
		})
		if err != nil {
			return nil, err
		}
		parsed, _, _, _, err := gossh.ParseAuthorizedKey([]byte(resp.Certificate))
		if err != nil {
			return nil, err
		}
		cert := parsed.(*gossh.Certificate)
		base, _ := gossh.NewSignerFromKey(priv)
		return gossh.NewCertSigner(cert, base)
	}

	target := fakeTargetTrustingCA(t, "alice", ca.pub)

	// Build a server with the certd-backed signerFn.
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      signerFn,
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
	})
	if err != nil {
		t.Fatalf("pssh.New: %v", err)
	}
	ctx := t.Context()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		t.Fatal("server did not bind")
	}

	userSigner := newUserKey(t)
	userCert := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client2, err := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(userCert))
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer client2.Close()

	sess, err := client2.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := sess.Output("anything")
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("session.Output: %v", err)
	}
	if string(out) != echoResponse {
		t.Errorf("session output = %q, want %q", string(out), echoResponse)
	}

	// Proves the proxy went through certd — at least one sign-user
	// call should have landed.
	if got := mock.callCount.Load(); got < 1 {
		t.Errorf("mock certd received %d sign-user calls, want >= 1", got)
	}
}

func TestServer_PropagatesCertdMintingErrors(t *testing.T) {
	// signerFn returns an error → handleConn rejects channels with
	// "proxy could not obtain a client signer".
	ca := newCA(t)
	target := fakeTargetTrustingCA(t, "alice", ca.pub)

	signerFn := func(context.Context, string) (gossh.Signer, error) {
		return nil, errors.New("certd unreachable")
	}
	srv, _ := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      signerFn,
		TargetHostKeyCallback: gossh.FixedHostKey(target.hostPub),
	})
	ctx := t.Context()
	go func() { _ = srv.ListenAndServe(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	userSigner := newUserKey(t)
	userCert := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, err := dialAsUser(srv.Addr(), "alice@"+target.addr, gossh.PublicKeys(userCert))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	_, err = client.NewSession()
	if err == nil {
		t.Fatal("expected NewSession to fail due to signer error")
	}
	if !strings.Contains(err.Error(), "client signer") {
		t.Errorf("expected 'client signer' in error, got %v", err)
	}
}
