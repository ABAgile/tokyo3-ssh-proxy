package ssh_test

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
)

// fakeTarget is an in-process SSH server that simulates a real sshd
// the proxy might dial. It accepts a single client public key for a
// configured remote user, then responds to each session channel by
// piping data back ("exec" / "shell" produce the configured echo
// reply).
type fakeTarget struct {
	addr       string
	hostPub    gossh.PublicKey
	listener   net.Listener
	stop       func()
	gotUser    string
	gotChannel chan string // channel types observed, for assertions
}

// echoResponse is the bytes the fake target writes back over any
// session channel before closing it. Tests assert this round-trips
// through the proxy unchanged.
const echoResponse = "hello from the target\n"

func newFakeTarget(t *testing.T, allowedUser string, allowedKey gossh.PublicKey) *fakeTarget {
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

	srvCfg := &gossh.ServerConfig{
		PublicKeyCallback: func(meta gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if meta.User() != allowedUser {
				return nil, &gossh.OpenChannelError{Reason: gossh.Prohibited, Message: "wrong user"}
			}
			// Same-key check via marshaled bytes — sufficient for tests.
			if string(key.Marshal()) != string(allowedKey.Marshal()) {
				return nil, &gossh.OpenChannelError{Reason: gossh.Prohibited, Message: "wrong key"}
			}
			ft.gotUser = meta.User()
			return &gossh.Permissions{}, nil
		},
	}
	srvCfg.AddHostKey(hostSigner)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				ft.serveConn(c, srvCfg)
			}(conn)
		}
	}()

	ft.stop = func() {
		close(stopCh)
		_ = ln.Close()
		wg.Wait()
	}
	t.Cleanup(ft.stop)
	return ft
}

// serveConn does the SSH handshake on conn and pipes each session
// channel — echo + close.
func (ft *fakeTarget) serveConn(conn net.Conn, cfg *gossh.ServerConfig) {
	defer conn.Close()
	sshConn, channels, requests, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go gossh.DiscardRequests(requests)

	for newCh := range channels {
		ft.gotChannel <- newCh.ChannelType()
		switch newCh.ChannelType() {
		case "session":
			// fall through to the existing session handler
		case "direct-tcpip":
			// Echo every byte the user sends to the (mocked) remote
			// host. Lets port-forward tests round-trip data through
			// the proxy and assert on the audit attribution.
			ch, _, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func(c gossh.Channel) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(ch)
			continue
		default:
			_ = newCh.Reject(gossh.UnknownChannelType, newCh.ChannelType())
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		// Accept any channel request (shell, exec, pty-req, etc.) and
		// reply ok. The first exec / shell request triggers the echo
		// reply + exit-status; later requests are still acked but
		// don't produce output (matches sshd's "command already
		// running" behavior loosely enough for tests).
		go func() {
			done := false
			for req := range reqs {
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				switch req.Type {
				case "exec", "shell":
					if done {
						continue
					}
					done = true
					_, _ = io.WriteString(ch, echoResponse)
					// SSH "exit-status" request: uint32 exit code.
					_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
					_ = ch.CloseWrite()
					// Small drain pause before the full close. gossh
					// occasionally races a CHANNEL_CLOSE on the
					// outbound side against the inbound data
					// forwarding goroutine — a real sshd doesn't hit
					// this because it does its own teardown signaling
					// around the exit-status. A few milliseconds let
					// the proxy's target→user io.Copy drain the
					// buffered echo before the channel is torn down.
					time.Sleep(10 * time.Millisecond)
					_ = ch.Close()
				}
			}
		}()
	}
}

// startServerWithTarget brings up an ssh-proxyd configured to use
// proxyClientSigner for outbound auth and to trust the given target
// host key via FixedHostKey. Returns the proxy's address and a stop
// callback.
func startServerWithTarget(t *testing.T, ca caBundle, proxyClientSigner gossh.Signer, targetHostKey gossh.PublicKey) (addr string, stop func()) {
	t.Helper()
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSignerFunc:      pssh.StaticSigner(proxyClientSigner),
		TargetHostKeyCallback: gossh.FixedHostKey(targetHostKey),
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

// ── tests ─────────────────────────────────────────────────────────────────────

func TestServer_ForwardsToTarget(t *testing.T) {
	// Full end-to-end: user → ssh-proxyd → fake target, with a
	// session-level echo response flowing back unchanged.
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t) // ssh-proxyd's outbound key
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	proxyAddr, stop := startServerWithTarget(t, ca, proxyClientSigner, target.hostPub)
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, err := dialAsUser(proxyAddr, "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	// Read the echo response from the session's stdout. The target
	// closes the channel after writing, so io.ReadAll returns when
	// EOF arrives.
	out, err := sess.Output("anything")
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("session.Output: %v", err)
	}
	if got := string(out); got != echoResponse {
		t.Errorf("session output = %q, want %q", got, echoResponse)
	}

	// Target saw the right remote user (parsed out of "alice@<addr>").
	if target.gotUser != "alice" {
		t.Errorf("target saw user %q, want alice", target.gotUser)
	}

	// Channel type seen by the target was "session".
	select {
	case got := <-target.gotChannel:
		if got != "session" {
			t.Errorf("target saw channel type %q, want session", got)
		}
	case <-time.After(time.Second):
		t.Error("target never received a channel")
	}
}

func TestServer_RejectsWhenTargetHostKeyMismatches(t *testing.T) {
	// Proxy configured with a stale/wrong host key for the target —
	// outbound handshake fails, user gets the propagated error as
	// "target unreachable".
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	// Generate a DIFFERENT host key to use in the FixedHostKey
	// callback so the target's real host key doesn't match.
	_, otherPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	otherSigner, _ := gossh.NewSignerFromKey(otherPriv)
	wrongHostKey := otherSigner.PublicKey()

	proxyAddr, stop := startServerWithTarget(t, ca, proxyClientSigner, wrongHostKey)
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, err := dialAsUser(proxyAddr, "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	_, err = client.NewSession()
	if err == nil {
		t.Fatal("expected NewSession to fail due to target host key mismatch")
	}
	if !strings.Contains(err.Error(), "target unreachable") {
		t.Errorf("expected target-unreachable error, got %v", err)
	}
}
