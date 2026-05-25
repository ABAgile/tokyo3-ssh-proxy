package ssh_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
)

// startServerWithRecording wraps startServerWithTarget so the
// Recording-aware integration tests can plug in a sink.
func startServerWithRecording(t *testing.T, ca caBundle, proxyClientSigner gossh.Signer, targetHostKey gossh.PublicKey, sink recording.Sink) (addr string, stop func()) {
	t.Helper()
	srv, err := pssh.New(pssh.Config{
		Addr:                  "127.0.0.1:0",
		Log:                   silentLogger(),
		HostSigner:            newHostSigner(t),
		TrustedUserCA:         ca.pub,
		ClientSigner:          proxyClientSigner,
		TargetHostKeyCallback: gossh.FixedHostKey(targetHostKey),
		RecordingSink:         sink,
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

func TestServer_RecordsPTYSession(t *testing.T) {
	// Set up: cert-issuing CA, proxy client key, fake target. The
	// fake target accepts pty-req + exec, writes echo, exits.
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	sinkRoot := filepath.Join(t.TempDir(), "casts")
	sink, err := recording.NewLocalDirSink(sinkRoot)
	if err != nil {
		t.Fatalf("NewLocalDirSink: %v", err)
	}

	proxyAddr, stop := startServerWithRecording(t, ca, proxyClientSigner, target.hostPub, sink)
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, err := dialAsUser(proxyAddr, "alice@"+target.addr, gossh.PublicKeys(certSigner))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// Request a PTY so the proxy enables recording.
	if err := sess.RequestPty("xterm-256color", 40, 120, gossh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}

	out, err := sess.Output("anything")
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("Output: %v", err)
	}
	if string(out) != echoResponse {
		t.Errorf("session output = %q, want %q", string(out), echoResponse)
	}

	// Give the proxy a beat to flush + close the cast file.
	time.Sleep(50 * time.Millisecond)

	// Walk the sink root and find the cast file. Should be exactly one.
	var castPath string
	err = filepath.Walk(sinkRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(p, ".cast") {
			castPath = p
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", sinkRoot, err)
	}
	if castPath == "" {
		t.Fatalf("no .cast file produced under %s", sinkRoot)
	}

	// Verify the file shape: header line + at least one "o" event
	// carrying the echo response.
	f, err := os.Open(castPath)
	if err != nil {
		t.Fatalf("open cast: %v", err)
	}
	defer f.Close()
	body, _ := io.ReadAll(f)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("cast file has %d lines, want header + at least one event; body=%q", len(lines), string(body))
	}

	var hdr struct {
		Version int    `json:"version"`
		Width   int    `json:"width"`
		Height  int    `json:"height"`
		Title   string `json:"title"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatalf("decode header: %v; line=%q", err, lines[0])
	}
	if hdr.Version != 2 {
		t.Errorf("header version = %d", hdr.Version)
	}
	if hdr.Width != 120 || hdr.Height != 40 {
		t.Errorf("header dims = %dx%d, want 120x40", hdr.Width, hdr.Height)
	}
	if !strings.HasSuffix(hdr.Title, "@"+target.addr) {
		t.Errorf("title = %q, want suffix @%s", hdr.Title, target.addr)
	}

	// Find an event whose payload is the echo response.
	foundEcho := false
	for _, line := range lines[1:] {
		var ev [3]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if kind, _ := ev[1].(string); kind != "o" {
			continue
		}
		if payload, _ := ev[2].(string); payload == echoResponse {
			foundEcho = true
			break
		}
	}
	if !foundEcho {
		t.Errorf("expected an 'o' event with payload %q; got body=%q", echoResponse, string(body))
	}
}

func TestServer_NoRecordingForNonPTYSession(t *testing.T) {
	// Same flow as TestServer_ForwardsToTarget but with a sink wired
	// up. Without a pty-req the proxy must NOT produce a cast file.
	ca := newCA(t)
	proxyClientSigner := newHostSigner(t)
	target := newFakeTarget(t, "alice", proxyClientSigner.PublicKey())

	sinkRoot := filepath.Join(t.TempDir(), "casts")
	sink, _ := recording.NewLocalDirSink(sinkRoot)

	proxyAddr, stop := startServerWithRecording(t, ca, proxyClientSigner, target.hostPub, sink)
	defer stop()

	userSigner := newUserKey(t)
	certSigner := signUserCertWithSigner(t, ca, userSigner, []string{"alice"}, time.Time{}, time.Time{})

	client, _ := dialAsUser(proxyAddr, "alice@"+target.addr, gossh.PublicKeys(certSigner))
	defer client.Close()
	sess, _ := client.NewSession()
	_, _ = sess.Output("anything")
	time.Sleep(50 * time.Millisecond)

	// Walk sinkRoot — no cast file should exist.
	_ = filepath.Walk(sinkRoot, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && strings.HasSuffix(p, ".cast") {
			t.Errorf("non-PTY session produced cast file: %s", p)
		}
		return nil
	})
}
