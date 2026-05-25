package tunnel_test

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/abagile/tokyo3-ssh-proxy/internal/common/tunnel"
)

func TestClientServerConfigsAgree(t *testing.T) {
	// Both sides MUST use the same keepalive cadence and frame timeout
	// or yamux will tear down the session as soon as the slower side
	// misses a ping. This test pins the contract.
	c := tunnel.ClientConfig()
	s := tunnel.ServerConfig()

	if c.KeepAliveInterval != s.KeepAliveInterval {
		t.Errorf("KeepAliveInterval mismatch: client=%v server=%v",
			c.KeepAliveInterval, s.KeepAliveInterval)
	}
	if c.ConnectionWriteTimeout != s.ConnectionWriteTimeout {
		t.Errorf("ConnectionWriteTimeout mismatch: client=%v server=%v",
			c.ConnectionWriteTimeout, s.ConnectionWriteTimeout)
	}
	if c.MaxStreamWindowSize != s.MaxStreamWindowSize {
		t.Errorf("MaxStreamWindowSize mismatch: client=%v server=%v",
			c.MaxStreamWindowSize, s.MaxStreamWindowSize)
	}
}

func TestClientConfig_KnownConstants(t *testing.T) {
	// Locks the published constants. Changing these is a coordinated
	// change; let the test scream when someone tweaks one side.
	c := tunnel.ClientConfig()
	if c.KeepAliveInterval != tunnel.KeepAliveInterval {
		t.Errorf("KeepAliveInterval = %v, want %v", c.KeepAliveInterval, tunnel.KeepAliveInterval)
	}
	if c.ConnectionWriteTimeout != tunnel.ConnectionWriteTimeout {
		t.Errorf("ConnectionWriteTimeout = %v, want %v", c.ConnectionWriteTimeout, tunnel.ConnectionWriteTimeout)
	}
	if c.MaxStreamWindowSize != tunnel.MaxStreamWindowSize {
		t.Errorf("MaxStreamWindowSize = %v, want %v", c.MaxStreamWindowSize, tunnel.MaxStreamWindowSize)
	}
	if !c.EnableKeepAlive {
		t.Error("EnableKeepAlive must be true")
	}
}

func TestValidateConfig_DetectsDrift(t *testing.T) {
	c := tunnel.ClientConfig()
	if err := tunnel.ValidateConfig(c); err != nil {
		t.Errorf("validate canonical client config: %v", err)
	}

	c.KeepAliveInterval = 9 * time.Second
	if err := tunnel.ValidateConfig(c); err == nil {
		t.Error("validate should reject drifted KeepAliveInterval")
	}

	if err := tunnel.ValidateConfig(nil); err == nil {
		t.Error("validate(nil) should fail")
	}
}

func TestRoundTripOverInProcessConn(t *testing.T) {
	// Smoke-test that the canonical configs successfully negotiate
	// a yamux session over a net.Pipe (no TLS, no real net stack —
	// just confirms the parameters are mutually compatible).
	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	clientCh := make(chan *yamux.Session, 1)
	serverCh := make(chan *yamux.Session, 1)
	errCh := make(chan error, 2)

	go func() {
		sess, err := yamux.Client(cConn, tunnel.ClientConfig())
		if err != nil {
			errCh <- err
			return
		}
		clientCh <- sess
	}()
	go func() {
		sess, err := yamux.Server(sConn, tunnel.ServerConfig())
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- sess
	}()

	select {
	case err := <-errCh:
		t.Fatalf("yamux handshake: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("yamux handshake stalled")
	case csess := <-clientCh:
		defer csess.Close()
		ssess := <-serverCh
		defer ssess.Close()
		// Open a stream to verify both sides agree on the framing.
		go func() {
			s, err := ssess.Accept()
			if err != nil {
				errCh <- err
				return
			}
			_, _ = s.Write([]byte("pong"))
			_ = s.Close()
		}()
		stream, err := csess.Open()
		if err != nil {
			t.Fatalf("client Open: %v", err)
		}
		buf := make([]byte, 4)
		_ = stream.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := stream.Read(buf)
		if string(buf[:n]) != "pong" {
			t.Errorf("stream payload = %q, want %q", string(buf[:n]), "pong")
		}
	}
}
