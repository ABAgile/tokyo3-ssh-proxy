package forward_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	commontunnel "github.com/abagile/tokyo3-ssh-proxy/internal/common/tunnel"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/forward"
)

// inProcessYamux returns a pair of connected yamux sessions over a
// net.Pipe — no real socket, no TLS. The client session is the
// "proxy" side that opens streams; the server session is the
// "tunneld" side that the forwarder accepts on.
func inProcessYamux(t *testing.T) (client, server *yamux.Session) {
	t.Helper()
	cConn, sConn := net.Pipe()
	t.Cleanup(func() { _ = cConn.Close(); _ = sConn.Close() })

	type sessOrErr struct {
		s   *yamux.Session
		err error
	}
	clientCh := make(chan sessOrErr, 1)
	serverCh := make(chan sessOrErr, 1)
	go func() {
		s, err := yamux.Client(cConn, commontunnel.ClientConfig())
		clientCh <- sessOrErr{s, err}
	}()
	go func() {
		s, err := yamux.Server(sConn, commontunnel.ServerConfig())
		serverCh <- sessOrErr{s, err}
	}()
	cr, sr := <-clientCh, <-serverCh
	if cr.err != nil || sr.err != nil {
		t.Fatalf("yamux handshake: client=%v server=%v", cr.err, sr.err)
	}
	t.Cleanup(func() {
		_ = cr.s.Close()
		_ = sr.s.Close()
	})
	return cr.s, sr.s
}

// echoServer accepts inbound TCP connections and writes each chunk
// back, prefixed with "echo:". Returns its addr; stop fires on
// t.Cleanup.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(append([]byte("echo:"), buf[:n]...))
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestForwarder_Handle_PipesStreamToLocal(t *testing.T) {
	addr := echoServer(t)
	fwd := forward.New(forward.Config{LocalAddr: addr})

	proxy, tunneld := inProcessYamux(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan error, 1)
	go func() { doneCh <- fwd.Handle(ctx, tunneld) }()

	// Proxy opens a stream, sends data, expects "echo:" prefix back.
	stream, err := proxy.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 32)
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != "echo:hello" {
		t.Errorf("got %q, want %q", got, "echo:hello")
	}

	// Close the proxy stream — the forwarder should drop its end too.
	_ = stream.Close()

	// Cancelling ctx unwinds the forwarder.
	cancel()
	select {
	case err := <-doneCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Handle err = %v, want context.Canceled or nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Handle did not return after ctx cancel")
	}
}

func TestForwarder_Handle_DialFailureClosesOnlyStream(t *testing.T) {
	// Pick a port that nothing listens on so the dial reliably fails.
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := probe.Addr().String()
	_ = probe.Close()

	fwd := forward.New(forward.Config{
		LocalAddr:   deadAddr,
		DialTimeout: 100 * time.Millisecond,
	})

	proxy, tunneld := inProcessYamux(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan error, 1)
	go func() { doneCh <- fwd.Handle(ctx, tunneld) }()

	// Open a stream — the forwarder will dial deadAddr, fail, and
	// close just this stream. The session must stay alive.
	stream1, err := proxy.Open()
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	// Reading the stream should return an immediate error (forwarder
	// closed its end after the dial failed) — but the SESSION is fine.
	buf := make([]byte, 8)
	_ = stream1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := stream1.Read(buf); err == nil {
		t.Error("stream1 Read should have errored after forwarder closed it")
	}

	// A second stream should still be openable — session still alive.
	stream2, err := proxy.Open()
	if err != nil {
		t.Fatalf("Open 2 after dial failure: %v", err)
	}
	_ = stream2.Close()

	cancel()
	<-doneCh
}

func TestForwarder_Handle_ServesConcurrentStreams(t *testing.T) {
	addr := echoServer(t)
	fwd := forward.New(forward.Config{LocalAddr: addr})

	proxy, tunneld := inProcessYamux(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan error, 1)
	go func() { doneCh <- fwd.Handle(ctx, tunneld) }()

	const n = 6
	var wg sync.WaitGroup
	wg.Add(n)
	var success int32
	for i := 0; i < n; i++ {
		go func(id int) {
			defer wg.Done()
			s, err := proxy.Open()
			if err != nil {
				t.Errorf("Open %d: %v", id, err)
				return
			}
			defer s.Close()
			payload := []byte("p")
			if _, err := s.Write(payload); err != nil {
				t.Errorf("Write %d: %v", id, err)
				return
			}
			buf := make([]byte, 16)
			_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
			r, err := s.Read(buf)
			if err != nil {
				t.Errorf("Read %d: %v", id, err)
				return
			}
			if got := string(buf[:r]); got == "echo:p" {
				atomic.AddInt32(&success, 1)
			} else {
				t.Errorf("stream %d got %q, want %q", id, got, "echo:p")
			}
		}(i)
	}
	wg.Wait()
	if got := atomic.LoadInt32(&success); got != n {
		t.Errorf("success = %d, want %d", got, n)
	}
	cancel()
	<-doneCh
}

func TestForwarder_Handle_UsesCustomDialer(t *testing.T) {
	// Custom dialer returns an in-memory connection backed by net.Pipe.
	// Confirms we don't depend on real loopback for testing.
	var dialerCalls int32
	cPipe, sPipe := net.Pipe()
	t.Cleanup(func() { _ = cPipe.Close(); _ = sPipe.Close() })

	// Mini echo server on sPipe.
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := sPipe.Read(buf)
			if n > 0 {
				_, _ = sPipe.Write(append([]byte("d:"), buf[:n]...))
			}
			if err != nil {
				return
			}
		}
	}()

	fwd := forward.New(forward.Config{
		LocalAddr: "fakehost:22",
		Dialer: func(_ context.Context, addr string) (net.Conn, error) {
			atomic.AddInt32(&dialerCalls, 1)
			if addr != "fakehost:22" {
				t.Errorf("dialer addr = %q, want fakehost:22", addr)
			}
			return cPipe, nil
		},
	})

	proxy, tunneld := inProcessYamux(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan error, 1)
	go func() { doneCh <- fwd.Handle(ctx, tunneld) }()

	stream, err := proxy.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer stream.Close()
	_, _ = stream.Write([]byte("X"))
	buf := make([]byte, 8)
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := stream.Read(buf)
	if string(buf[:n]) != "d:X" {
		t.Errorf("got %q, want %q", string(buf[:n]), "d:X")
	}
	if atomic.LoadInt32(&dialerCalls) != 1 {
		t.Errorf("dialer calls = %d, want 1", dialerCalls)
	}

	cancel()
	<-doneCh
}

func TestForwarder_Handle_ReturnsWhenSessionShutdown(t *testing.T) {
	addr := echoServer(t)
	fwd := forward.New(forward.Config{LocalAddr: addr})

	proxy, tunneld := inProcessYamux(t)
	doneCh := make(chan error, 1)
	go func() { doneCh <- fwd.Handle(context.Background(), tunneld) }()

	// Tear down the session from the client side.
	_ = proxy.Close()

	select {
	case err := <-doneCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, yamux.ErrSessionShutdown) {
			t.Errorf("Handle err = %v, want nil/EOF/ErrSessionShutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Handle did not return after session shutdown")
	}
}
