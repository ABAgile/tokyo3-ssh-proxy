package tunnel_test

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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	commontunnel "github.com/abagile/tokyo3-ssh-proxy/internal/common/tunnel"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/tunnel"
)

func TestNew_RejectsMissingConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  tunnel.Config
		want string
	}{
		{"no target", tunnel.Config{TLSConfig: &tls.Config{}, Handler: func(context.Context, *yamux.Session) error { return nil }}, "target is required"},
		{"no tls", tunnel.Config{Target: "x:1", Handler: func(context.Context, *yamux.Session) error { return nil }}, "TLSConfig is required"},
		{"no handler", tunnel.Config{Target: "x:1", TLSConfig: &tls.Config{}}, "handler is required"},
		{
			"bad jitter",
			tunnel.Config{
				Target: "x:1", TLSConfig: &tls.Config{},
				Handler:       func(context.Context, *yamux.Session) error { return nil },
				BackoffJitter: 1.5,
			},
			"BackoffJitter must be",
		},
		{
			"initial > max",
			tunnel.Config{
				Target: "x:1", TLSConfig: &tls.Config{},
				Handler:        func(context.Context, *yamux.Session) error { return nil },
				InitialBackoff: 10 * time.Second,
				MaxBackoff:     1 * time.Second,
			},
			"InitialBackoff",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tunnel.New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// fakeProxy is an in-process TLS+yamux server that stands in for
// ssh-proxyd. Accepts a single configured client cert (via the
// supplied tls.Config), then runs yamux.Server on each accepted
// connection. sessions chan delivers each negotiated session for
// assertion.
type fakeProxy struct {
	addr     string
	listener net.Listener
	sessions chan *yamux.Session
	stop     func()
}

func newFakeProxy(t *testing.T, srvTLS *tls.Config) *fakeProxy {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	fp := &fakeProxy{
		addr:     ln.Addr().String(),
		listener: ln,
		sessions: make(chan *yamux.Session, 4),
	}
	var wg sync.WaitGroup
	stopCh := make(chan struct{})
	wg.Go(func() {
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
				sess, err := yamux.Server(c, commontunnel.ServerConfig())
				if err != nil {
					_ = c.Close()
					return
				}
				select {
				case fp.sessions <- sess:
				case <-stopCh:
					_ = sess.Close()
				}
			}(conn)
		}
	})
	fp.stop = func() {
		close(stopCh)
		_ = ln.Close()
		wg.Wait()
	}
	t.Cleanup(fp.stop)
	return fp
}

// mintTLS returns a (clientTLS, serverTLS) pair using a single
// self-signed cert as both server cert and client cert — sufficient
// for end-to-end mTLS test without standing up a CA.
func mintTLS(t *testing.T) (clientTLS, serverTLS *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tunnel-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	derBytes, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: priv}
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(derBytes)
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

func TestDialer_Run_ConnectsAndInvokesHandler(t *testing.T) {
	clientTLS, serverTLS := mintTLS(t)
	fp := newFakeProxy(t, serverTLS)

	handlerCalled := make(chan *yamux.Session, 1)
	d, err := tunnel.New(tunnel.Config{
		Target:    fp.addr,
		TLSConfig: clientTLS,
		Handler: func(ctx context.Context, s *yamux.Session) error {
			handlerCalled <- s
			<-ctx.Done()
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- d.Run(ctx) }()

	// Wait for the handler to be invoked with a live session.
	select {
	case cs := <-handlerCalled:
		// Mirror it with the server-side session — open a stream
		// from the server, write "hi", verify the client gets it.
		var ss *yamux.Session
		select {
		case ss = <-fp.sessions:
		case <-time.After(2 * time.Second):
			t.Fatal("server didn't see a yamux session")
		}

		// Server opens a stream toward the client.
		go func() {
			stream, err := ss.Open()
			if err != nil {
				return
			}
			defer stream.Close()
			_, _ = stream.Write([]byte("hi"))
		}()
		stream, err := cs.Accept()
		if err != nil {
			t.Fatalf("client Accept: %v", err)
		}
		buf := make([]byte, 2)
		_ = stream.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := stream.Read(buf)
		if string(buf[:n]) != "hi" {
			t.Errorf("stream payload = %q, want %q", string(buf[:n]), "hi")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never invoked")
	}

	cancel()
	select {
	case err := <-runErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run didn't exit after cancel")
	}
}

func TestDialer_Run_RetriesAfterDialFailure(t *testing.T) {
	// Start with a closed listener so the first dial fails, then
	// stand up a real proxy mid-flight and verify the dialer
	// recovers.
	clientTLS, serverTLS := mintTLS(t)

	// Find a free port the second listener can bind by listening +
	// closing immediately. Race-y in principle but fine in this
	// test scope; the kernel's reuse window will usually still
	// have the port available a few ms later.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	var calls atomic.Int32
	d, _ := tunnel.New(tunnel.Config{
		Target:         addr,
		TLSConfig:      clientTLS,
		DialTimeout:    100 * time.Millisecond,
		InitialBackoff: 20 * time.Millisecond,
		MaxBackoff:     40 * time.Millisecond,
		BackoffJitter:  0, // deterministic schedule
		Handler: func(ctx context.Context, s *yamux.Session) error {
			calls.Add(1)
			<-ctx.Done()
			return ctx.Err()
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- d.Run(ctx) }()

	// Let at least one dial attempt fail.
	time.Sleep(80 * time.Millisecond)

	// Bring up the proxy on the same address. Stash the bind
	// listener so the cleanup closes it.
	srvLn, err := tls.Listen("tcp", addr, serverTLS)
	if err != nil {
		cancel()
		t.Skipf("could not rebind %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = srvLn.Close() })
	go func() {
		for {
			conn, err := srvLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sess, err := yamux.Server(c, commontunnel.ServerConfig())
				if err != nil {
					_ = c.Close()
					return
				}
				<-sess.CloseChan()
			}(conn)
		}
	}()

	// Expect the handler to fire within a few backoff windows.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Error("handler never invoked after recovery")
	}

	cancel()
	<-runErrCh
}

func TestDialer_Run_ReconnectsAfterHandlerReturn(t *testing.T) {
	clientTLS, serverTLS := mintTLS(t)
	fp := newFakeProxy(t, serverTLS)

	var calls atomic.Int32
	d, _ := tunnel.New(tunnel.Config{
		Target:         fp.addr,
		TLSConfig:      clientTLS,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		BackoffJitter:  0,
		Handler: func(_ context.Context, _ *yamux.Session) error {
			calls.Add(1)
			return errors.New("forcing reconnect")
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = d.Run(ctx)

	if got := calls.Load(); got < 2 {
		t.Errorf("calls = %d, want at least 2 (initial + at least 1 reconnect)", got)
	}
}

func TestDialer_DialOnce_PropagatesTLSError(t *testing.T) {
	// No proxy listening at all → DialOnce surfaces the underlying
	// connection error.
	clientTLS, _ := mintTLS(t)
	d, _ := tunnel.New(tunnel.Config{
		Target:         "127.0.0.1:1", // reserved/blackhole
		TLSConfig:      clientTLS,
		Handler:        func(context.Context, *yamux.Session) error { return nil },
		DialTimeout:    100 * time.Millisecond,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		BackoffJitter:  0,
	})
	_, err := d.DialOnce(context.Background())
	if err == nil {
		t.Fatal("DialOnce should fail when proxy is unreachable")
	}
}
