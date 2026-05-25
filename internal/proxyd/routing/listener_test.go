package routing_test

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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	commontunnel "github.com/abagile/tokyo3-ssh-proxy/internal/common/tunnel"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/routing"
)

// mintTLSWithSPIFFE returns matched (clientTLS, serverTLS) configs
// where the client cert carries the supplied SPIFFE URI. Same
// self-signed cert is both CA root and leaf — small enough for tests
// that just need a valid mTLS handshake.
func mintTLSWithSPIFFE(t *testing.T, spiffeURI string) (clientTLS, serverTLS *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: spiffeURI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	if spiffeURI != "" {
		u, _ := url.Parse(spiffeURI)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
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

func TestHostFromSPIFFE_ExtractsSingleHost(t *testing.T) {
	u, _ := url.Parse("spiffe://tokyo3.example/host/db-1.prod")
	leaf := &x509.Certificate{URIs: []*url.URL{u}}
	hosts, err := routing.HostFromSPIFFE(leaf)
	if err != nil {
		t.Fatalf("HostFromSPIFFE: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "db-1.prod" {
		t.Errorf("hosts = %v, want [db-1.prod]", hosts)
	}
}

func TestHostFromSPIFFE_SupportsAliases(t *testing.T) {
	u, _ := url.Parse("spiffe://tokyo3.example/host/db-1.prod,db-1,db1")
	leaf := &x509.Certificate{URIs: []*url.URL{u}}
	hosts, err := routing.HostFromSPIFFE(leaf)
	if err != nil {
		t.Fatalf("HostFromSPIFFE: %v", err)
	}
	want := []string{"db-1.prod", "db-1", "db1"}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}
	for i, h := range want {
		if hosts[i] != h {
			t.Errorf("hosts[%d] = %q, want %q", i, hosts[i], h)
		}
	}
}

func TestHostFromSPIFFE_Rejects(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		err  string
	}{
		{"empty SAN list", "", "no SPIFFE URI"},
		{"wrong path prefix", "spiffe://td/workload/x", "/host/"},
		{"empty host component", "spiffe://td/host/", "no host component"},
		{"only commas", "spiffe://td/host/,,,", "empty after parsing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var uris []*url.URL
			if tc.uri != "" {
				u, _ := url.Parse(tc.uri)
				uris = []*url.URL{u}
			}
			leaf := &x509.Certificate{URIs: uris}
			_, err := routing.HostFromSPIFFE(leaf)
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("err = %v, want %q", err, tc.err)
			}
		})
	}
}

func TestHostFromSPIFFE_RejectsMultipleSPIFFEURIs(t *testing.T) {
	u1, _ := url.Parse("spiffe://td/host/a")
	u2, _ := url.Parse("spiffe://td/host/b")
	leaf := &x509.Certificate{URIs: []*url.URL{u1, u2}}
	_, err := routing.HostFromSPIFFE(leaf)
	if err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Errorf("err = %v, want multiple-URI rejection", err)
	}
}

func TestNewListener_RejectsMissingConfig(t *testing.T) {
	r := routing.New()
	cases := []struct {
		name string
		cfg  routing.ListenerConfig
		want string
	}{
		{"no addr", routing.ListenerConfig{TLSConfig: &tls.Config{}, Registry: r}, "addr is required"},
		{"no tls", routing.ListenerConfig{Addr: ":0", Registry: r}, "TLSConfig is required"},
		{"no registry", routing.ListenerConfig{Addr: ":0", TLSConfig: &tls.Config{}}, "registry is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := routing.NewListener(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestListener_Serve_AcceptsAndRegistersTunnel(t *testing.T) {
	clientTLS, serverTLS := mintTLSWithSPIFFE(t, "spiffe://tokyo3.example/host/db-1.prod")
	r := routing.New()
	defer r.Close()

	l, err := routing.NewListener(routing.ListenerConfig{
		Addr:      "127.0.0.1:0",
		TLSConfig: serverTLS,
		Registry:  r,
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}

	// Bind manually so the test can learn the chosen port.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- l.Serve(ctx, ln) }()

	// Connect as a fake tunneld — mTLS dial + yamux client.
	tlsClient, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer tlsClient.Close()
	cliSess, err := yamux.Client(tlsClient, commontunnel.ClientConfig())
	if err != nil {
		t.Fatalf("yamux.Client: %v", err)
	}
	defer cliSess.Close()

	// Poll for the registry to pick up the new tunnel.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := r.Lookup("db-1.prod"); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := r.Lookup("db-1.prod"); err != nil {
		t.Fatalf("registry never saw db-1.prod: %v", err)
	}

	// Close the client side; the listener should unregister.
	_ = cliSess.Close()
	_ = tlsClient.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := r.Lookup("db-1.prod"); errors.Is(err, routing.ErrNoTunnel) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := r.Lookup("db-1.prod"); !errors.Is(err, routing.ErrNoTunnel) {
		t.Errorf("registry still has db-1.prod after disconnect: %v", err)
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Serve did not exit after cancel")
	}
}

func TestListener_Serve_RejectsCertWithoutSPIFFEURI(t *testing.T) {
	// Cert has no SPIFFE URI — the listener drops the connection
	// without ever registering anything.
	clientTLS, serverTLS := mintTLSWithSPIFFE(t, "")

	r := routing.New()
	defer r.Close()
	l, err := routing.NewListener(routing.ListenerConfig{
		Addr: "127.0.0.1:0", TLSConfig: serverTLS, Registry: r,
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx, ln) }()

	tlsClient, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tlsClient.Close()
	// Yamux negotiation might still succeed before the listener
	// notices and closes; give it a beat.
	time.Sleep(100 * time.Millisecond)

	if r.Len() != 0 {
		t.Errorf("registry size = %d, want 0", r.Len())
	}
}

func TestListener_Serve_CustomHostExtractor(t *testing.T) {
	// Custom extractor returns a fixed label regardless of the cert
	// contents — verifies the hook is honoured.
	clientTLS, serverTLS := mintTLSWithSPIFFE(t, "")

	r := routing.New()
	defer r.Close()
	l, err := routing.NewListener(routing.ListenerConfig{
		Addr: "127.0.0.1:0", TLSConfig: serverTLS, Registry: r,
		HostExtractor: func(_ *x509.Certificate) ([]string, error) {
			return []string{"forced-host"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx, ln) }()

	tlsClient, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tlsClient.Close()
	cliSess, err := yamux.Client(tlsClient, commontunnel.ClientConfig())
	if err != nil {
		t.Fatalf("yamux.Client: %v", err)
	}
	defer cliSess.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := r.Lookup("forced-host"); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("custom extractor never registered forced-host (registry len=%d)", r.Len())
}
