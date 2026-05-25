package routing

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/hashicorp/yamux"

	commontunnel "github.com/abagile/tokyo3-ssh-proxy/internal/common/tunnel"
)

// ListenerConfig wires a tunnel [Listener]. Required fields are
// validated at [NewListener] time; optional knobs default to the
// production-sensible values used across the rest of the tunneld /
// proxyd surface.
type ListenerConfig struct {
	// Addr is the listen address (e.g., ":2223"). Required.
	Addr string

	// TLSConfig must be configured for mTLS:
	//   Certificates: proxy server cert + key
	//   ClientCAs:    CA bundle that signs ssh-tunneld workload certs
	//   ClientAuth:   RequireAndVerifyClientCert
	// Required.
	TLSConfig *tls.Config

	// Registry is the map the listener populates. Required.
	Registry *Registry

	// HostExtractor returns the host labels to register the session
	// under, given the peer's verified leaf cert. nil ⇒
	// [HostFromSPIFFE] — the convention is a SPIFFE URI of the form
	// "spiffe://<td>/host/<fqdn>".
	HostExtractor func(leaf *x509.Certificate) ([]string, error)

	// Log is the logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// Listener accepts inbound mTLS connections from ssh-tunneld
// instances, wraps each in a yamux server session, and registers the
// session in [Registry] under the host labels derived from the
// peer's workload identity cert. The listener owns the lifecycle of
// each session — when a session closes (peer disconnect, idle
// timeout, etc.), the entry is removed from the registry.
type Listener struct {
	cfg ListenerConfig
}

// NewListener validates cfg and returns a [Listener].
func NewListener(cfg ListenerConfig) (*Listener, error) {
	if cfg.Addr == "" {
		return nil, errors.New("addr is required")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("TLSConfig is required")
	}
	if cfg.Registry == nil {
		return nil, errors.New("registry is required")
	}
	if cfg.HostExtractor == nil {
		cfg.HostExtractor = defaultHostExtractor
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Listener{cfg: cfg}, nil
}

// ListenAndServe binds the configured address and accepts inbound
// connections until ctx is cancelled. Per-connection failures (TLS
// handshake error, missing SPIFFE URI, conflicting host label) are
// logged and dropped; only failures binding the listener itself are
// returned.
func (l *Listener) ListenAndServe(ctx context.Context) error {
	ln, err := tls.Listen("tcp", l.cfg.Addr, l.cfg.TLSConfig)
	if err != nil {
		return fmt.Errorf("listen %s: %w", l.cfg.Addr, err)
	}
	l.cfg.Log.Info("tunnel listener bound", "addr", ln.Addr().String())
	return l.serve(ctx, ln)
}

// Serve accepts on an externally-supplied listener. Useful when the
// caller wants to control the bind (e.g., systemd socket activation,
// tests against a free ephemeral port).
func (l *Listener) Serve(ctx context.Context, ln net.Listener) error {
	return l.serve(ctx, ln)
}

func (l *Listener) serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			l.handleConn(ctx, c)
		}(conn)
	}
}

// handleConn drives the per-connection lifecycle. Any failure before
// registration tears the connection down silently (logged at warn);
// after registration, the session is owned by the registry until
// CloseChan fires.
func (l *Listener) handleConn(ctx context.Context, conn net.Conn) {
	defer func() {
		// Belt-and-braces close; yamux.Session.Close also closes the
		// underlying conn but the early-failure paths skip yamux.
		_ = conn.Close()
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		l.cfg.Log.Warn("tunnel accept got non-TLS connection",
			"remote_addr", conn.RemoteAddr())
		return
	}
	// Force the handshake so PeerCertificates is populated before we
	// extract the SPIFFE URI.
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		l.cfg.Log.Warn("tunnel TLS handshake failed",
			"remote_addr", conn.RemoteAddr(), "err", err)
		return
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		l.cfg.Log.Warn("tunnel peer presented no client cert",
			"remote_addr", conn.RemoteAddr())
		return
	}
	leaf := state.PeerCertificates[0]

	hosts, err := l.cfg.HostExtractor(leaf)
	if err != nil {
		l.cfg.Log.Warn("tunnel peer cert: extract host failed",
			"remote_addr", conn.RemoteAddr(),
			"subject", leaf.Subject.String(), "err", err)
		return
	}
	if len(hosts) == 0 {
		l.cfg.Log.Warn("tunnel peer cert: no hosts derived",
			"remote_addr", conn.RemoteAddr(),
			"subject", leaf.Subject.String())
		return
	}

	session, err := yamux.Server(tlsConn, commontunnel.ServerConfig())
	if err != nil {
		l.cfg.Log.Warn("tunnel yamux setup failed",
			"remote_addr", conn.RemoteAddr(), "err", err)
		return
	}

	registered, err := l.cfg.Registry.Register(session, hosts...)
	if err != nil {
		l.cfg.Log.Warn("tunnel register failed",
			"remote_addr", conn.RemoteAddr(),
			"hosts", hosts, "err", err)
		_ = session.Close()
		return
	}
	l.cfg.Log.Info("tunnel registered",
		"remote_addr", conn.RemoteAddr(),
		"hosts", registered)

	defer func() {
		l.cfg.Registry.Unregister(session)
		_ = session.Close()
		l.cfg.Log.Info("tunnel disconnected",
			"remote_addr", conn.RemoteAddr(),
			"hosts", registered)
	}()

	// Block until the session ends or ctx fires.
	select {
	case <-session.CloseChan():
	case <-ctx.Done():
	}
}

// HostFromSPIFFE is the default [ListenerConfig.HostExtractor].
// It expects exactly one SPIFFE URI in the leaf cert with a path of
// the form "/host/<fqdn>" and returns the fqdn as the single host
// label. The convention matches certd's SPIFFE issuance shape for
// ssh-tunneld workloads.
//
// Hosts with multiple aliases (e.g., FQDN + short name) should
// register both via the path "/host/<fqdn>,alias1,alias2" — the
// comma-separated suffix is split into multiple labels.
func HostFromSPIFFE(leaf *x509.Certificate) ([]string, error) {
	if leaf == nil {
		return nil, errors.New("nil cert")
	}
	var spiffeURI *url.URL
	for _, u := range leaf.URIs {
		if strings.EqualFold(u.Scheme, "spiffe") {
			if spiffeURI != nil {
				return nil, errors.New("cert has multiple SPIFFE URIs")
			}
			spiffeURI = u
		}
	}
	if spiffeURI == nil {
		return nil, errors.New("cert has no SPIFFE URI")
	}
	const prefix = "/host/"
	if !strings.HasPrefix(spiffeURI.Path, prefix) {
		return nil, fmt.Errorf("SPIFFE path %q does not start with %s", spiffeURI.Path, prefix)
	}
	tail := strings.TrimPrefix(spiffeURI.Path, prefix)
	if tail == "" {
		return nil, errors.New("SPIFFE path has no host component")
	}
	parts := strings.Split(tail, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("SPIFFE host component is empty after parsing")
	}
	return out, nil
}

// defaultHostExtractor is the indirection point so tests can swap
// the extractor without touching the public [HostFromSPIFFE] symbol.
func defaultHostExtractor(leaf *x509.Certificate) ([]string, error) {
	return HostFromSPIFFE(leaf)
}
