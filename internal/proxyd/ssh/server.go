// Package ssh hosts the SSH server side of ssh-proxyd — the protocol
// terminator that accepts user connections, validates the user cert
// against certd's user CA pubkey, and hands off to the routing layer.
// Built on golang.org/x/crypto/ssh.
//
// This slice only proves the auth path end to end:
// every accepted session is rejected with a clear placeholder
// message. Real session forwarding lands in phase 3.3, recording in
// 3.4, per-session cert minting in 3.5.
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// Config configures a [Server]. Required fields are HostSigner and
// TrustedUserCA; Log defaults to slog.Default() when nil.
type Config struct {
	// Addr is the TCP listen address (e.g., ":2222"). Required.
	Addr string
	// Log is the structured logger used for connection and handshake
	// events. Defaults to [slog.Default] when nil.
	Log *slog.Logger
	// HostSigner is the proxy's SSH host key — presented to clients
	// during the SSH handshake so they know they're talking to
	// ssh-proxyd. Required.
	HostSigner gossh.Signer
	// TrustedUserCA is the public key whose user certs the proxy
	// accepts. Issued by certd; populated at startup from a file or
	// API discovery. Required.
	TrustedUserCA gossh.PublicKey
	// HandshakeTimeout caps the time a single inbound connection
	// can take to complete the SSH handshake. Defaults to 30s when
	// zero; prevents slow-loris-style resource exhaustion on the
	// accept goroutine.
	HandshakeTimeout time.Duration
}

// Server is the SSH gateway. Accepts connections via [ListenAndServe];
// graceful shutdown via context cancellation.
type Server struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
}

// New validates cfg and returns a [Server] ready for [ListenAndServe].
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		return nil, errors.New("ssh.New: Addr is required")
	}
	if cfg.HostSigner == nil {
		return nil, errors.New("ssh.New: HostSigner is required")
	}
	if cfg.TrustedUserCA == nil {
		return nil, errors.New("ssh.New: TrustedUserCA is required")
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 30 * time.Second
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, log: log}, nil
}

// ListenAndServe binds and serves until ctx is cancelled or the
// underlying listener fails. Returns the underlying listen error;
// returns nil for a clean context-driven shutdown.
//
// New connections complete the SSH handshake on their own goroutine;
// the accept loop never blocks on a single slow client. Shutdown
// closes the listener (stopping new accepts) then waits for in-flight
// handshake/session goroutines to drain.
func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	s.log.Info("listening", "addr", listener.Addr())

	// Close the listener when ctx is cancelled — Accept then returns
	// a *net.OpError we treat as a clean shutdown.
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedErr(err) {
				s.log.Info("listener closed")
				break
			}
			return fmt.Errorf("accept: %w", err)
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(ctx, c)
		}(conn)
	}

	s.wg.Wait()
	return nil
}

// Addr returns the address the listener is bound to. Useful in tests
// (caller passes ":0" and reads back the kernel-assigned port).
// Returns an empty string before [ListenAndServe] has bound.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// handleConn runs the SSH handshake on conn and dispatches accepted
// sessions. In this slice every channel request is rejected with a
// placeholder message — the real forwarding wiring lands in phase 3.3.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	deadline := time.Now().Add(s.cfg.HandshakeTimeout)
	_ = conn.SetDeadline(deadline)

	srvCfg := &gossh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
	}
	srvCfg.AddHostKey(s.cfg.HostSigner)

	sshConn, channels, requests, err := gossh.NewServerConn(conn, srvCfg)
	if err != nil {
		s.log.Debug("ssh handshake failed", "remote", conn.RemoteAddr(), "err", err)
		return
	}
	// Clear deadline now that the handshake is done — real sessions
	// can be long-lived.
	_ = conn.SetDeadline(time.Time{})

	s.log.Info("ssh session opened",
		"user", sshConn.User(),
		"key_id", sshConn.Permissions.Extensions["key-id"],
		"principals", sshConn.Permissions.Extensions["principals"],
		"remote", conn.RemoteAddr(),
	)
	defer func() {
		s.log.Info("ssh session closed", "user", sshConn.User(), "remote", conn.RemoteAddr())
		_ = sshConn.Close()
	}()

	// Global out-of-band requests are not used yet — discard.
	go gossh.DiscardRequests(requests)

	for newCh := range channels {
		// Cancel-aware close path: when the server is shutting down
		// we want to stop accepting new channels.
		select {
		case <-ctx.Done():
			_ = newCh.Reject(gossh.ConnectionFailed, "server shutting down")
			continue
		default:
		}
		if err := newCh.Reject(gossh.ConnectionFailed, "ssh-proxyd session forwarding not yet implemented (phase 3.3)"); err != nil {
			s.log.Debug("channel reject failed", "err", err)
		}
	}
}

// publicKeyCallback validates that key is a User certificate signed by
// the configured TrustedUserCA and that the requested user appears in
// its principals list. On success it returns the cert's KeyID +
// principals in [ssh.Permissions.Extensions] so the connection
// handler downstream can attribute the session in audit logs without
// re-parsing the cert.
//
// Uses [gossh.CertChecker.Authenticate], which does:
//   - reject non-cert keys
//   - require CertType == UserCert
//   - call IsUserAuthority (signed by trusted CA)
//   - CheckCert (principals + validity + critical options)
//
// All in one call. Bare CheckCert deliberately omits the IsUserAuthority
// step — using it directly would silently accept certs signed by any
// CA, including untrusted ones.
func (s *Server) publicKeyCallback(meta gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
	checker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), s.cfg.TrustedUserCA.Marshal())
		},
	}
	perms, err := checker.Authenticate(meta, key)
	if err != nil {
		s.log.Debug("user cert rejected",
			"user", meta.User(), "err", err)
		return nil, err
	}

	cert := key.(*gossh.Certificate) // safe: Authenticate guaranteed it
	// Merge cert.Permissions (returned by Authenticate) with the
	// connection-level attribution fields the downstream code reads.
	if perms.Extensions == nil {
		perms.Extensions = map[string]string{}
	}
	perms.Extensions["key-id"] = cert.KeyId
	perms.Extensions["principals"] = strings.Join(cert.ValidPrincipals, ",")
	perms.Extensions["serial"] = fmt.Sprintf("%d", cert.Serial)
	return perms, nil
}

// isClosedErr reports whether err is a "listener closed" sentinel.
// net.ErrClosed lands in net.OpError.Err, so [errors.Is] handles it.
func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
