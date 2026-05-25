// Package ssh hosts the SSH server side of ssh-proxyd — the protocol
// terminator that accepts user connections, validates the user cert
// against certd's user CA pubkey, dials the target, and pipes
// channels between the two. Built on golang.org/x/crypto/ssh.
//
// The target host is parsed from the SSH username field (the
// convention is "<remote-user>@<target-host>"), so no custom
// protocol is required.
package ssh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/rbac"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/revcheck"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/routing"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/session"
)

// Config configures a [Server]. Required: HostSigner, TrustedUserCA,
// ClientSigner, TargetHostKeyCallback. Log defaults to slog.Default()
// when nil.
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
	// ClientSignerFunc returns the [gossh.Signer] used to authenticate
	// to the target sshd on a per-session basis. It is invoked once
	// per inbound connection with the remote user the cert should
	// principal-bind to; implementations may return a static key
	// (dev) or mint a short-lived cert from certd (production).
	// Required.
	ClientSignerFunc func(ctx context.Context, remoteUser string) (gossh.Signer, error)
	// TargetHostKeyCallback verifies the target sshd's host key.
	// Production should use a known_hosts-backed callback (or one
	// that trusts certd-issued host certs); passing
	// [gossh.InsecureIgnoreHostKey] is dev-only. Required.
	TargetHostKeyCallback gossh.HostKeyCallback
	// RecordingSink, when non-nil, captures every session channel's
	// PTY traffic into an asciinema cast. nil disables recording.
	RecordingSink recording.Sink
	// Audit, when non-nil, receives session lifecycle + channel
	// rejection events. When nil, [audit.NoopSink] is used (events
	// are discarded silently).
	Audit audit.Sink
	// TunnelRegistry, when non-nil, is consulted before each target
	// dial. When the target host is registered (an ssh-tunneld has an
	// active session for it), the proxy routes the user session over
	// that yamux tunnel as a new stream. Unregistered hosts fall back
	// to direct TCP. nil disables tunnel routing entirely (every
	// session is a direct dial).
	TunnelRegistry *routing.Registry
	// Revocations, when non-nil, is consulted on every cert
	// authentication; certs that match the configured store are
	// refused at handshake time. nil disables revocation checking
	// entirely (every otherwise-valid cert is accepted). The proxy
	// owns no lifecycle — caller starts/stops the underlying
	// polling loop.
	Revocations revcheck.Checker
	// HandshakeTimeout caps the time a single inbound connection
	// can take to complete the SSH handshake. Defaults to 30s when
	// zero; prevents slow-loris-style resource exhaustion on the
	// accept goroutine.
	HandshakeTimeout time.Duration
}

// StaticSigner adapts a fixed [gossh.Signer] to the per-session
// [Config.ClientSignerFunc] shape. Useful for dev / tests where the
// proxy uses a long-lived shared key instead of certd-minted
// per-session certs.
func StaticSigner(sig gossh.Signer) func(context.Context, string) (gossh.Signer, error) {
	return func(context.Context, string) (gossh.Signer, error) {
		return sig, nil
	}
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
	if cfg.ClientSignerFunc == nil {
		return nil, errors.New("ssh.New: ClientSignerFunc is required (target-side authentication)")
	}
	if cfg.TargetHostKeyCallback == nil {
		return nil, errors.New("ssh.New: TargetHostKeyCallback is required (target-side host key verification)")
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

// handleConn runs the SSH handshake on conn, parses the target out
// of the username, dials it, and proxies channels between the two
// ends until either side closes.
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

	// Build the session attribution once at handshake-complete and
	// reuse it across every event emitted for this connection.
	ev := sessionEvents{
		sink:       s.audit(),
		log:        s.log,
		sessionID:  uuid.NewString(),
		user:       sshConn.Permissions.Extensions["key-id"],
		principals: sshConn.Permissions.Extensions["principals"],
		target:     sshConn.Permissions.Extensions["target-host"],
		remoteUser: sshConn.Permissions.Extensions["remote-user"],
		clientIP:   ipFromAddr(conn.RemoteAddr()),
	}

	s.log.Info("ssh session opened",
		"session_id", ev.sessionID,
		"user", sshConn.User(),
		"key_id", ev.user,
		"principals", ev.principals,
		"remote", conn.RemoteAddr(),
	)
	ev.emit(ctx, audit.ActionSessionOpened, "", nil)
	defer func() {
		s.log.Info("ssh session closed",
			"session_id", ev.sessionID, "user", sshConn.User(), "remote", conn.RemoteAddr())
		ev.emit(ctx, audit.ActionSessionClosed, "", nil)
		_ = sshConn.Close()
	}()

	// Global out-of-band requests are not used yet — discard.
	go gossh.DiscardRequests(requests)

	// Mint (or fetch) the outbound signer for this session. When
	// certd is wired, this is a freshly-minted short-lived cert tied
	// to the user's identity; otherwise it's the static fallback key.
	signer, err := s.cfg.ClientSignerFunc(ctx, ev.remoteUser)
	if err != nil {
		reason := fmt.Sprintf("proxy could not obtain a client signer: %v", err)
		s.log.Warn("obtain client signer", "err", err)
		ev.emit(ctx, audit.ActionChannelRejected, reason, map[string]any{"stage": "client_signer"})
		rejectAll(ctx, channels, gossh.ConnectionFailed, reason)
		return
	}

	// Dial the target sshd. The handshake timeout doesn't apply
	// here — DialTarget has its own. When a tunnel is registered for
	// the host, the Transport hook routes the dial over the existing
	// yamux session; otherwise DialTarget falls back to a direct TCP
	// connect.
	target, err := session.DialTarget(ctx, session.DialConfig{
		Address:         ev.target,
		User:            ev.remoteUser,
		Signer:          signer,
		HostKeyCallback: s.cfg.TargetHostKeyCallback,
		Transport:       s.tunnelTransport(ev.target),
	})
	if err != nil {
		reason := fmt.Sprintf("target unreachable: %v", err)
		s.log.Warn("target dial failed",
			"target", ev.target, "remote_user", ev.remoteUser, "err", err)
		ev.emit(ctx, audit.ActionChannelRejected, reason, map[string]any{"stage": "target_dial"})
		rejectAll(ctx, channels, gossh.ConnectionFailed, reason)
		return
	}
	defer target.Close()

	s.log.Info("target connected",
		"session_id", ev.sessionID, "target", ev.target, "remote_user", ev.remoteUser)

	// Build the channel proxier with cert-driven RBAC gates,
	// optional recording, and the audit context so the recorder can
	// emit recording.completed events tied to this connection's
	// SessionID.
	enforcer := rbac.New(sshConn.Permissions)
	proxier := session.NewProxier(session.Config{
		Target:    target,
		Enforcer:  enforcer,
		Sink:      s.cfg.RecordingSink,
		User:      ev.user,
		Host:      ev.target,
		Audit:     ev.sink,
		SessionID: ev.sessionID,
		AuditAttr: session.RecordingAuditAttr{
			Principals: ev.principals,
			Target:     ev.target,
			RemoteUser: ev.remoteUser,
			ClientIP:   ev.clientIP,
		},
		Log: s.log,
	})
	proxier.HandleNewChannels(channels)
}

// audit returns the audit sink, defaulting to NoopSink when the
// Config didn't set one. Reading the field through this accessor
// keeps the nil-safe pattern in one place.
func (s *Server) audit() audit.Sink {
	if s.cfg.Audit == nil {
		return audit.NoopSink
	}
	return s.cfg.Audit
}

// tunnelTransport returns the session.Transport hook for a given
// target host. When no registry is configured the result is nil
// (DialTarget falls back to direct TCP). When the registry is
// configured but the host isn't registered, the transport still
// surfaces ErrNoTunnel as a fallback by dialing TCP — operators can
// run tunneled hosts alongside direct-connect hosts without
// per-target config.
func (s *Server) tunnelTransport(host string) session.Transport {
	if s.cfg.TunnelRegistry == nil {
		return nil
	}
	registry := s.cfg.TunnelRegistry
	// host is "<addr>:<port>" — strip the port for the registry
	// lookup; tunnel registrations key off the hostname only.
	lookupHost := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		lookupHost = h
	}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := registry.Open(ctx, lookupHost)
		if err == nil {
			s.log.Debug("dialing target via tunnel",
				"host", lookupHost, "addr", addr)
			return conn, nil
		}
		if !errors.Is(err, routing.ErrNoTunnel) {
			return nil, err
		}
		// No tunnel for this host — fall back to a direct TCP dial.
		s.log.Debug("no tunnel registered; dialing target directly",
			"host", lookupHost, "addr", addr)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// sessionEvents bundles the per-connection attribution shared by
// every audit emission ssh-proxyd makes during one inbound session.
type sessionEvents struct {
	sink       audit.Sink
	log        *slog.Logger
	sessionID  string
	user       string
	principals string
	target     string
	remoteUser string
	clientIP   string
}

// emit packages an audit Entry and fires the sink. Errors are logged
// but never fail the request — audit is observational.
func (e *sessionEvents) emit(ctx context.Context, action, reason string, metadata map[string]any) {
	var md string
	if len(metadata) > 0 {
		if b, err := json.Marshal(metadata); err == nil {
			md = string(b)
		}
	}
	entry := audit.Entry{
		ID:         uuid.NewString(),
		Action:     action,
		SessionID:  e.sessionID,
		User:       e.user,
		Principals: e.principals,
		Target:     e.target,
		RemoteUser: e.remoteUser,
		ClientIP:   e.clientIP,
		Reason:     reason,
		Metadata:   md,
		OccurredAt: time.Now().UTC(),
	}
	if err := e.sink.Append(ctx, entry); err != nil {
		e.log.Warn("audit append failed", "action", action, "err", err)
	}
}

// ipFromAddr extracts a bare IP from a net.Addr; returns the
// remote's string representation on parse failure.
func ipFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// rejectAll drains every remaining NewChannel from chans, rejecting
// each with the given reason/message. Honours ctx so shutdown is
// instant when the server is stopping.
func rejectAll(ctx context.Context, chans <-chan gossh.NewChannel, reason gossh.RejectionReason, msg string) {
	for newCh := range chans {
		select {
		case <-ctx.Done():
			_ = newCh.Reject(gossh.ConnectionFailed, "server shutting down")
			continue
		default:
		}
		_ = newCh.Reject(reason, msg)
	}
}

// publicKeyCallback validates that key is a User certificate signed by
// the configured TrustedUserCA and that the *remote-user* portion of
// the SSH username (i.e., the bit to the left of "@") appears in the
// cert's principals list. On success the resolved remote-user and
// target-host are stashed in [ssh.Permissions.Extensions] so the
// connection handler doesn't re-parse the username.
//
// The SSH username convention is "<remote-user>@<target-host>"; the
// cert's principals are remote-user values (e.g., "alice", "deploy"),
// not "alice@target". Validating against the full username would
// reject every cert. We wrap the ConnMetadata so the underlying
// [gossh.CertChecker.Authenticate] sees just the remote-user.
//
// Uses Authenticate (not bare CheckCert) so the IsUserAuthority step
// runs — bare CheckCert silently accepts certs signed by any CA.
func (s *Server) publicKeyCallback(meta gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
	remoteUser, targetHost, parseErr := session.ParseTarget(meta.User())
	if parseErr != nil {
		s.log.Debug("ssh username missing target", "user", meta.User(), "err", parseErr)
		return nil, parseErr
	}

	checker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), s.cfg.TrustedUserCA.Marshal())
		},
		// IsRevoked runs after IsUserAuthority + the cert's own
		// validity envelope check, so a revoked-but-otherwise-valid
		// cert lands here with .KeyId / .Serial populated.
		IsRevoked: func(cert *gossh.Certificate) bool {
			if s.cfg.Revocations == nil {
				return false
			}
			revoked := s.cfg.Revocations.IsRevoked(cert)
			if revoked {
				s.log.Info("user cert refused: revoked",
					"key_id", cert.KeyId, "serial", cert.Serial)
			}
			return revoked
		},
	}
	perms, err := checker.Authenticate(remoteUserMeta{ConnMetadata: meta, user: remoteUser}, key)
	if err != nil {
		s.log.Debug("user cert rejected",
			"user", meta.User(), "remote_user", remoteUser, "err", err)
		return nil, err
	}

	cert := key.(*gossh.Certificate) // safe: Authenticate guaranteed it

	// Cert is otherwise valid — enforce the source-address critical
	// option here (only check we can do at handshake time; channel
	// and request gates run later via the rbac package).
	enforcer := rbac.New(perms)
	if !enforcer.SourceAddressOK(meta.RemoteAddr()) {
		s.log.Info("user cert rejected by source-address",
			"user", meta.User(), "key_id", cert.KeyId, "remote", meta.RemoteAddr())
		return nil, fmt.Errorf("source-address restriction: remote %s not in allowed list", meta.RemoteAddr())
	}

	// Merge cert.Permissions (returned by Authenticate) with the
	// connection-level attribution fields the downstream code reads,
	// plus the parsed target host so handleConn doesn't re-parse.
	if perms.Extensions == nil {
		perms.Extensions = map[string]string{}
	}
	perms.Extensions["key-id"] = cert.KeyId
	perms.Extensions["principals"] = strings.Join(cert.ValidPrincipals, ",")
	perms.Extensions["serial"] = fmt.Sprintf("%d", cert.Serial)
	perms.Extensions["remote-user"] = remoteUser
	perms.Extensions["target-host"] = targetHost
	return perms, nil
}

// remoteUserMeta wraps a [gossh.ConnMetadata] so the underlying
// [gossh.CertChecker] sees only the remote-user portion of the SSH
// username. All other ConnMetadata methods (RemoteAddr, etc.) pass
// through to the original.
type remoteUserMeta struct {
	gossh.ConnMetadata
	user string
}

func (m remoteUserMeta) User() string { return m.user }

// isClosedErr reports whether err is a "listener closed" sentinel.
// net.ErrClosed lands in net.OpError.Err, so [errors.Is] handles it.
func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
