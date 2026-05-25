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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/rbac"
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
	// ClientSigner authenticates the proxy to target sshds when it
	// opens an outbound connection on behalf of an inbound user.
	// For this slice it's a static key configured at startup; later
	// slices replace it with a per-session cert minted by certd.
	// Required.
	ClientSigner gossh.Signer
	// TargetHostKeyCallback verifies the target sshd's host key.
	// Production should use a known_hosts-backed callback (or one
	// that trusts certd-issued host certs); passing
	// [gossh.InsecureIgnoreHostKey] is dev-only. Required.
	TargetHostKeyCallback gossh.HostKeyCallback
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
	if cfg.ClientSigner == nil {
		return nil, errors.New("ssh.New: ClientSigner is required (target-side authentication)")
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

	// remote-user + target-host were resolved at handshake time by
	// publicKeyCallback and stashed in Permissions.Extensions.
	remoteUser := sshConn.Permissions.Extensions["remote-user"]
	targetHost := sshConn.Permissions.Extensions["target-host"]

	// Dial the target sshd. The handshake timeout doesn't apply
	// here — DialTarget has its own.
	target, err := session.DialTarget(ctx, session.DialConfig{
		Address:         targetHost,
		User:            remoteUser,
		Signer:          s.cfg.ClientSigner,
		HostKeyCallback: s.cfg.TargetHostKeyCallback,
	})
	if err != nil {
		s.log.Warn("target dial failed",
			"target", targetHost, "remote_user", remoteUser, "err", err)
		rejectAll(ctx, channels, gossh.ConnectionFailed,
			fmt.Sprintf("target unreachable: %v", err))
		return
	}
	defer target.Close()

	s.log.Info("target connected",
		"target", targetHost, "remote_user", remoteUser)

	// Build the channel proxier with cert-driven RBAC gates.
	enforcer := rbac.New(sshConn.Permissions)
	proxier := session.NewProxier(target, enforcer, s.log)
	proxier.HandleNewChannels(channels)
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
