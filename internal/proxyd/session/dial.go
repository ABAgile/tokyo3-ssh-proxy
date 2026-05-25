package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// DefaultTargetPort is the TCP port [DialTarget] connects to when the
// caller passes a bare hostname without ":port".
const DefaultTargetPort = "22"

// DefaultDialTimeout is the maximum time [DialTarget] waits for both
// the TCP connect and the SSH handshake to complete.
const DefaultDialTimeout = 15 * time.Second

// Transport produces the raw [net.Conn] that the SSH handshake will
// run on top of. The default (nil Transport) is a TCP dial via
// [net.Dialer]; ssh-proxyd injects a routing-registry-backed
// transport in production so traffic flows over an existing yamux
// tunnel when one is registered for the host.
//
// Implementations should honour ctx for cancellation and surface
// transport-level errors verbatim — DialTarget wraps them with the
// "dial <addr>" prefix.
type Transport func(ctx context.Context, addr string) (net.Conn, error)

// DialConfig configures a [DialTarget] call.
type DialConfig struct {
	// Address is the target's host or host:port. When the port is
	// omitted, [DefaultTargetPort] is appended.
	Address string
	// User is the remote login name; the target's sshd uses this to
	// pick the account whose authorized_keys is consulted.
	User string
	// Signer authenticates the proxy to the target's sshd. For this
	// slice it's a static client key configured at startup; later
	// slices replace it with a per-session cert minted by certd.
	Signer gossh.Signer
	// HostKeyCallback verifies the target's host key. Callers should
	// supply a real known_hosts-backed callback (or a CA-cert-based
	// one once host certs are wired); passing
	// [gossh.InsecureIgnoreHostKey] is dev-only.
	HostKeyCallback gossh.HostKeyCallback
	// Timeout caps the time the dial may take. Zero uses
	// [DefaultDialTimeout].
	Timeout time.Duration
	// Transport optionally overrides the raw connection acquisition.
	// Nil ⇒ a direct TCP dial. The proxy passes a routing-registry-
	// backed transport here so tunneled hosts get an existing yamux
	// stream instead of a fresh TCP connection.
	Transport Transport
}

// DialTarget opens an outbound SSH client connection to cfg.Address
// authenticated as cfg.User. The returned [gossh.Client] is the
// proxy's handle to the target — callers open channels on it and
// pipe traffic from the inbound user-side connection.
//
// ctx is honoured for the TCP connect; the SSH handshake itself runs
// under cfg.Timeout (the SSH library doesn't accept a context).
func DialTarget(ctx context.Context, cfg DialConfig) (*gossh.Client, error) {
	if cfg.Address == "" {
		return nil, errors.New("DialTarget: Address is required")
	}
	if cfg.User == "" {
		return nil, errors.New("DialTarget: User is required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("DialTarget: Signer is required")
	}
	if cfg.HostKeyCallback == nil {
		return nil, errors.New("DialTarget: HostKeyCallback is required")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultDialTimeout
	}

	addr := cfg.Address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// SplitHostPort fails on bare "host" (no colon); add the
		// default port. For IPv6 literals the caller must already
		// supply brackets + port.
		addr = net.JoinHostPort(addr, DefaultTargetPort)
	}

	transport := cfg.Transport
	if transport == nil {
		transport = func(ctx context.Context, target string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, "tcp", target)
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := transport(dialCtx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	clientCfg := &gossh.ClientConfig{
		User: cfg.User,
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(cfg.Signer),
		},
		HostKeyCallback: cfg.HostKeyCallback,
		Timeout:         timeout,
	}

	sshConn, channels, requests, err := gossh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake to %s: %w", addr, err)
	}
	return gossh.NewClient(sshConn, channels, requests), nil
}
