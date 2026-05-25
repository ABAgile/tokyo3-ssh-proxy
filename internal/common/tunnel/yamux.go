// Package tunnel holds the multiplex protocol primitives shared between
// ssh-proxyd (server side) and ssh-tunneld (client side) — yamux config,
// framing, keepalive constants, and reconnection semantics.
//
// Both sides must agree on the yamux parameters or the session will
// flap. Construction goes through [ClientConfig] / [ServerConfig] so
// drift between the two binaries is impossible at compile time.
package tunnel

import (
	"errors"
	"io"
	"time"

	"github.com/hashicorp/yamux"
)

// Connection-level constants. These are the values both sides set in
// their yamux config; tweaking them is a coordinated change.
const (
	// KeepAliveInterval is how often each side sends a yamux ping.
	// Short enough to detect a half-open TCP connection within a few
	// seconds; long enough that idle bursts don't waste CPU.
	KeepAliveInterval = 15 * time.Second

	// ConnectionWriteTimeout is how long a single yamux frame write
	// can stall before yamux tears down the session. Must be larger
	// than KeepAliveInterval so a slow ping doesn't kill an
	// otherwise-healthy link.
	ConnectionWriteTimeout = 30 * time.Second

	// MaxStreamWindowSize is the per-stream flow-control window
	// (4 MiB). SSH session bytes are bursty but small per packet;
	// this gives reasonable throughput on fat links without
	// over-committing memory per stream.
	MaxStreamWindowSize = 4 * 1024 * 1024
)

// ClientConfig returns a [*yamux.Config] for ssh-tunneld (the side
// that *initiates* the outbound connection). Defensive copies keep
// callers from mutating the shared defaults.
func ClientConfig() *yamux.Config {
	return baseConfig()
}

// ServerConfig returns a [*yamux.Config] for ssh-proxyd (the side
// that *accepts* the inbound tunnel). Currently identical to
// ClientConfig; kept as a distinct constructor so future asymmetry
// (per-side log prefixes, accept-only window tuning) has a place
// to live.
func ServerConfig() *yamux.Config {
	return baseConfig()
}

func baseConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = KeepAliveInterval
	cfg.ConnectionWriteTimeout = ConnectionWriteTimeout
	cfg.MaxStreamWindowSize = MaxStreamWindowSize
	// Suppress yamux's stdlib-logger output — tunneld and proxyd
	// route logs through slog. Errors that matter surface as
	// session.Wait() return values; chatter doesn't help.
	cfg.LogOutput = io.Discard
	return cfg
}

// ValidateConfig is a sanity check tests use to catch configs that
// drift out of sync between client and server. Exposed (not just
// inline asserts) so consumers can pin the contract in their own
// tests.
func ValidateConfig(cfg *yamux.Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if cfg.KeepAliveInterval != KeepAliveInterval {
		return errors.New("KeepAliveInterval drifted")
	}
	if cfg.ConnectionWriteTimeout != ConnectionWriteTimeout {
		return errors.New("ConnectionWriteTimeout drifted")
	}
	if cfg.MaxStreamWindowSize != MaxStreamWindowSize {
		return errors.New("MaxStreamWindowSize drifted")
	}
	return nil
}
