// Package tunnel is ssh-tunneld's outbound multiplexed tunnel client —
// dials ssh-proxyd over mTLS, negotiates the mux protocol (yamux),
// emits heartbeats, and reconnects with exponential backoff. Streams
// inbound from the proxy are handed off to package forward.
package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	commontunnel "github.com/abagile/tokyo3-ssh-proxy/internal/common/tunnel"
)

// SessionHandler is invoked once per established yamux session.
// Implementations typically loop on session.Accept() and hand each
// new stream off to the forwarder; returning ends the session's
// lifecycle and triggers the next reconnect.
//
// Handlers should respect ctx cancellation — when the parent Run
// loop is stopping, ctx is cancelled before the session is closed.
type SessionHandler func(ctx context.Context, session *yamux.Session) error

// Config wires a [Dialer]. All required fields are validated in
// [New]; optional knobs default to production-sane values.
type Config struct {
	// Target is the proxy address in host:port form. Required.
	Target string

	// TLSConfig carries the workload mTLS material — client cert,
	// trusted CA bundle for the proxy's server cert, ServerName, etc.
	// Required; the dialer never establishes a plaintext connection.
	TLSConfig *tls.Config

	// Handler is invoked per accepted session. Required.
	Handler SessionHandler

	// DialTimeout caps a single TCP+TLS connect attempt. 0 ⇒ DefaultDialTimeout.
	DialTimeout time.Duration

	// InitialBackoff is the first-failure reconnect delay. 0 ⇒ DefaultInitialBackoff.
	InitialBackoff time.Duration

	// MaxBackoff caps the exponential backoff. 0 ⇒ DefaultMaxBackoff.
	MaxBackoff time.Duration

	// BackoffJitter is the multiplicative jitter applied to each
	// backoff (0.2 ⇒ ±20%). 0 ⇒ DefaultBackoffJitter. Negative or
	// >=1 values are rejected.
	BackoffJitter float64

	// Now is the clock used for backoff calculations. nil ⇒ time.Now.
	Now func() time.Time

	// Rand picks the jitter delta. nil ⇒ a thread-local source.
	// Exposed so tests can pin the schedule deterministically.
	Rand func() float64

	// Log is the logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// Production defaults — picked to detect a half-open link within
// ~30s and to avoid pummelling certd / the proxy on a sustained
// outage.
const (
	DefaultDialTimeout    = 10 * time.Second
	DefaultInitialBackoff = 1 * time.Second
	DefaultMaxBackoff     = 30 * time.Second
	DefaultBackoffJitter  = 0.2
)

// Dialer maintains a live tunnel to ssh-proxyd. Stateless across
// reconnects; safe to embed in a single-purpose goroutine.
type Dialer struct {
	cfg Config
}

// New validates cfg and returns a [Dialer].
func New(cfg Config) (*Dialer, error) {
	if cfg.Target == "" {
		return nil, errors.New("target is required")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("TLSConfig is required")
	}
	if cfg.Handler == nil {
		return nil, errors.New("handler is required")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.InitialBackoff == 0 {
		cfg.InitialBackoff = DefaultInitialBackoff
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	if cfg.InitialBackoff > cfg.MaxBackoff {
		return nil, fmt.Errorf("InitialBackoff (%v) > MaxBackoff (%v)",
			cfg.InitialBackoff, cfg.MaxBackoff)
	}
	if cfg.BackoffJitter == 0 {
		cfg.BackoffJitter = DefaultBackoffJitter
	}
	if cfg.BackoffJitter < 0 || cfg.BackoffJitter >= 1 {
		return nil, fmt.Errorf("BackoffJitter must be in [0,1), got %v", cfg.BackoffJitter)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = func() float64 { return rand.Float64() } //nolint:gosec // jitter, not crypto
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Dialer{cfg: cfg}, nil
}

// DialOnce performs a single connect: TCP → TLS handshake → yamux
// client. The returned session is live; callers must close it (or
// let the reconnect loop in [Run] do so).
func (d *Dialer) DialOnce(ctx context.Context) (*yamux.Session, error) {
	dialCtx, cancel := context.WithTimeout(ctx, d.cfg.DialTimeout)
	defer cancel()

	tlsDialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: d.cfg.DialTimeout},
		Config:    d.cfg.TLSConfig.Clone(),
	}
	conn, err := tlsDialer.DialContext(dialCtx, "tcp", d.cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", d.cfg.Target, err)
	}
	session, err := yamux.Client(conn, commontunnel.ClientConfig())
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("yamux client: %w", err)
	}
	return session, nil
}

// Run dials, invokes Handler, and reconnects when the handler
// returns or the session dies. Returns when ctx is cancelled. The
// returned error is whatever ctx surfaces (typically
// [context.Canceled] / [context.DeadlineExceeded]); transient
// connect/session failures are logged and retried, never bubbled.
func (d *Dialer) Run(ctx context.Context) error {
	delay := d.cfg.InitialBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		session, err := d.DialOnce(ctx)
		if err != nil {
			d.cfg.Log.Warn("tunnel dial failed; backing off",
				"target", d.cfg.Target, "err", err, "backoff", delay)
			if sleepErr := d.sleep(ctx, d.applyJitter(delay)); sleepErr != nil {
				return sleepErr
			}
			delay = d.nextBackoff(delay)
			continue
		}

		// Reset backoff on a successful connection — subsequent
		// failures restart from InitialBackoff.
		delay = d.cfg.InitialBackoff
		d.cfg.Log.Info("tunnel connected", "target", d.cfg.Target,
			"remote_addr", session.RemoteAddr())

		runErr := d.runSession(ctx, session)
		_ = session.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		d.cfg.Log.Warn("tunnel session ended; reconnecting",
			"target", d.cfg.Target, "err", runErr)
	}
}

// runSession invokes the handler with a cancellable sub-ctx. When
// the yamux session is detected dead via session.CloseChan, the
// sub-ctx is cancelled so the handler can unwind quickly rather
// than waiting on stuck reads.
func (d *Dialer) runSession(ctx context.Context, session *yamux.Session) error {
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-session.CloseChan():
		case <-subCtx.Done():
		}
		cancel()
	}()

	return d.cfg.Handler(subCtx, session)
}

// nextBackoff doubles delay, capped at MaxBackoff. Jitter is applied
// at the sleep site rather than baked into the schedule so each
// retry uses the canonical sequence (1s → 2s → 4s …) before jitter.
func (d *Dialer) nextBackoff(delay time.Duration) time.Duration {
	next := delay * 2
	if next > d.cfg.MaxBackoff {
		return d.cfg.MaxBackoff
	}
	return next
}

// applyJitter perturbs delay by ±BackoffJitter*delay. Rand() returns
// [0,1); the result lands in [delay·(1-j), delay·(1+j)).
func (d *Dialer) applyJitter(delay time.Duration) time.Duration {
	if d.cfg.BackoffJitter == 0 {
		return delay
	}
	span := float64(delay) * d.cfg.BackoffJitter
	offset := (d.cfg.Rand()*2 - 1) * span
	out := time.Duration(float64(delay) + offset)
	if out < 0 {
		return 0
	}
	return out
}

// sleep blocks for d but returns immediately if ctx fires.
func (d *Dialer) sleep(ctx context.Context, dur time.Duration) error {
	if dur <= 0 {
		return nil
	}
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
