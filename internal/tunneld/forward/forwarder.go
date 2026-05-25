// Package forward receives inbound streams from the tunnel, dials the
// local sshd, and pipes bytes between the two. The effective SSH
// session terminates between ssh-proxyd (server side) and the host's
// local sshd (target side); this package is pure transport.
//
// The forwarder implements [github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/tunnel.SessionHandler]
// so it can be handed straight to a [tunnel.Dialer.Run] loop. A
// dial failure on the local sshd closes only the offending stream;
// the session keeps serving subsequent streams so an sshd restart
// doesn't take the whole tunnel down.
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/tunnel"
)

// Compile-time check: Forwarder.Handle must satisfy tunnel.SessionHandler
// so callers can pass it straight to tunnel.Dialer's Config.Handler.
var _ tunnel.SessionHandler = (*Forwarder)(nil).Handle

// Config wires a [Forwarder].
type Config struct {
	// LocalAddr is the host:port of the local sshd. 0 ⇒ 127.0.0.1:22.
	LocalAddr string

	// DialTimeout caps a single dial to the local sshd. 0 ⇒ DefaultDialTimeout.
	DialTimeout time.Duration

	// Dialer is the function used to reach the local sshd. nil ⇒ a
	// default [net.Dialer]. Exposed so tests can intercept the dial
	// without a real listener.
	Dialer func(ctx context.Context, addr string) (net.Conn, error)

	// Log is the logger. nil ⇒ slog.Default.
	Log *slog.Logger
}

// Defaults — sshd runs on 22; 5s is generous on loopback.
const (
	DefaultLocalAddr   = "127.0.0.1:22"
	DefaultDialTimeout = 5 * time.Second
)

// Forwarder is a [tunnel.SessionHandler]. Stateless across streams;
// safe to reuse across reconnects.
type Forwarder struct {
	cfg Config
}

// New validates cfg and returns a [Forwarder]. Defaults are applied
// for optional knobs.
func New(cfg Config) *Forwarder {
	if cfg.LocalAddr == "" {
		cfg.LocalAddr = DefaultLocalAddr
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.Dialer == nil {
		cfg.Dialer = func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Forwarder{cfg: cfg}
}

// Handle implements [tunnel.SessionHandler]. Returns when the session
// is closed or ctx is cancelled. AcceptStream doesn't take a context,
// so a watcher goroutine closes the session on ctx.Done — closing the
// session is what unblocks AcceptStream and lets Handle return.
// In-flight streams are torn down by the same close.
func (f *Forwarder) Handle(ctx context.Context, session *yamux.Session) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-stopWatch:
		}
	}()
	defer close(stopWatch)

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			// Session-level error — usually means the session is
			// closing. Surface ctx errors verbatim; other errors are
			// logged and bubbled so the dialer can reconnect.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, yamux.ErrSessionShutdown) || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("accept stream: %w", err)
		}

		wg.Add(1)
		go func(s *yamux.Stream) {
			defer wg.Done()
			f.serveStream(ctx, s)
		}(stream)
	}
}

// serveStream dials the local sshd and pipes bytes both ways until
// either side closes. Failures dialing the local sshd close only the
// stream; subsequent streams keep flowing.
func (f *Forwarder) serveStream(ctx context.Context, stream *yamux.Stream) {
	streamID := stream.StreamID()
	defer func() { _ = stream.Close() }()

	dialCtx, cancel := context.WithTimeout(ctx, f.cfg.DialTimeout)
	local, err := f.cfg.Dialer(dialCtx, f.cfg.LocalAddr)
	cancel()
	if err != nil {
		f.cfg.Log.Warn("dial local sshd failed",
			"stream_id", streamID, "addr", f.cfg.LocalAddr, "err", err)
		return
	}
	defer func() { _ = local.Close() }()

	pipe(ctx, stream, local, f.cfg.Log)
}

// pipe copies bytes between the yamux stream and the local TCP conn
// in both directions, returning when either side closes. Whichever
// direction finishes first triggers a full close on both ends —
// yamux.Stream has no half-close primitive, and SSH wraps these
// bytes itself anyway, so peer-side EOF is handled at the SSH layer.
func pipe(ctx context.Context, stream *yamux.Stream, local net.Conn, log *slog.Logger) {
	closeBoth := sync.OnceFunc(func() {
		_ = stream.Close()
		_ = local.Close()
	})

	var wg sync.WaitGroup
	wg.Add(2)

	// stream → local
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err != nil && ctx.Err() == nil && !isExpectedCopyErr(err) {
			log.Debug("copy stream→local", "err", err, "stream_id", stream.StreamID())
		}
		closeBoth()
	}()

	// local → stream
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err != nil && ctx.Err() == nil && !isExpectedCopyErr(err) {
			log.Debug("copy local→stream", "err", err, "stream_id", stream.StreamID())
		}
		closeBoth()
	}()

	// If ctx cancels mid-flight, slam both sides shut so the io.Copy
	// goroutines unblock instead of waiting on stuck reads.
	doneCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-doneCh:
		}
	}()

	wg.Wait()
	close(doneCh)
}

// isExpectedCopyErr filters errors that are part of normal stream
// teardown — peer hangup, session shutdown, deadline. Keeps the log
// quiet during sshd restart / proxy disconnect.
func isExpectedCopyErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, yamux.ErrStreamClosed) ||
		errors.Is(err, yamux.ErrSessionShutdown) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}
