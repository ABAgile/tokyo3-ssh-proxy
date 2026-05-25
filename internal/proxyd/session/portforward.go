package session

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
)

// directTCPIPRequest is the [extra-data] payload for a direct-tcpip
// channel — RFC 4254 §7.2 wire format ("string remote_host, uint32
// remote_port, string origin_host, uint32 origin_port"), which
// golang.org/x/crypto/ssh's [gossh.Unmarshal] decodes into struct
// fields with this exact ordering.
type directTCPIPRequest struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

// parseDirectTCPIPRequest decodes the channel's ExtraData. Returns
// an error when the payload is malformed; callers in the proxy log
// the error and continue (the channel itself is still proxied —
// audit attribution is best-effort, not load-bearing).
func parseDirectTCPIPRequest(extra []byte) (directTCPIPRequest, error) {
	var req directTCPIPRequest
	if err := gossh.Unmarshal(extra, &req); err != nil {
		return directTCPIPRequest{}, fmt.Errorf("decode direct-tcpip extra-data: %w", err)
	}
	return req, nil
}

// countingChannel wraps a [gossh.Channel] and tallies bytes flowing
// in each direction. Reads and writes pass through unchanged; the
// counters are read at channel close time to populate the
// port_forward.closed audit event.
//
// Safe for concurrent calls — the underlying Channel already is,
// and the counters are atomic.
type countingChannel struct {
	gossh.Channel
	bytesRead    int64 // bytes the proxy read from this channel
	bytesWritten int64 // bytes the proxy wrote to this channel
}

// Read satisfies [io.Reader] on the wrapped channel and updates the
// byte counter atomically.
func (c *countingChannel) Read(p []byte) (int, error) {
	n, err := c.Channel.Read(p)
	if n > 0 {
		atomic.AddInt64(&c.bytesRead, int64(n))
	}
	return n, err
}

// Write satisfies [io.Writer] on the wrapped channel and updates the
// byte counter atomically.
func (c *countingChannel) Write(p []byte) (int, error) {
	n, err := c.Channel.Write(p)
	if n > 0 {
		atomic.AddInt64(&c.bytesWritten, int64(n))
	}
	return n, err
}

// portForwardAuditor groups the audit attribution + emit logic for
// one direct-tcpip channel's lifecycle. Constructed in
// [Proxier.handleChannel] before the channel is accepted; Open emits
// ssh.port_forward.opened, Close emits ssh.port_forward.closed.
type portForwardAuditor struct {
	sink       audit.Sink
	log        slogLogger
	sessionID  string
	attr       recordingAuditAttr
	req        directTCPIPRequest
	openedAt   time.Time
	emitOpened bool // skip Close emission when Open didn't fire
}

// slogLogger is the subset of [*slog.Logger] this file uses. Defined
// here so the audit emit path doesn't take an import dependency on
// the rest of the proxy logger plumbing.
type slogLogger interface {
	Warn(msg string, args ...any)
}

// Open emits ssh.port_forward.opened. nil sink short-circuits to a
// no-op so the call site doesn't need to nil-check.
func (a *portForwardAuditor) Open(ctx context.Context) {
	if a == nil || a.sink == nil {
		return
	}
	a.openedAt = time.Now().UTC()
	a.emitOpened = true
	md, _ := json.Marshal(map[string]any{
		"src_host": a.req.OriginHost,
		"src_port": a.req.OriginPort,
		"dst_host": a.req.DestHost,
		"dst_port": a.req.DestPort,
	})
	entry := audit.Entry{
		ID:         uuid.NewString(),
		Action:     audit.ActionPortForwardOpened,
		SessionID:  a.sessionID,
		User:       a.attr.RemoteUser,
		Principals: a.attr.Principals,
		Target:     fmt.Sprintf("%s:%d", a.req.DestHost, a.req.DestPort),
		RemoteUser: a.attr.RemoteUser,
		ClientIP:   a.attr.ClientIP,
		Metadata:   string(md),
		OccurredAt: a.openedAt,
	}
	if err := a.sink.Append(ctx, entry); err != nil {
		a.log.Warn("audit port_forward.opened append failed", "session_id", a.sessionID, "err", err)
	}
}

// Close emits ssh.port_forward.closed with byte counts + duration.
// Skipped when Open never fired (RBAC denial, target reject, etc.) —
// avoids "closed before opened" pairs in the audit stream.
func (a *portForwardAuditor) Close(ctx context.Context, bytesIn, bytesOut int64) {
	if a == nil || a.sink == nil || !a.emitOpened {
		return
	}
	closedAt := time.Now().UTC()
	md, _ := json.Marshal(map[string]any{
		"src_host":         a.req.OriginHost,
		"src_port":         a.req.OriginPort,
		"dst_host":         a.req.DestHost,
		"dst_port":         a.req.DestPort,
		"bytes_in":         bytesIn,
		"bytes_out":        bytesOut,
		"duration_seconds": round6(closedAt.Sub(a.openedAt).Seconds()),
	})
	entry := audit.Entry{
		ID:         uuid.NewString(),
		Action:     audit.ActionPortForwardClosed,
		SessionID:  a.sessionID,
		User:       a.attr.RemoteUser,
		Principals: a.attr.Principals,
		Target:     fmt.Sprintf("%s:%d", a.req.DestHost, a.req.DestPort),
		RemoteUser: a.attr.RemoteUser,
		ClientIP:   a.attr.ClientIP,
		Metadata:   string(md),
		OccurredAt: closedAt,
	}
	if err := a.sink.Append(ctx, entry); err != nil {
		a.log.Warn("audit port_forward.closed append failed", "session_id", a.sessionID, "err", err)
	}
}

// io.ReadWriter assertion so future refactors that swap the
// underlying Channel for something narrower break here, where the
// audit-byte counters are.
var _ io.ReadWriter = (*countingChannel)(nil)
