package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/rbac"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
)

// Proxier bridges a user-side SSH connection to a target-side SSH
// client connection. New inbound channels open a matching outbound
// channel on the target; data + requests flow bidirectionally.
// Cert-driven RBAC gates filter the channel and request types the
// user is allowed to use, and PTY traffic is tee'd into an
// asciinema cast for audit + replay.
type Proxier struct {
	target      *gossh.Client
	rbac        *rbac.CertEnforcer
	sink        recording.Sink // nil disables recording
	user        string         // cert KeyID, for cast metadata
	host        string         // target host, for cast metadata
	auditSink   audit.Sink     // for recording.completed events
	sessionID   string         // matches the SSH server's session ID
	sessionAttr recordingAuditAttr
	log         *slog.Logger
}

// Config bundles the optional knobs for [NewProxier]. Required:
// Target. Sink + User + Host enable session recording; leaving Sink
// nil disables it. Audit + SessionID + AuditAttr enable
// recording.completed audit emission tied back to the SSH server's
// session lifecycle.
type Config struct {
	Target    *gossh.Client
	Enforcer  *rbac.CertEnforcer
	Sink      recording.Sink
	User      string
	Host      string
	Audit     audit.Sink
	SessionID string
	// AuditAttr carries the optional attribution fields recorded on
	// the recording.completed event. Empty values produce a
	// less-attributable Entry; non-empty values mirror what the
	// SSH server's session.opened event emitted.
	AuditAttr RecordingAuditAttr
	Log       *slog.Logger
}

// RecordingAuditAttr is the public alias for the internal attribution
// struct so the SSH server can populate fields by name.
type RecordingAuditAttr struct {
	Principals string
	Target     string
	RemoteUser string
	ClientIP   string
}

// NewProxier wraps cfg into a [Proxier]. A nil Enforcer is treated as
// fully permissive — useful in tests; the production server always
// passes a real one.
func NewProxier(cfg Config) *Proxier {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	enforcer := cfg.Enforcer
	if enforcer == nil {
		// Build a permissive enforcer to avoid nil dereferences. The
		// rbac.New(nil) path defaults *all* permit-* to false, so we
		// pass a populated Permissions to opt into the default-allow
		// path that the request handlers check below.
		enforcer = rbac.New(permissivePerms())
	}
	return &Proxier{
		target:    cfg.Target,
		rbac:      enforcer,
		sink:      cfg.Sink,
		user:      cfg.User,
		host:      cfg.Host,
		auditSink: cfg.Audit,
		sessionID: cfg.SessionID,
		sessionAttr: recordingAuditAttr{
			Principals: cfg.AuditAttr.Principals,
			Target:     cfg.AuditAttr.Target,
			RemoteUser: cfg.AuditAttr.RemoteUser,
			ClientIP:   cfg.AuditAttr.ClientIP,
		},
		log: log,
	}
}

// HandleNewChannels iterates over the inbound channels chan from the
// user-side [gossh.ServerConn] until it closes (peer disconnect or
// server shutdown). Each channel is proxied on its own goroutine.
func (p *Proxier) HandleNewChannels(chans <-chan gossh.NewChannel) {
	var wg sync.WaitGroup
	for newCh := range chans {
		wg.Add(1)
		go func(nc gossh.NewChannel) {
			defer wg.Done()
			p.handleChannel(nc)
		}(newCh)
	}
	wg.Wait()
}

// handleChannel proxies a single inbound channel to the target.
func (p *Proxier) handleChannel(newCh gossh.NewChannel) {
	// Per-channel-type RBAC gates. The set is small for now;
	// follow-on slices add tcpip-forward (remote -R), session-level
	// x11-req / auth-agent-req, and force-command substitution.
	var pfAuditor *portForwardAuditor
	switch newCh.ChannelType() {
	case "direct-tcpip":
		if !p.rbac.PermitsPortForwarding() {
			_ = newCh.Reject(gossh.Prohibited, "port forwarding not permitted by cert")
			return
		}
		// Decode the extra-data so we can emit a structured audit
		// event when the channel opens. Decode failures are
		// non-fatal — log and continue without auditing this
		// channel, rather than blocking a valid forward request.
		req, err := parseDirectTCPIPRequest(newCh.ExtraData())
		if err != nil {
			p.log.Warn("direct-tcpip extra-data decode failed; audit attribution will be empty",
				"session_id", p.sessionID, "err", err)
		} else {
			pfAuditor = &portForwardAuditor{
				sink:      p.auditSink,
				log:       p.log,
				sessionID: p.sessionID,
				attr:      p.sessionAttr,
				req:       req,
			}
		}
	}

	// Open the matching channel on the target before accepting the
	// inbound — if the target rejects we propagate the precise
	// rejection reason back to the user.
	targetCh, targetReqs, err := p.target.OpenChannel(newCh.ChannelType(), newCh.ExtraData())
	if err != nil {
		reason, msg := openChannelRejection(err)
		_ = newCh.Reject(reason, msg)
		return
	}

	srcCh, srcReqs, err := newCh.Accept()
	if err != nil {
		p.log.Debug("accept inbound channel failed", "err", err)
		_ = targetCh.Close()
		return
	}

	// Only "session" channels are recorded. direct-tcpip and the
	// like are pure transport — no PTY data to capture.
	var rec *channelRecorder
	if newCh.ChannelType() == "session" && p.sink != nil {
		rec = newChannelRecorder(p.sink, p.sessionID, p.user, p.host, p.sessionAttr, p.auditSink, p.log)
		defer rec.Close()
	}

	// Port-forward audit: wrap the user-side channel with byte
	// counters and emit opened/closed events around the pipe.
	// closeBoth in pipeChannel runs even when Close errors out, so
	// the deferred emission is guaranteed. The closure-form defer
	// is essential — direct args are evaluated at defer-registration
	// time (still zero), only a closure samples the counters after
	// pipeChannel returns.
	var pfCh *countingChannel
	if pfAuditor != nil {
		pfCh = &countingChannel{Channel: srcCh}
		srcCh = pfCh
		pfAuditor.Open(context.Background())
		defer func() {
			pfAuditor.Close(context.Background(),
				atomic.LoadInt64(&pfCh.bytesRead),
				atomic.LoadInt64(&pfCh.bytesWritten))
		}()
	}

	p.pipeChannel(srcCh, srcReqs, targetCh, targetReqs, rec)
}

// pipeChannel ferries bytes + requests between an accepted inbound
// channel and the matching outbound channel. Each direction (user →
// target, target → user) groups its data copy and its request stream;
// one direction finishing triggers a close on both channels, which
// unblocks the other direction's reads.
//
// The grouping is important: it guarantees exit-status (a request
// from the target) is forwarded BEFORE the user-side channel is
// closed, so sess.Wait() on the client doesn't return "exited
// without exit status."
//
// When rec is non-nil, target→user data is tee'd into the asciinema
// recorder and pty-req / window-change requests are forwarded into
// the recorder's Resize hook. nil rec disables recording for this
// channel.
func (p *Proxier) pipeChannel(srcCh gossh.Channel, srcReqs <-chan *gossh.Request, targetCh gossh.Channel, targetReqs <-chan *gossh.Request, rec *channelRecorder) {
	// closeBoth tears down both channels. Used as the trigger after
	// either side has fully drained its data + requests.
	closeBoth := sync.OnceFunc(func() {
		_ = srcCh.Close()
		_ = targetCh.Close()
	})

	var wg sync.WaitGroup
	wg.Add(4)

	// target → user: drain data and requests together, then close.
	// This is the path that delivers exit-status to the user. Data
	// is tee'd into the recorder when one is configured.
	go func() {
		defer wg.Done()
		var inner sync.WaitGroup
		inner.Add(2)
		go func() {
			defer inner.Done()
			dst := io.Writer(srcCh)
			if rec != nil {
				dst = &recordingTee{w: srcCh, rec: rec}
			}
			_, _ = io.Copy(dst, targetCh)
		}()
		go func() {
			defer inner.Done()
			pipeRequestsVerbatim(targetReqs, srcCh)
		}()
		inner.Wait()
		closeBoth()
	}()

	// user → target: drain data and user requests together. Closes
	// both when the user finishes (e.g., disconnects). The user-side
	// request stream is where we observe pty-req + window-change for
	// the recorder.
	go func() {
		defer wg.Done()
		var inner sync.WaitGroup
		inner.Add(2)
		go func() {
			defer inner.Done()
			_, _ = io.Copy(targetCh, srcCh)
		}()
		go func() {
			defer inner.Done()
			p.pipeUserRequests(srcReqs, targetCh, rec)
		}()
		inner.Wait()
		closeBoth()
	}()

	// stderr both ways. No request-ordering concerns here — once
	// the underlying channels close, the Stderr Readers return EOF
	// naturally.
	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetCh.Stderr(), srcCh.Stderr())
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(srcCh.Stderr(), targetCh.Stderr())
	}()

	wg.Wait()
}

// pipeUserRequests forwards channel requests from the user to the
// target, applying RBAC gates. Denied requests get a false reply
// (when WantReply) instead of being forwarded. pty-req and
// window-change requests are also peeked at so the recorder can
// learn the terminal dimensions.
func (p *Proxier) pipeUserRequests(src <-chan *gossh.Request, dst gossh.Channel, rec *channelRecorder) {
	for req := range src {
		if !p.permitsRequest(req.Type) {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			p.log.Debug("channel request denied by cert", "type", req.Type)
			continue
		}
		// Peek at terminal-shape requests for recording purposes.
		// Errors here are logged but don't fail the request — audit
		// is observational.
		if rec != nil {
			switch req.Type {
			case "pty-req":
				if width, height, err := parsePTYReq(req.Payload); err != nil {
					p.log.Debug("parse pty-req for recording", "err", err)
				} else if err := rec.StartIfNeeded(width, height); err != nil {
					p.log.Warn("start recording", "err", err)
				}
			case "window-change":
				if width, height, err := parseWindowChange(req.Payload); err != nil {
					p.log.Debug("parse window-change for recording", "err", err)
				} else {
					rec.Resize(width, height)
				}
			}
		}
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			ok = false
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
}

// parsePTYReq decodes the cols + rows from an SSH pty-req payload.
// RFC 4254 6.2: string TERM, uint32 cols, uint32 rows, uint32 width
// pixels, uint32 height pixels, string modes. We only need cols + rows.
//
// Some clients (including OpenSSH's `ssh -tt` from a non-TTY shell)
// send zero dimensions when they can't query the local terminal. We
// fall back to a sensible 80x24 default rather than refuse to record
// the session — the asciinema-player can still replay either way.
func parsePTYReq(payload []byte) (width, height int, err error) {
	var p struct {
		Term         string
		Cols         uint32
		Rows         uint32
		WidthPixels  uint32
		HeightPixels uint32
		Modes        string
	}
	if err := gossh.Unmarshal(payload, &p); err != nil {
		return 0, 0, fmt.Errorf("unmarshal pty-req: %w", err)
	}
	cols, rows := int(p.Cols), int(p.Rows)
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	return cols, rows, nil
}

// parseWindowChange decodes the cols + rows from a window-change
// payload. RFC 4254 6.7: uint32 cols, uint32 rows, uint32 width
// pixels, uint32 height pixels. Avoid gossh.Unmarshal for fixed-size
// payloads — it's just 16 bytes.
func parseWindowChange(payload []byte) (width, height int, err error) {
	if len(payload) < 8 {
		return 0, 0, fmt.Errorf("window-change payload too short: %d bytes", len(payload))
	}
	cols := binary.BigEndian.Uint32(payload[0:4])
	rows := binary.BigEndian.Uint32(payload[4:8])
	if cols == 0 || rows == 0 {
		return 0, 0, fmt.Errorf("window-change has zero dimensions %dx%d", cols, rows)
	}
	return int(cols), int(rows), nil
}

// pipeRequestsVerbatim forwards target-side requests (e.g.,
// exit-status, exit-signal, keepalive) back to the user without
// filtering — the target is trusted to speak truth about the
// session's outcome.
func pipeRequestsVerbatim(src <-chan *gossh.Request, dst gossh.Channel) {
	for req := range src {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			ok = false
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
}

// permitsRequest applies the cert-driven gates for channel-request
// types. Default-allow for unknown types — gates only narrow access.
func (p *Proxier) permitsRequest(reqType string) bool {
	switch reqType {
	case "pty-req":
		return p.rbac.PermitsPTY()
	case "x11-req":
		return p.rbac.PermitsX11Forwarding()
	case "auth-agent-req@openssh.com":
		return p.rbac.PermitsAgentForwarding()
	}
	return true
}

// openChannelRejection unpacks a target-side OpenChannel error into
// the precise (reason, message) tuple the user-side channel reject
// requires. Generic errors become ConnectionFailed.
func openChannelRejection(err error) (gossh.RejectionReason, string) {
	var oce *gossh.OpenChannelError
	if errors.As(err, &oce) {
		return oce.Reason, oce.Message
	}
	return gossh.ConnectionFailed, err.Error()
}

// permissivePerms returns a Permissions with all permit-* extensions
// set; used when [NewProxier] is called with a nil enforcer.
func permissivePerms() *gossh.Permissions {
	return &gossh.Permissions{
		Extensions: map[string]string{
			"permit-pty":              "",
			"permit-port-forwarding":  "",
			"permit-agent-forwarding": "",
			"permit-X11-forwarding":   "",
			"permit-user-rc":          "",
		},
	}
}
