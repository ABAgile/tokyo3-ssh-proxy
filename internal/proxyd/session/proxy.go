package session

import (
	"errors"
	"io"
	"log/slog"
	"sync"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/rbac"
)

// Proxier bridges a user-side SSH connection to a target-side SSH
// client connection. New inbound channels open a matching outbound
// channel on the target; data + requests flow bidirectionally.
// Cert-driven RBAC gates filter the channel and request types the
// user is allowed to use.
type Proxier struct {
	target *gossh.Client
	rbac   *rbac.CertEnforcer
	log    *slog.Logger
}

// NewProxier wraps target + cert claims into a [Proxier]. A nil
// enforcer is treated as fully permissive — useful in tests; the
// production server always passes a real one.
func NewProxier(target *gossh.Client, enforcer *rbac.CertEnforcer, log *slog.Logger) *Proxier {
	if log == nil {
		log = slog.Default()
	}
	if enforcer == nil {
		// Build a permissive enforcer to avoid nil dereferences. The
		// rbac.New(nil) path defaults *all* permit-* to false, so we
		// pass a populated Permissions to opt into the default-allow
		// path that the request handlers check below.
		enforcer = rbac.New(permissivePerms())
	}
	return &Proxier{target: target, rbac: enforcer, log: log}
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
	switch newCh.ChannelType() {
	case "direct-tcpip":
		if !p.rbac.PermitsPortForwarding() {
			_ = newCh.Reject(gossh.Prohibited, "port forwarding not permitted by cert")
			return
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

	p.pipeChannel(srcCh, srcReqs, targetCh, targetReqs)
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
func (p *Proxier) pipeChannel(srcCh gossh.Channel, srcReqs <-chan *gossh.Request, targetCh gossh.Channel, targetReqs <-chan *gossh.Request) {
	// closeBoth tears down both channels. Used as the trigger after
	// either side has fully drained its data + requests.
	closeBoth := sync.OnceFunc(func() {
		_ = srcCh.Close()
		_ = targetCh.Close()
	})

	var wg sync.WaitGroup
	wg.Add(4)

	// target → user: drain data and requests together, then close.
	// This is the path that delivers exit-status to the user.
	go func() {
		defer wg.Done()
		var inner sync.WaitGroup
		inner.Add(2)
		go func() {
			defer inner.Done()
			_, _ = io.Copy(srcCh, targetCh)
		}()
		go func() {
			defer inner.Done()
			pipeRequestsVerbatim(targetReqs, srcCh)
		}()
		inner.Wait()
		closeBoth()
	}()

	// user → target: drain data and user requests together. Closes
	// both when the user finishes (e.g., disconnects).
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
			p.pipeUserRequests(srcReqs, targetCh)
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
// (when WantReply) instead of being forwarded.
func (p *Proxier) pipeUserRequests(src <-chan *gossh.Request, dst gossh.Channel) {
	for req := range src {
		if !p.permitsRequest(req.Type) {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			p.log.Debug("channel request denied by cert", "type", req.Type)
			continue
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
