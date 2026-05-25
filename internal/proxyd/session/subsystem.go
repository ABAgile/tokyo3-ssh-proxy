package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
)

// subsystemKind labels what kind of file-transfer-or-similar
// activity the user kicked off on a session channel. "scp" is
// detected via the "exec" request payload prefix; "sftp" via the
// "subsystem" request with name "sftp". Other exec / subsystem
// activity is not surfaced here — only the file-transfer set, which
// is what compliance teams ask about.
type subsystemKind string

const (
	subsystemSCP  subsystemKind = "scp"
	subsystemSFTP subsystemKind = "sftp"
)

// detectSubsystem inspects an SSH channel request and returns the
// file-transfer kind plus the command tail (for scp). When the
// request isn't a file-transfer kickoff, returns ("", "", false).
//
// The exec payload format is RFC 4254 §6.5: "string command". We
// decode the length-prefixed string and look for an scp prefix.
// scp's command line is typically "scp -t /tmp/foo" (receive into)
// or "scp -f /tmp/foo" (read from) — both start with "scp ", so a
// simple prefix check suffices and avoids tokenization edge cases.
func detectSubsystem(req *gossh.Request) (kind subsystemKind, command string, ok bool) {
	switch req.Type {
	case "exec":
		var p struct{ Command string }
		if err := gossh.Unmarshal(req.Payload, &p); err != nil {
			return "", "", false
		}
		cmd := strings.TrimSpace(p.Command)
		if strings.HasPrefix(cmd, "scp ") || cmd == "scp" || strings.HasPrefix(cmd, "scp\t") {
			return subsystemSCP, cmd, true
		}
		return "", "", false
	case "subsystem":
		var p struct{ Name string }
		if err := gossh.Unmarshal(req.Payload, &p); err != nil {
			return "", "", false
		}
		if p.Name == "sftp" {
			return subsystemSFTP, "", true
		}
		return "", "", false
	}
	return "", "", false
}

// emitSubsystemOpened publishes one ssh.subsystem.opened audit
// event. Best-effort: failures are logged but never block the
// underlying SSH request flow.
func emitSubsystemOpened(ctx context.Context, sink audit.Sink, sessionID string, attr recordingAuditAttr, kind subsystemKind, command string, log slogLogger) {
	if sink == nil {
		return
	}
	mdMap := map[string]any{
		"kind": string(kind),
	}
	if command != "" {
		mdMap["command"] = command
	}
	md, _ := json.Marshal(mdMap)
	entry := audit.Entry{
		ID:         uuid.NewString(),
		Action:     audit.ActionSubsystemOpened,
		SessionID:  sessionID,
		User:       attr.RemoteUser,
		Principals: attr.Principals,
		Target:     attr.Target,
		RemoteUser: attr.RemoteUser,
		ClientIP:   attr.ClientIP,
		Metadata:   string(md),
		OccurredAt: time.Now().UTC(),
	}
	if err := sink.Append(ctx, entry); err != nil {
		log.Warn(fmt.Sprintf("audit %s append failed", audit.ActionSubsystemOpened),
			"session_id", sessionID, "kind", kind, "err", err)
	}
}
