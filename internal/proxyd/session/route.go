// Package session owns the lifecycle of a single SSH session at the
// proxy — parses the target from the SSH username, opens an outbound
// SSH connection to that target, and pipes channels + requests
// between the inbound user-side connection and the outbound
// target-side one. The cert-driven RBAC gates from
// [github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/rbac] are
// invoked at the points the cert authorizes (PTY allocation, port
// forwarding, force-command substitution).
//
// Recording (PTY mirror → asciinema → S3) and per-session cert
// minting against certd live in separate sibling packages that wrap
// the primitives here.
package session

import (
	"errors"
	"strings"
)

// ParseTarget extracts the remote user and target host from an SSH
// username field. The convention is "<user>@<host>"; the user's SSH
// client passes both pieces through the standard username field so
// no custom protocol is needed.
//
// The last "@" wins, mirroring how OpenSSH treats account-style
// usernames containing "@" (e.g., Kerberos principals like
// "alice@CORP.EXAMPLE.COM" with host added: "alice@CORP.EXAMPLE.COM@db-1").
//
// Returns an error when the input is missing the "@" delimiter, has
// an empty user, or has an empty host.
func ParseTarget(sshUser string) (user, host string, err error) {
	at := strings.LastIndex(sshUser, "@")
	if at < 0 {
		return "", "", errors.New(`ssh username must be "<remote-user>@<target-host>" (no "@" found)`)
	}
	user = sshUser[:at]
	host = sshUser[at+1:]
	if user == "" {
		return "", "", errors.New(`ssh username has empty remote-user before "@"`)
	}
	if host == "" {
		return "", "", errors.New(`ssh username has empty target-host after "@"`)
	}
	return user, host, nil
}
