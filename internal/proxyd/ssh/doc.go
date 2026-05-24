// Package ssh hosts the SSH server side of ssh-proxyd — the protocol
// terminator that accepts user connections, validates the user cert
// against certd's user CA pubkey, and hands off to package session.
// Built on golang.org/x/crypto/ssh.
package ssh
