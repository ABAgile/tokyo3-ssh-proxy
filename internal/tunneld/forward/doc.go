// Package forward receives an inbound stream from the tunnel, dials the
// local sshd on 127.0.0.1:22, and pipes bytes between the two. The
// effective SSH session terminates between ssh-proxyd (server side) and
// the host's local sshd (target side); this package is pure transport.
package forward
