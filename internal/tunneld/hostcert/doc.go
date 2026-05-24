// Package hostcert renews the SSH host certificate from certd over mTLS,
// writes it atomically to /etc/ssh/ssh_host_*-cert.pub (or the
// configured path), and signals sshd via SIGHUP to pick up the new
// cert. Uses the host's existing workload mTLS identity for the call
// to certd.
package hostcert
