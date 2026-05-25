// Package rbac enforces what the user certificate says — the
// allowed-principals list, the SSH cert extensions (permit-pty,
// permit-port-forwarding, etc.), and the critical options
// (source-address, force-command). The proxy itself owns no policy
// database; it consults what the cert carries and refuses requests
// the cert doesn't authorize.
//
// The cert's claims arrive through [gossh.Permissions], populated by
// the SSH server's publicKeyCallback when it accepts the cert. This
// package exposes a small read-only API the session handler invokes
// at request time.
//
// Default-allow vs default-deny:
//
//   - SSH cert extensions (the "permit-*" ones) are default-DENY:
//     absence means the capability is forbidden, exactly as sshd
//     enforces them. PermitsPTY etc. mirror this.
//   - source-address is default-ALLOW: a cert with no source-address
//     option is valid from anywhere. Set the option to lock the cert
//     to specific CIDRs.
//   - force-command is informational here — returning "" means no
//     forced command; the session handler runs whatever the client
//     asked for. A non-empty value must be substituted for the
//     client's command.
package rbac

import (
	"net"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// SSH certificate extension names. The cert grants the bearer each
// capability when the matching extension is present; gossh and OpenSSH
// follow the same conventions (value is conventionally the empty
// string but only presence matters).
const (
	extPermitPTY             = "permit-pty"
	extPermitPortForwarding  = "permit-port-forwarding"
	extPermitAgentForwarding = "permit-agent-forwarding"
	extPermitX11Forwarding   = "permit-X11-forwarding"
	extPermitUserRC          = "permit-user-rc"
)

// SSH certificate critical option names. The cert is rejected at
// validation time if any unknown critical option is present, so
// anything we encounter here is something we explicitly know about.
const (
	optSourceAddress = "source-address"
	optForceCommand  = "force-command"
)

// CertEnforcer wraps the [gossh.Permissions] from an authenticated
// connection and exposes per-capability gates. Safe for concurrent
// reads; the underlying Permissions struct must not be mutated after
// construction.
type CertEnforcer struct {
	perms *gossh.Permissions
}

// New returns a [CertEnforcer] backed by perms. A nil perms is
// permitted — every gate then returns its default (false for
// permit-* extensions, true for SourceAddressOK, "" for ForceCommand).
// The session handler holds the only reference; lifetime tracks the
// SSH connection.
func New(perms *gossh.Permissions) *CertEnforcer {
	return &CertEnforcer{perms: perms}
}

// PermitsPTY reports whether the cert authorises PTY allocation.
func (e *CertEnforcer) PermitsPTY() bool { return e.hasExtension(extPermitPTY) }

// PermitsPortForwarding reports whether the cert authorises -L/-R/-D
// style direct-tcpip forward channels.
func (e *CertEnforcer) PermitsPortForwarding() bool {
	return e.hasExtension(extPermitPortForwarding)
}

// PermitsAgentForwarding reports whether the cert authorises
// ssh-agent forwarding (the auth-agent-req@openssh.com request).
func (e *CertEnforcer) PermitsAgentForwarding() bool {
	return e.hasExtension(extPermitAgentForwarding)
}

// PermitsX11Forwarding reports whether the cert authorises X11
// forwarding (the x11-req request).
func (e *CertEnforcer) PermitsX11Forwarding() bool {
	return e.hasExtension(extPermitX11Forwarding)
}

// PermitsUserRC reports whether the cert authorises execution of the
// user's ~/.ssh/rc file on session start.
func (e *CertEnforcer) PermitsUserRC() bool { return e.hasExtension(extPermitUserRC) }

// ForceCommand returns the value of the force-command critical option
// (the only command the client may run, regardless of what they
// asked for) or "" when unset. Callers that get a non-empty value
// must substitute it for the client's "exec" / "shell" request
// command.
func (e *CertEnforcer) ForceCommand() string {
	if e == nil || e.perms == nil {
		return ""
	}
	return e.perms.CriticalOptions[optForceCommand]
}

// SourceAddressOK reports whether remote is allowed by the
// source-address critical option. When the option is absent (no
// network restriction) the check is default-allow. When the option
// is set, remote must fall within at least one of the
// comma-separated CIDRs or single-IP entries.
//
// remote may be a [*net.TCPAddr], [*net.UDPAddr], or any net.Addr
// whose [net.Addr.String] returns "host:port" or just "host" — the
// IP is extracted up to the last colon (handles IPv6 brackets).
// Returns false if the address can't be parsed.
func (e *CertEnforcer) SourceAddressOK(remote net.Addr) bool {
	if e == nil || e.perms == nil {
		return true
	}
	raw, ok := e.perms.CriticalOptions[optSourceAddress]
	if !ok || raw == "" {
		return true
	}
	ip := remoteIP(remote)
	if ip == nil {
		return false
	}
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if matchAddress(entry, ip) {
			return true
		}
	}
	return false
}

// hasExtension reports whether the named cert extension is present.
// Value is ignored; OpenSSH treats permit-* extensions as set-or-not.
func (e *CertEnforcer) hasExtension(name string) bool {
	if e == nil || e.perms == nil {
		return false
	}
	_, ok := e.perms.Extensions[name]
	return ok
}

// remoteIP extracts the net.IP from a net.Addr. Returns nil if the
// address cannot be parsed.
func remoteIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	case *net.IPAddr:
		return a.IP
	}
	// Generic net.Addr — assume String() is "host:port" or "host".
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(host)
}

// matchAddress reports whether ip matches entry, which is either a
// CIDR ("10.0.0.0/8") or a bare IP ("203.0.113.7"). Bare IPs become
// /32 (IPv4) or /128 (IPv6) implicit CIDRs.
func matchAddress(entry string, ip net.IP) bool {
	if strings.Contains(entry, "/") {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	}
	parsed := net.ParseIP(entry)
	if parsed == nil {
		return false
	}
	return parsed.Equal(ip)
}
