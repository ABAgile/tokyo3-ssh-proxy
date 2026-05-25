package rbac_test

import (
	"net"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/rbac"
)

// remote returns a stub net.Addr resolving to the requested IPv4
// address, useful for SourceAddressOK benchmarks where each call
// needs a distinct origin.
type remote struct{ ip string }

func (r remote) Network() string { return "tcp" }
func (r remote) String() string  { return r.ip + ":54321" }

// BenchmarkPermitsPTY exercises the extension-lookup hot path that
// runs once per session.opened plus once per pty-req. CertEnforcer
// is constructed from a Permissions whose Extensions map mirrors
// what gossh.CertChecker writes.
func BenchmarkPermitsPTY(b *testing.B) {
	enforcer := rbac.New(&gossh.Permissions{
		Extensions: map[string]string{
			"permit-pty":              "",
			"permit-port-forwarding":  "",
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-user-rc":          "",
		},
	})
	b.ReportAllocs()
	for b.Loop() {
		_ = enforcer.PermitsPTY()
	}
}

// BenchmarkSourceAddressOK_NoRestriction covers the fast path where
// the cert carries no source-address critical option. Runs once per
// handshake.
func BenchmarkSourceAddressOK_NoRestriction(b *testing.B) {
	enforcer := rbac.New(&gossh.Permissions{
		CriticalOptions: map[string]string{},
	})
	addr := remote{ip: "10.0.0.42"}
	b.ReportAllocs()
	for b.Loop() {
		_ = enforcer.SourceAddressOK(addr)
	}
}

// BenchmarkSourceAddressOK_CIDRMatch covers the realistic path: a
// cert with one or two CIDR restrictions and an inbound address
// that matches the first entry. This is what 99% of production
// handshakes hit.
func BenchmarkSourceAddressOK_CIDRMatch(b *testing.B) {
	enforcer := rbac.New(&gossh.Permissions{
		CriticalOptions: map[string]string{
			"source-address": "10.0.0.0/8,192.168.0.0/16",
		},
	})
	addr := remote{ip: "10.0.0.42"}
	b.ReportAllocs()
	for b.Loop() {
		_ = enforcer.SourceAddressOK(addr)
	}
}

// BenchmarkSourceAddressOK_LastRange exercises the worst-case
// in-range match: the cert lists five CIDRs and the address only
// matches the fifth. Bounds the cost of badly-ordered restriction
// lists.
func BenchmarkSourceAddressOK_LastRange(b *testing.B) {
	enforcer := rbac.New(&gossh.Permissions{
		CriticalOptions: map[string]string{
			"source-address": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,203.0.113.0/24",
		},
	})
	addr := remote{ip: "203.0.113.7"}
	b.ReportAllocs()
	for b.Loop() {
		_ = enforcer.SourceAddressOK(addr)
	}
}

// Compile-time check: remote satisfies net.Addr.
var _ net.Addr = remote{}
