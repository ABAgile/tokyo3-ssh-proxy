package rbac_test

import (
	"net"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/rbac"
)

// permsWith builds a *ssh.Permissions whose Extensions and
// CriticalOptions are the given maps. Lets tests pose exact cert
// claims without round-tripping through a real Certificate.
func permsWith(ext, crit map[string]string) *gossh.Permissions {
	return &gossh.Permissions{Extensions: ext, CriticalOptions: crit}
}

// ── extension permits ────────────────────────────────────────────────────────

func TestPermitsExtensions(t *testing.T) {
	tests := []struct {
		name  string
		ext   map[string]string
		check func(*rbac.CertEnforcer) bool
		want  bool
	}{
		{"pty present", map[string]string{"permit-pty": ""}, (*rbac.CertEnforcer).PermitsPTY, true},
		{"pty absent", nil, (*rbac.CertEnforcer).PermitsPTY, false},
		{"port-forwarding present", map[string]string{"permit-port-forwarding": ""}, (*rbac.CertEnforcer).PermitsPortForwarding, true},
		{"port-forwarding absent", map[string]string{"permit-pty": ""}, (*rbac.CertEnforcer).PermitsPortForwarding, false},
		{"agent-forwarding present", map[string]string{"permit-agent-forwarding": ""}, (*rbac.CertEnforcer).PermitsAgentForwarding, true},
		{"agent-forwarding absent", nil, (*rbac.CertEnforcer).PermitsAgentForwarding, false},
		{"x11 present", map[string]string{"permit-X11-forwarding": ""}, (*rbac.CertEnforcer).PermitsX11Forwarding, true},
		{"x11 absent", nil, (*rbac.CertEnforcer).PermitsX11Forwarding, false},
		{"user-rc present", map[string]string{"permit-user-rc": ""}, (*rbac.CertEnforcer).PermitsUserRC, true},
		{"user-rc absent", nil, (*rbac.CertEnforcer).PermitsUserRC, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := rbac.New(permsWith(tc.ext, nil))
			if got := tc.check(e); got != tc.want {
				t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestPermits_NilPermsAlwaysDenies(t *testing.T) {
	e := rbac.New(nil)
	if e.PermitsPTY() || e.PermitsPortForwarding() || e.PermitsAgentForwarding() ||
		e.PermitsX11Forwarding() || e.PermitsUserRC() {
		t.Error("nil perms should default-deny every permit-*")
	}
}

func TestPermits_NilEnforcer_AlsoSafe(t *testing.T) {
	// A nil CertEnforcer is rare but trivially safe — callers that
	// chain through optional values shouldn't panic.
	var e *rbac.CertEnforcer
	if e.PermitsPTY() || e.PermitsPortForwarding() {
		t.Error("nil enforcer should default-deny")
	}
}

// ── force-command ────────────────────────────────────────────────────────────

func TestForceCommand_PresentReturnsValue(t *testing.T) {
	e := rbac.New(permsWith(nil, map[string]string{"force-command": "/usr/bin/backup --read-only"}))
	if got := e.ForceCommand(); got != "/usr/bin/backup --read-only" {
		t.Errorf("ForceCommand = %q", got)
	}
}

func TestForceCommand_AbsentReturnsEmpty(t *testing.T) {
	e := rbac.New(permsWith(nil, nil))
	if got := e.ForceCommand(); got != "" {
		t.Errorf("ForceCommand = %q, want empty", got)
	}
}

// ── source-address ──────────────────────────────────────────────────────────

func TestSourceAddressOK_DefaultAllowsWhenUnset(t *testing.T) {
	e := rbac.New(permsWith(nil, nil))
	if !e.SourceAddressOK(&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345}) {
		t.Error("no source-address option should default-allow")
	}
}

func TestSourceAddressOK_SingleIPMatch(t *testing.T) {
	e := rbac.New(permsWith(nil, map[string]string{"source-address": "203.0.113.7"}))
	cases := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{"matching IP", &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345}, true},
		{"different IP", &net.TCPAddr{IP: net.ParseIP("203.0.113.8"), Port: 12345}, false},
		{"unrelated subnet", &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.SourceAddressOK(tc.addr); got != tc.want {
				t.Errorf("SourceAddressOK(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestSourceAddressOK_CIDRMatch(t *testing.T) {
	e := rbac.New(permsWith(nil, map[string]string{"source-address": "10.0.0.0/8"}))
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"inside /8", "10.42.0.1", true},
		{"boundary", "10.0.0.0", true},
		{"outside /8", "11.0.0.1", false},
		{"public", "203.0.113.7", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 22}
			if got := e.SourceAddressOK(addr); got != tc.want {
				t.Errorf("SourceAddressOK(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestSourceAddressOK_MultipleEntries(t *testing.T) {
	e := rbac.New(permsWith(nil, map[string]string{
		"source-address": "10.0.0.0/8, 203.0.113.7, 192.168.1.0/24",
	}))
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.42.0.1", true},     // /8
		{"203.0.113.7", true},   // exact
		{"192.168.1.100", true}, // /24
		{"172.16.0.1", false},   // none
		{"203.0.113.8", false},  // adjacent to exact
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			addr := &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 22}
			if got := e.SourceAddressOK(addr); got != tc.want {
				t.Errorf("SourceAddressOK(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestSourceAddressOK_IPv6(t *testing.T) {
	e := rbac.New(permsWith(nil, map[string]string{
		"source-address": "2001:db8::/32",
	}))
	cases := []struct {
		ip   string
		want bool
	}{
		{"2001:db8::1", true},
		{"2001:db8:1:2:3:4:5:6", true},
		{"2001:db9::1", false}, // outside /32
		{"fe80::1", false},     // link-local
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			addr := &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 22}
			if got := e.SourceAddressOK(addr); got != tc.want {
				t.Errorf("SourceAddressOK(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestSourceAddressOK_RejectsMalformedAddrWhenOptionSet(t *testing.T) {
	// When source-address is set, an unparseable remote is denied
	// (we can't prove it's allowed). When the option is absent the
	// remote address doesn't matter, but we still want a sane no-panic.
	e := rbac.New(permsWith(nil, map[string]string{"source-address": "10.0.0.0/8"}))
	if e.SourceAddressOK(&badAddr{}) {
		t.Error("malformed remote should be denied when source-address is set")
	}
	e2 := rbac.New(permsWith(nil, nil))
	if !e2.SourceAddressOK(&badAddr{}) {
		t.Error("malformed remote with no source-address option should still default-allow")
	}
}

// badAddr is a net.Addr whose String() can't be parsed as an IP.
type badAddr struct{}

func (*badAddr) Network() string { return "stub" }
func (*badAddr) String() string  { return "not-an-ip" }

func TestSourceAddressOK_BareNetIPAddr(t *testing.T) {
	// *net.IPAddr (used by some net package helpers) should work
	// alongside *net.TCPAddr / *net.UDPAddr.
	e := rbac.New(permsWith(nil, map[string]string{"source-address": "10.0.0.0/8"}))
	if !e.SourceAddressOK(&net.IPAddr{IP: net.ParseIP("10.1.2.3")}) {
		t.Error("IPAddr inside CIDR should match")
	}
}

func TestSourceAddressOK_MalformedCIDREntryIsIgnored(t *testing.T) {
	// An invalid CIDR entry shouldn't crash; if no other entry
	// matches, the address is denied.
	e := rbac.New(permsWith(nil, map[string]string{
		"source-address": "garbage, 10.0.0.0/8",
	}))
	if !e.SourceAddressOK(&net.TCPAddr{IP: net.ParseIP("10.1.2.3")}) {
		t.Error("valid entry after a malformed one should still match")
	}
	if e.SourceAddressOK(&net.TCPAddr{IP: net.ParseIP("203.0.113.7")}) {
		t.Error("address matching only the malformed entry should be denied")
	}
}

func TestSourceAddressOK_EmptyValueDefaultAllows(t *testing.T) {
	// An empty source-address value (rather than missing key) should
	// be treated the same as unset — default-allow.
	e := rbac.New(permsWith(nil, map[string]string{"source-address": ""}))
	if !e.SourceAddressOK(&net.TCPAddr{IP: net.ParseIP("10.0.0.1")}) {
		t.Error("empty source-address should default-allow")
	}
}
