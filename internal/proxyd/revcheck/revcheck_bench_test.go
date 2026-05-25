package revcheck

import (
	"strconv"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// BenchmarkIsRevoked_Hit measures the cost of confirming a cert is
// revoked. Runs in the SSH CertChecker.IsRevoked callback once per
// handshake, so even a microsecond bloats login latency at scale.
func BenchmarkIsRevoked_Hit(b *testing.B) {
	p := newWithEntries(1000)
	cert := &gossh.Certificate{Serial: 500}
	b.ReportAllocs()
	for b.Loop() {
		_ = p.IsRevoked(cert)
	}
}

// BenchmarkIsRevoked_Miss is the common path: cert is NOT revoked.
// The miss has to consult both maps before returning false.
func BenchmarkIsRevoked_Miss(b *testing.B) {
	p := newWithEntries(1000)
	cert := &gossh.Certificate{Serial: 99_999_999, KeyId: "user:never-revoked"}
	b.ReportAllocs()
	for b.Loop() {
		_ = p.IsRevoked(cert)
	}
}

// BenchmarkIsRevoked_NilCert covers the defensive nil-check path —
// shouldn't fire in production but worth confirming it stays cheap.
func BenchmarkIsRevoked_NilCert(b *testing.B) {
	p := newWithEntries(100)
	b.ReportAllocs()
	for b.Loop() {
		_ = p.IsRevoked(nil)
	}
}

// newWithEntries builds a PollingChecker pre-populated with n
// revocation entries. Each entry is registered under both Serial
// and KeyID so Hit benchmarks exercise the typical two-key shape.
func newWithEntries(n int) *PollingChecker {
	p := &PollingChecker{
		bySerial: make(map[uint64]Revocation, n),
		byKeyID:  make(map[string]Revocation, n),
	}
	for i := range n {
		serial := uint64(i)
		keyID := "user:" + strconv.Itoa(i) + "@example.com"
		rev := Revocation{Serial: serial, KeyID: keyID}
		p.bySerial[serial] = rev
		p.byKeyID[keyID] = rev
	}
	return p
}
