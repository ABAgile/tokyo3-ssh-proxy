package routing_test

import (
	"strconv"
	"testing"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/routing"
)

// BenchmarkRegistry_Lookup_Hit measures the cost of a successful
// host-label lookup. Runs once per user session; the registry is
// the per-target dial gate.
func BenchmarkRegistry_Lookup_Hit(b *testing.B) {
	r := routing.New()
	defer r.Close()
	// Populate with 1000 entries — realistic upper bound for a
	// single proxy serving thousands of hosts in a fleet.
	for i := range 1000 {
		_, s := twoSessions(b)
		if _, err := r.Register(s, "host-"+strconv.Itoa(i)); err != nil {
			b.Fatalf("Register: %v", err)
		}
	}
	const target = "host-500"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = r.Lookup(target)
	}
}

// BenchmarkRegistry_Lookup_Miss measures the absent-host path. Same
// shape — operators care about both hit and miss latency since
// every dial consults the registry.
func BenchmarkRegistry_Lookup_Miss(b *testing.B) {
	r := routing.New()
	defer r.Close()
	for i := range 1000 {
		_, s := twoSessions(b)
		if _, err := r.Register(s, "host-"+strconv.Itoa(i)); err != nil {
			b.Fatalf("Register: %v", err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = r.Lookup("not-a-real-host")
	}
}

// BenchmarkRegistry_RegisterUnregister exercises the write side
// without paying yamux-pair setup cost on every iteration: one
// session is reused, the same label is registered + unregistered
// repeatedly. Bounds the per-reconnect-storm map cost.
func BenchmarkRegistry_RegisterUnregister(b *testing.B) {
	r := routing.New()
	defer r.Close()
	_, s := twoSessions(b)
	const label = "bench-host"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := r.Register(s, label); err != nil {
			b.Fatalf("Register: %v", err)
		}
		r.Unregister(s)
	}
}
