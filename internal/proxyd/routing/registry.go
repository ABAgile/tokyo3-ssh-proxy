// Package routing holds the tunnel registry — the in-memory map from
// host labels (FQDNs, short names) to live ssh-tunneld yamux sessions
// — and dispatches new SSH user-sessions to the right tunnel.
//
// The registry is the proxy-side counterpart to ssh-tunneld's dialer:
// each agent registers itself under one or more host labels at connect
// time and removes itself on disconnect. ssh-proxyd's session router
// looks up the target host in the registry before falling back to
// direct TCP — when a tunnel exists for the host, traffic rides the
// existing yamux session as a new stream.
package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/hashicorp/yamux"
)

// ErrNoTunnel is returned by [Registry.Open] / [Registry.Lookup] when
// no live tunnel is registered for the requested host. Callers
// typically interpret this as "fall back to direct TCP" rather than
// a hard failure.
var ErrNoTunnel = errors.New("no tunnel registered for host")

// Registry maps host labels to live yamux sessions. Safe for
// concurrent use. Lookups are O(1); reads outnumber writes by orders
// of magnitude so this is the right shape even at high session
// counts.
//
// Host labels are case-folded on insert and lookup so "Db-1" and
// "db-1" resolve to the same tunnel; this matches sshd's
// case-insensitive hostname handling.
type Registry struct {
	mu      sync.RWMutex
	tunnels map[string]*entry
	closed  bool
}

// entry holds a single registered tunnel plus the host labels it
// owns. Tracking the label list on the entry (rather than in a
// separate index) keeps Unregister simple and atomic.
type entry struct {
	session *yamux.Session
	hosts   []string
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{tunnels: make(map[string]*entry)}
}

// Register associates each host label with session. A host already
// claimed by a different session is rejected — registry takes
// ownership at first-write time and refuses silent overwrites that
// would orphan stale tunnels. Re-registering the same session under
// new labels is fine; the old labels still resolve.
//
// Returns the actual labels that were inserted. An error is returned
// only when the registry is closed or when at least one label
// conflicts; partial registrations are rolled back.
func (r *Registry) Register(session *yamux.Session, hosts ...string) ([]string, error) {
	if session == nil {
		return nil, errors.New("session is nil")
	}
	if len(hosts) == 0 {
		return nil, errors.New("at least one host is required")
	}
	normalized := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = normalize(h)
		if h == "" {
			return nil, errors.New("empty host label")
		}
		normalized = append(normalized, h)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("registry is closed")
	}

	// Validate first so a conflict mid-list doesn't leave partial state.
	for _, h := range normalized {
		if existing, ok := r.tunnels[h]; ok && existing.session != session {
			return nil, fmt.Errorf("host %q already registered by a different session", h)
		}
	}

	e := &entry{session: session, hosts: normalized}
	for _, h := range normalized {
		r.tunnels[h] = e
	}
	return normalized, nil
}

// Unregister drops every host label associated with session. Safe to
// call when the session was never registered (no-op).
func (r *Registry) Unregister(session *yamux.Session) {
	if session == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for h, e := range r.tunnels {
		if e.session == session {
			delete(r.tunnels, h)
		}
	}
}

// Lookup returns the session registered for host, or [ErrNoTunnel]
// when none is present. Stale sessions (those whose CloseChan has
// already fired) are surfaced as ErrNoTunnel — callers shouldn't
// open new streams against a dead session.
func (r *Registry) Lookup(host string) (*yamux.Session, error) {
	host = normalize(host)
	r.mu.RLock()
	e, ok := r.tunnels[host]
	r.mu.RUnlock()
	if !ok {
		return nil, ErrNoTunnel
	}
	if isDead(e.session) {
		// Best-effort cleanup so the next lookup doesn't pay the
		// liveness check again. Demoting to a write lock; safe to
		// race because Unregister tolerates absent labels.
		r.Unregister(e.session)
		return nil, ErrNoTunnel
	}
	return e.session, nil
}

// Open is a convenience for "lookup, then open a stream". It returns
// the yamux stream as a [net.Conn] so callers (DialTarget) can pass
// it straight to gossh.NewClientConn. ctx isn't honoured during the
// open itself — yamux.Open doesn't take one — but a cancelled ctx
// is detected before the open is attempted.
func (r *Registry) Open(ctx context.Context, host string) (net.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	session, err := r.Lookup(host)
	if err != nil {
		return nil, err
	}
	stream, err := session.Open()
	if err != nil {
		return nil, fmt.Errorf("open stream on tunnel for %q: %w", host, err)
	}
	return stream, nil
}

// Hosts returns a snapshot of every registered host label, sorted.
// Useful for admin endpoints and tests; the cost is one allocation.
func (r *Registry) Hosts() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.tunnels))
	for h := range r.tunnels {
		out = append(out, h)
	}
	// Sort for stable assertions / output. Imported lazily — the
	// hot path is Lookup, which doesn't allocate.
	sortStrings(out)
	return out
}

// Len returns the current host label count. Constant-time.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tunnels)
}

// Close marks the registry closed (rejects further Register calls)
// and closes every live session. Idempotent.
func (r *Registry) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	// Collect unique sessions so we don't Close the same one twice
	// when multiple labels point at it.
	seen := make(map[*yamux.Session]struct{}, len(r.tunnels))
	for _, e := range r.tunnels {
		seen[e.session] = struct{}{}
	}
	r.tunnels = make(map[string]*entry)
	r.mu.Unlock()

	for s := range seen {
		_ = s.Close()
	}
	return nil
}

// normalize folds case and strips whitespace so callers can pass
// "DB-1 " and lookups against "db-1" still hit. Empty input maps to
// empty (and is rejected at Register time).
func normalize(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// isDead reports whether session has already closed. yamux exposes
// IsClosed() as a cheap predicate.
func isDead(session *yamux.Session) bool {
	if session == nil {
		return true
	}
	return session.IsClosed()
}

// sortStrings sorts in place. Wrapped to keep the import surface of
// this file minimal — Lookup is the hot path, Hosts is not.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
