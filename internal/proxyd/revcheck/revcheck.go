// Package revcheck pulls the SSH cert revocation snapshot from certd
// on a schedule and exposes it as a [gossh.CertChecker.IsRevoked]-shape
// predicate. The ssh-proxyd server installs the predicate so revoked
// certs are refused at handshake time, before they ever reach the
// channel-routing path.
//
// The polling loop owns one HTTP client + one in-memory snapshot
// holder. A failed fetch logs at warn and keeps serving the last-
// successful snapshot — operators see staleness, not flapping
// authentication. Operators set acceptable staleness via PollInterval
// and the [PollingChecker.Healthy] predicate the portal/admin can
// surface.
package revcheck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// Checker is the surface ssh-proxyd's [gossh.CertChecker.IsRevoked]
// adapter consumes. Returns true to refuse the cert at handshake.
type Checker interface {
	IsRevoked(cert *gossh.Certificate) bool
}

// PermissiveChecker is the no-op implementation: every cert passes.
// Used when CERTD_REVOCATIONS_URL is unset so the existing handshake
// path is preserved.
type PermissiveChecker struct{}

// IsRevoked satisfies [Checker]. Always false.
func (PermissiveChecker) IsRevoked(*gossh.Certificate) bool { return false }

// Snapshot mirrors the JSON shape certd's
// /api/v1/ssh/revocations returns. Decoupled from the cert/internal/krl
// types because they live in a different Go module.
type Snapshot struct {
	CapturedAt time.Time    `json:"captured_at"`
	Entries    []Revocation `json:"entries"`
}

// Revocation matches certd's krl.Revocation wire shape.
type Revocation struct {
	Serial  uint64    `json:"serial,omitempty"`
	KeyID   string    `json:"key_id,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Revoker string    `json:"revoker,omitempty"`
	Revoked time.Time `json:"revoked_at"`
}

// PollingChecker polls a certd revocation endpoint and exposes the
// resulting set as a [Checker]. Safe for concurrent IsRevoked reads
// while Run is in flight.
type PollingChecker struct {
	url             string
	client          *http.Client
	log             *slog.Logger
	period          time.Duration
	refreshErrAttrs func() []any

	mu            sync.RWMutex
	bySerial      map[uint64]Revocation
	byKeyID       map[string]Revocation
	lastFetchTime time.Time
	lastFetchErr  error
}

// Config wires a [PollingChecker].
type Config struct {
	// URL is the full certd revocations endpoint (e.g.,
	// "https://certd.internal/api/v1/ssh/revocations"). Required.
	URL string

	// TLSConfig is the mTLS material the proxy presents to certd.
	// Required in production. Nil disables TLS (test only).
	TLSConfig *tls.Config

	// PollInterval is the cadence between fetches. 0 ⇒
	// DefaultPollInterval (30s) — short enough that a freshly-
	// revoked cert fails within a minute, long enough that certd
	// isn't hammered.
	PollInterval time.Duration

	// HTTPTimeout caps a single fetch. 0 ⇒ DefaultHTTPTimeout.
	HTTPTimeout time.Duration

	// Log is the structured logger. nil ⇒ slog.Default.
	Log *slog.Logger

	// RefreshErrorAttrs, if set, returns extra structured fields the
	// poller appends to its per-failure "revocation refresh failed"
	// warn line. Use this to surface caller-specific context (e.g.,
	// remaining validity on the mTLS material the proxy presents to
	// certd) without coupling this package to the caller's
	// bootstrap concepts. Called once per failed fetch inside Run,
	// before the next tick. Nil ⇒ no extra fields.
	RefreshErrorAttrs func() []any
}

// Defaults — chosen for the same reasons certd's own caching
// settings: refresh fast enough for a minute-scale revocation TTL,
// slow enough to keep mTLS cost reasonable on the broker side.
const (
	DefaultPollInterval = 30 * time.Second
	DefaultHTTPTimeout  = 5 * time.Second
)

// NewPollingChecker validates cfg and returns a checker. The initial
// snapshot is empty; the first poll happens at startup of [Run].
func NewPollingChecker(cfg Config) (*PollingChecker, error) {
	if cfg.URL == "" {
		return nil, errors.New("URL is required")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = DefaultHTTPTimeout
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &PollingChecker{
		url:             cfg.URL,
		client:          &http.Client{Timeout: cfg.HTTPTimeout, Transport: &http.Transport{TLSClientConfig: cfg.TLSConfig}},
		log:             cfg.Log,
		period:          cfg.PollInterval,
		refreshErrAttrs: cfg.RefreshErrorAttrs,
		bySerial:        make(map[uint64]Revocation),
		byKeyID:         make(map[string]Revocation),
	}, nil
}

// Run polls the certd snapshot on the configured cadence until ctx
// cancels. The initial fetch happens immediately so the proxy isn't
// open-by-default for the first PollInterval. Fetch failures keep
// the previous snapshot live — a transient certd outage doesn't
// suddenly admit every previously-revoked cert.
func (p *PollingChecker) Run(ctx context.Context) error {
	// Immediate first fetch, then on-period.
	p.refresh(ctx)
	ticker := time.NewTicker(p.period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			p.refresh(ctx)
		}
	}
}

// IsRevoked satisfies [Checker]. Lock-protected against in-flight
// refreshes; the underlying maps are never written to in place,
// they're swapped atomically in [refresh].
func (p *PollingChecker) IsRevoked(cert *gossh.Certificate) bool {
	if cert == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if cert.Serial != 0 {
		if _, ok := p.bySerial[cert.Serial]; ok {
			return true
		}
	}
	if cert.KeyId != "" {
		if _, ok := p.byKeyID[cert.KeyId]; ok {
			return true
		}
	}
	return false
}

// Healthy reports the freshness state for monitoring. ok is false
// when the last fetch errored OR no successful fetch has occurred
// yet. Operators wire this to /healthz or a similar surface.
func (p *PollingChecker) Healthy() (lastFetch time.Time, lastErr error, ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastFetchTime, p.lastFetchErr, p.lastFetchErr == nil && !p.lastFetchTime.IsZero()
}

// refresh fetches the latest snapshot and replaces the in-memory
// maps. Errors are logged + stored; the old maps remain live so
// IsRevoked keeps refusing previously-revoked certs.
func (p *PollingChecker) refresh(ctx context.Context) {
	snap, err := p.fetch(ctx)
	if err != nil {
		p.mu.Lock()
		p.lastFetchErr = err
		p.mu.Unlock()
		args := []any{"url", p.url, "err", err}
		if p.refreshErrAttrs != nil {
			args = append(args, p.refreshErrAttrs()...)
		}
		p.log.Warn("revocation refresh failed; keeping previous snapshot", args...)
		return
	}
	bySerial := make(map[uint64]Revocation, len(snap.Entries))
	byKeyID := make(map[string]Revocation, len(snap.Entries))
	for _, e := range snap.Entries {
		if e.Serial != 0 {
			bySerial[e.Serial] = e
		}
		if e.KeyID != "" {
			byKeyID[e.KeyID] = e
		}
	}
	p.mu.Lock()
	p.bySerial = bySerial
	p.byKeyID = byKeyID
	p.lastFetchTime = time.Now().UTC()
	p.lastFetchErr = nil
	p.mu.Unlock()
	p.log.Debug("revocation snapshot refreshed",
		"entries", len(snap.Entries), "captured_at", snap.CapturedAt)
}

// fetch performs one HTTP round-trip + decode. Separated for tests
// that want to drive snapshots directly.
func (p *PollingChecker) fetch(ctx context.Context) (Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return Snapshot{}, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return Snapshot{}, fmt.Errorf("certd revocations returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var snap Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	return snap, nil
}
