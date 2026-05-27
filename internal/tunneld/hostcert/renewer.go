// Package hostcert renews the SSH host certificate from certd over mTLS,
// writes it atomically to /etc/ssh/ssh_host_*-cert.pub (or the
// configured path), and notifies a caller-supplied hook (typically
// SIGHUP to sshd) so the new cert is picked up.
//
// The renewer is split into two surfaces: [Renewer.SignOnce] performs
// exactly one round-trip + write — useful for tests and the first run
// at startup — and [Renewer.Run] is the long-lived loop that re-signs
// when the cert reaches its renewal fraction. The host's existing
// workload mTLS identity is what the underlying [Signer] presents to
// certd; this package does not touch TLS material directly.
package hostcert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ssh-proxy/internal/common/certclient"
)

// Signer is the subset of [certclient.Client] [Renewer] needs. Defined
// here so tests can stub the network round-trip without spinning up an
// httptest server, and so a future caching/queueing wrapper can drop
// in without touching the renewer.
type Signer interface {
	SignHostCert(ctx context.Context, req certclient.SignHostRequest) (*certclient.SignHostResponse, error)
}

// Config wires a [Renewer]. All paths are required; defaults are
// applied to the timing knobs to keep production wiring concise.
type Config struct {
	// Signer is the certd client. Required.
	Signer Signer

	// HostKeyPath is the on-disk SSH host *private* key sshd already
	// uses (e.g., /etc/ssh/ssh_host_ed25519_key). The renewer reads
	// it once per call to derive the public key to submit to certd.
	HostKeyPath string

	// CertOutputPath is where the freshly signed cert is written
	// atomically. Convention: alongside HostKeyPath with the
	// "-cert.pub" suffix (sshd's HostCertificate directive looks
	// there by default).
	CertOutputPath string

	// KeyID is the human-readable identifier embedded in the cert
	// (also surfaces in certd's audit log). Convention: "host:<fqdn>".
	KeyID string

	// Principals are the hostnames the cert is valid for. sshd
	// validates the connecting client's destination against these.
	Principals []string

	// RequestedTTL is the validity window asked of certd. Certd may
	// cap it further; the renewer trusts the returned validity
	// envelope when scheduling the next renewal. Zero → let certd
	// pick the default.
	RequestedTTL time.Duration

	// RenewFraction is the fraction of [validity envelope] elapsed
	// before re-signing. 0 ⇒ DefaultRenewFraction.
	RenewFraction float64

	// MinRenewInterval is the floor between renewals; protects
	// against pathological short TTLs causing a tight signing loop.
	// 0 ⇒ DefaultMinRenewInterval.
	MinRenewInterval time.Duration

	// RetryBackoff is the delay after a signing failure before
	// retrying. 0 ⇒ DefaultRetryBackoff.
	RetryBackoff time.Duration

	// OnRenewed is invoked after each successful write with the
	// validity envelope of the new cert. Production wires this to
	// "kill -HUP $(pidof sshd)" or equivalent. Nil ⇒ no-op.
	OnRenewed func(validAfter, validBefore time.Time)

	// Now is the clock used for renewal scheduling. nil ⇒ time.Now.
	// Tests inject a fixed clock to exercise the loop deterministically.
	Now func() time.Time

	// Log is the logger. nil ⇒ slog.Default.
	Log *slog.Logger

	// SignErrorAttrs, if set, returns extra structured fields the
	// renewer appends to its per-failure retry-log warn line. Use
	// this to surface caller-specific context (e.g., remaining
	// validity on the mTLS material the agent presents to certd)
	// without coupling this package to the caller's bootstrap
	// concepts. Called once per failed SignOnce inside Run, before
	// the retry sleep. Nil ⇒ no extra fields.
	SignErrorAttrs func() []any
}

// Renewer signs the host cert on a schedule and writes it atomically
// to disk. Safe for concurrent calls to [Renewer.SignOnce] from a
// single goroutine; [Renewer.Run] is intended to own the goroutine.
type Renewer struct {
	cfg Config
}

// Sensible defaults — exported so callers can document deviations
// without re-deriving the constants.
const (
	DefaultRenewFraction    = 0.6 // re-sign at 60% of validity elapsed
	DefaultMinRenewInterval = 1 * time.Minute
	DefaultRetryBackoff     = 30 * time.Second
)

// New validates cfg and returns a [Renewer]. Returns an error rather
// than panicking so callers see config bugs at startup.
func New(cfg Config) (*Renewer, error) {
	if cfg.Signer == nil {
		return nil, errors.New("Signer is required")
	}
	if cfg.HostKeyPath == "" {
		return nil, errors.New("HostKeyPath is required")
	}
	if cfg.CertOutputPath == "" {
		return nil, errors.New("CertOutputPath is required")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("KeyID is required")
	}
	if len(cfg.Principals) == 0 {
		return nil, errors.New("at least one Principal is required")
	}
	if cfg.RenewFraction == 0 {
		cfg.RenewFraction = DefaultRenewFraction
	}
	if cfg.RenewFraction <= 0 || cfg.RenewFraction >= 1 {
		return nil, fmt.Errorf("RenewFraction must be in (0,1), got %v", cfg.RenewFraction)
	}
	if cfg.MinRenewInterval == 0 {
		cfg.MinRenewInterval = DefaultMinRenewInterval
	}
	if cfg.RetryBackoff == 0 {
		cfg.RetryBackoff = DefaultRetryBackoff
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Renewer{cfg: cfg}, nil
}

// SignOnce reads the host public key, asks certd for a fresh cert,
// and writes it atomically to the output path. Returns the validity
// envelope so callers (including the [Run] loop) can decide when to
// renew next. Failure modes — read errors, certd 4xx/5xx, write
// errors — are returned untransformed for the caller to log/retry.
func (r *Renewer) SignOnce(ctx context.Context) (validAfter, validBefore time.Time, err error) {
	pubBytes, err := readHostPublicKey(r.cfg.HostKeyPath)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("read host pub key: %w", err)
	}

	req := certclient.SignHostRequest{
		PublicKey:  string(pubBytes),
		KeyID:      r.cfg.KeyID,
		Principals: r.cfg.Principals,
	}
	if r.cfg.RequestedTTL > 0 {
		req.TTLSeconds = int64(r.cfg.RequestedTTL.Seconds())
	}
	resp, err := r.cfg.Signer.SignHostCert(ctx, req)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("sign host cert: %w", err)
	}
	if resp.Certificate == "" {
		return time.Time{}, time.Time{}, errors.New("certd returned empty certificate")
	}

	if err := writeAtomic(r.cfg.CertOutputPath, []byte(resp.Certificate)); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("write cert: %w", err)
	}
	r.cfg.Log.Info("host cert renewed",
		"key_id", resp.KeyID,
		"serial", resp.Serial,
		"valid_after", resp.ValidAfter,
		"valid_before", resp.ValidBefore,
		"path", r.cfg.CertOutputPath,
	)
	if r.cfg.OnRenewed != nil {
		r.cfg.OnRenewed(resp.ValidAfter, resp.ValidBefore)
	}
	return resp.ValidAfter, resp.ValidBefore, nil
}

// Run signs immediately and then loops, renewing at the configured
// fraction of validity elapsed. Returns when ctx is cancelled.
// Signing failures schedule a retry after [Config.RetryBackoff]
// rather than crashing the agent — sshd keeps serving with the
// existing cert until it expires.
func (r *Renewer) Run(ctx context.Context) error {
	for {
		validAfter, validBefore, err := r.SignOnce(ctx)
		var wait time.Duration
		if err != nil {
			args := []any{"err", err, "backoff", r.cfg.RetryBackoff}
			if r.cfg.SignErrorAttrs != nil {
				args = append(args, r.cfg.SignErrorAttrs()...)
			}
			r.cfg.Log.Warn("host cert sign failed; will retry", args...)
			wait = r.cfg.RetryBackoff
		} else {
			wait = r.nextRenewalDelay(validAfter, validBefore)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// nextRenewalDelay returns how long to wait before the next sign
// attempt. Floored at [Config.MinRenewInterval]; if the cert is
// already past its renewal point (or expired), the renewer
// re-signs immediately.
func (r *Renewer) nextRenewalDelay(validAfter, validBefore time.Time) time.Duration {
	lifetime := validBefore.Sub(validAfter)
	renewAfter := time.Duration(float64(lifetime) * r.cfg.RenewFraction)
	deadline := validAfter.Add(renewAfter)
	wait := deadline.Sub(r.cfg.Now())
	if wait < r.cfg.MinRenewInterval {
		return r.cfg.MinRenewInterval
	}
	return wait
}

// readHostPublicKey loads the SSH private key at path and returns
// the matching public key in authorized_keys format. sshd's host
// key is the natural source; this avoids requiring operators to
// maintain a separate ".pub" file alongside it.
func readHostPublicKey(path string) ([]byte, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := gossh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key at %s: %w", path, err)
	}
	return gossh.MarshalAuthorizedKey(signer.PublicKey()), nil
}

// writeAtomic writes b to path via a temp file + rename so partial
// writes are never observable by sshd or downstream tooling. The
// temp file lives in the same directory to guarantee rename(2) is
// atomic (cross-filesystem renames degrade to copy+delete).
func writeAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hostcert-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
