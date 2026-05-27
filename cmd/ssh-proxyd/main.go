// Command ssh-proxyd is the tokyo3-ssh-proxy SSH gateway and session recorder.
//
// Acts as the user-facing SSH entry point: terminates each SSH connection,
// validates the user's short-lived cert (issued by certd), enforces RBAC
// from cert extensions, requests a per-session impersonation cert from
// certd, opens a routed stream to the target's ssh-tunneld over an
// existing reverse tunnel, mirrors the PTY into an asciinema recording
// uploaded to S3, and publishes audit events to NATS JetStream.
//
// This slice ships only the SSH server skeleton:
// inbound connections handshake, user certs validate against the
// configured trusted user CA, and every channel is rejected with a
// placeholder message. Session forwarding, recording, per-session
// cert minting, and audit emission land in later slices.
//
// Required env vars:
//
//	SSH_PROXYD_USER_CA      Path to the SSH user CA public key in
//	                        authorized_keys format (e.g., the contents
//	                        of `ssh-ed25519 AAAA… ca`). Without this,
//	                        ssh-proxyd has no idea which user certs to
//	                        trust and refuses to start.
//
// Outbound auth — exactly one of:
//
//	CERTD_URL               certd base URL (e.g., https://certd.internal).
//	                        When set, ssh-proxyd mints a fresh short-lived
//	                        SSH cert for every session via certd's
//	                        /api/v1/ssh/sign-user endpoint, presents it to
//	                        the target, and discards it on session close.
//	                        Targets must trust the user CA via
//	                        TrustedUserCAKeys. This is the production
//	                        path; SSH_PROXYD_CLIENT_KEY is ignored when
//	                        set. Requires CERTD_MTLS_CERT + CERTD_MTLS_KEY
//	                        + CERTD_CA_BUNDLE for mTLS to certd.
//	SSH_PROXYD_CLIENT_KEY   Path to an Ed25519 private key (OpenSSH or
//	                        PKCS#8 PEM) the proxy uses to authenticate to
//	                        target sshds with a long-lived shared key.
//	                        The pubkey must be in each target's
//	                        authorized_keys for the relevant remote user.
//	                        Dev / single-target setups only.
//
// Optional env vars:
//
//	SSH_PROXYD_ADDR      TCP listen address (default ":2222").
//	SSH_PROXYD_HOST_KEY  Path to a PKCS#8 Ed25519 private key PEM used
//	                     as the proxy's SSH host key. When unset,
//	                     ssh-proxyd generates an ephemeral key at
//	                     startup — dev only; clients will see a
//	                     different host key after every restart.
//
//	SSH_PROXYD_TARGET_KNOWN_HOSTS  Path to a known_hosts-format file
//	                     used to verify target sshd host keys. When
//	                     unset, target host keys are NOT verified
//	                     (InsecureIgnoreHostKey) — dev only.
//
//	CERTD_MTLS_CERT      Client cert PEM the proxy presents to certd
//	                     during the sign-user call. Required iff
//	                     CERTD_URL is set.
//	CERTD_MTLS_KEY       Matching client key PEM.
//	CERTD_CA_BUNDLE      CA PEM that verifies certd's server cert.
//
//	CERTD_SESSION_TTL_SECONDS  TTL of each per-session cert minted by
//	                     certd. Defaults to 300 (5 minutes). Cap at
//	                     certd's user-cert max (24h by default).
//
//	CERTD_REVOCATIONS_URL  certd revocation-snapshot endpoint
//	                     (e.g., https://certd.internal/api/v1/ssh/revocations).
//	                     When set, ssh-proxyd polls it every
//	                     CERTD_REVOCATIONS_POLL_SECONDS (default 30s)
//	                     and refuses any user cert whose serial or
//	                     KeyID appears in the snapshot. mTLS material
//	                     is the same CERTD_MTLS_CERT/_KEY/_CA_BUNDLE
//	                     the per-session minter already uses.
//	                     Unset disables revocation checking (revoked
//	                     certs that are otherwise valid will be
//	                     accepted).
//	CERTD_REVOCATIONS_POLL_SECONDS  Polling cadence in seconds.
//	                     Default 30; the lower bound is the freshness
//	                     SLA on a freshly-revoked cert. Set high
//	                     when certd is under heavy load and the TTL
//	                     of issued certs is short enough that the
//	                     blast radius of a missed revocation is
//	                     small.
//
//	SSH_PROXYD_NATS_URL   NATS server URL (e.g., tls://nats:4222) used
//	                     for audit-event publishing AND operational log
//	                     shipping (subject "app_log.ssh-proxyd"). When
//	                     unset, audit emission is NoopSink (warn at
//	                     startup) and the logger falls back to stdout
//	                     only. Audit events land on subject
//	                     "ssh.audit.events" in stream "ssh_audit".
//	SSH_PROXYD_NATS_CERT  Publisher client cert PEM (mTLS to NATS),
//	                     shared by audit + log shipping.
//	SSH_PROXYD_NATS_KEY   Matching private key.
//	SSH_PROXYD_NATS_CA    CA bundle that signs the NATS server cert.
//	                     Falls back to SSH_PROXYD_WORKLOAD_CA.
//	SSH_PROXYD_WORKLOAD_CA  CA PEM used as the fallback CA bundle for
//	                     NATS verification. One workload CA per
//	                     deployment is the common case.
//
//	SSH_PROXYD_CAST_DIR  Directory where asciinema cast files are
//	                     written, one per recorded session. When
//	                     unset, session recording is disabled — the
//	                     proxy still forwards traffic but produces
//	                     no audit cast files.
//
//	SSH_PROXYD_TUNNEL_ADDR  Listen address for inbound mTLS+yamux
//	                     tunnels from ssh-tunneld instances (e.g.,
//	                     ":2223"). Unset disables tunnel acceptance —
//	                     every target dial goes direct TCP.
//	SSH_PROXYD_TUNNEL_TLS_CERT  Proxy server cert PEM presented to
//	                     tunneld agents on the tunnel listener.
//	                     Required iff SSH_PROXYD_TUNNEL_ADDR is set.
//	SSH_PROXYD_TUNNEL_TLS_KEY   Matching private key.
//	SSH_PROXYD_TUNNEL_CLIENT_CA CA bundle that signs ssh-tunneld
//	                     workload client certs (used to verify each
//	                     inbound tunnel). Falls back to
//	                     SSH_PROXYD_WORKLOAD_CA.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abagile/tokyo3-base/applog"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/abagile/tokyo3-base/journal/jetstream"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ssh-proxy/internal/audit"
	"github.com/abagile/tokyo3-ssh-proxy/internal/common/certclient"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/revcheck"
	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/routing"
	pssh "github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/ssh"
)

const appName = "ssh-proxyd"

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   appName,
		Short: "tokyo3-ssh-proxy SSH gateway and session recorder",
	}
	root.AddCommand(serveCmd(), versionCmd())
	return root
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the SSH gateway",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context())
		},
	}
}

func runServe(ctx context.Context) error {
	log, _, drainLog := applog.AppLoggerWithNATS(applog.Config{App: appName}, applog.NATSConfig{
		URL:      os.Getenv("SSH_PROXYD_NATS_URL"),
		CertFile: os.Getenv("SSH_PROXYD_NATS_CERT"),
		KeyFile:  os.Getenv("SSH_PROXYD_NATS_KEY"),
		CAFile:   envFirst("SSH_PROXYD_NATS_CA", "SSH_PROXYD_WORKLOAD_CA"),
	}, applog.WithStdout())
	defer drainLog()

	addr := envOr("SSH_PROXYD_ADDR", ":2222")

	hostSigner, err := loadHostKey(log)
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}
	userCA, err := loadUserCA()
	if err != nil {
		return fmt.Errorf("user ca: %w", err)
	}
	log.Info("user ca ready", "fingerprint", gossh.FingerprintSHA256(userCA))

	hostKeyCB, err := loadTargetHostKeyCallback(log)
	if err != nil {
		return fmt.Errorf("target host key callback: %w", err)
	}

	sink, err := loadRecordingSink(log)
	if err != nil {
		return fmt.Errorf("recording sink: %w", err)
	}

	auditSink, err := openAuditSink(log)
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
	defer closeIfCloser(auditSink)

	// Build the certd-client TLS reloader once when any certd-
	// touching surface is enabled (per-session minter OR revocation
	// poller). Shared by both so the workload cert + CA pool live
	// in a single hot-reloadable holder. nil when neither surface
	// needs to talk to certd.
	var certdReloader *certdClientReloader
	if os.Getenv("CERTD_URL") != "" || os.Getenv("CERTD_REVOCATIONS_URL") != "" {
		certdReloader, err = newCertdClientReloader(
			os.Getenv("CERTD_MTLS_CERT"),
			os.Getenv("CERTD_MTLS_KEY"),
			os.Getenv("CERTD_CA_BUNDLE"),
			log,
		)
		if err != nil {
			return fmt.Errorf("certd-client tls: %w", err)
		}
		warnIfCertdCertNearExpiry(log, certdReloader.LeafExpiry())
	}

	// Build the tunnel-server TLS reloader once when the listener
	// is enabled. nil when SSH_PROXYD_TUNNEL_ADDR is unset.
	tunnelReloader, err := newTunnelServerReloaderFromEnv(log)
	if err != nil {
		return fmt.Errorf("tunnel-server tls: %w", err)
	}

	signerFunc, err := loadClientSignerFunc(log, certdReloader)
	if err != nil {
		return fmt.Errorf("client signer: %w", err)
	}

	registry, tunnelListener, err := buildTunnelListener(log, tunnelReloader)
	if err != nil {
		return fmt.Errorf("tunnel listener: %w", err)
	}
	if registry != nil {
		defer func() { _ = registry.Close() }()
	}

	revocationChecker, err := buildRevocationChecker(log, certdReloader)
	if err != nil {
		return fmt.Errorf("revocation checker: %w", err)
	}

	srv, err := pssh.New(pssh.Config{
		Addr:                  addr,
		Log:                   log,
		HostSigner:            hostSigner,
		TrustedUserCA:         userCA,
		ClientSignerFunc:      signerFunc,
		TargetHostKeyCallback: hostKeyCB,
		RecordingSink:         sink,
		Audit:                 auditSink,
		TunnelRegistry:        registry,
		Revocations:           revocationChecker,
	})
	if err != nil {
		return fmt.Errorf("ssh server: %w", err)
	}

	rootCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if revocationChecker != nil {
		go func() {
			if err := revocationChecker.Run(rootCtx); err != nil && !errors.Is(err, context.Canceled) {
				log.Warn("revocation poller exited", "err", err)
			}
		}()
	}

	// CA-bundle mtime pollers — one per reloader. Each polls every
	// DefaultCAPollInterval and reloads its bundle on mtime advance,
	// letting operators rotate the CA pool without restart. Exits
	// are not treated as fatal here; they only ever return when the
	// rootCtx cancels (typical shutdown) or after a misconfigured
	// reloader was constructed (caught earlier).
	if certdReloader != nil {
		go func() {
			if err := certdReloader.RunPoll(rootCtx, DefaultCAPollInterval, log); err != nil && !errors.Is(err, context.Canceled) {
				log.Warn("certd-client CA poller exited", "err", err)
			}
		}()
	}
	if tunnelReloader != nil {
		go func() {
			if err := tunnelReloader.RunPoll(rootCtx, DefaultCAPollInterval, log); err != nil && !errors.Is(err, context.Canceled) {
				log.Warn("tunnel client CA poller exited", "err", err)
			}
		}()
	}

	// Run the tunnel listener alongside the SSH server when one is
	// configured. Either component's exit cancels rootCtx so the
	// other unwinds cleanly.
	errCh := make(chan error, 2)
	if tunnelListener != nil {
		go func() { errCh <- tunnelListener.ListenAndServe(rootCtx) }()
	}
	go func() { errCh <- srv.ListenAndServe(rootCtx) }()

	expected := 1
	if tunnelListener != nil {
		expected = 2
	}
	var firstErr error
	for i := 0; i < expected; i++ {
		err := <-errCh
		if firstErr == nil && err != nil && !errors.Is(err, context.Canceled) {
			firstErr = err
		}
		cancel() // bring the other component down
	}
	if firstErr != nil {
		return fmt.Errorf("serve: %w", firstErr)
	}
	log.Info("stopped")
	return nil
}

// buildRevocationChecker wires the certd revocation poller when
// CERTD_REVOCATIONS_URL is set. When unset, returns (nil, nil) —
// pssh.Server's CertChecker.IsRevoked short-circuits to false and
// the existing handshake behaviour is preserved.
//
// TLS material reuses the certd mTLS env vars the per-session
// minter already understands (CERTD_MTLS_CERT / _KEY / CERTD_CA_BUNDLE)
// — operators don't need separate keys for the revocations endpoint.
func buildRevocationChecker(log *slog.Logger, reloader *certdClientReloader) (*revcheck.PollingChecker, error) {
	url := os.Getenv("CERTD_REVOCATIONS_URL")
	if url == "" {
		log.Warn("CERTD_REVOCATIONS_URL unset — revocation checking disabled (revoked certs will still be accepted)")
		return nil, nil
	}
	if reloader == nil {
		return nil, errors.New("certd-client reloader is required when CERTD_REVOCATIONS_URL is set")
	}
	period := DefaultRevocationPollInterval
	if v := os.Getenv("CERTD_REVOCATIONS_POLL_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("CERTD_REVOCATIONS_POLL_SECONDS %q: must be positive integer", v)
		}
		period = time.Duration(n) * time.Second
	}
	checker, err := revcheck.NewPollingChecker(revcheck.Config{
		URL:               url,
		TLSConfig:         reloader.TLSConfig(),
		PollInterval:      period,
		Log:               log,
		RefreshErrorAttrs: workloadRemainingAttrsFor(reloader),
	})
	if err != nil {
		return nil, err
	}
	log.Info("revocation polling enabled", "url", url, "interval", period)
	return checker, nil
}

// warnIfCertdCertNearExpiry emits the one-shot startup warn if the
// loaded certd-client cert is within 24h of expiry. Called once
// from runServe right after the reloader is built.
func warnIfCertdCertNearExpiry(log *slog.Logger, notAfter time.Time) {
	if notAfter.IsZero() {
		return
	}
	remaining := time.Until(notAfter)
	if remaining >= 24*time.Hour {
		return
	}
	log.Warn("certd-client mTLS cert near expiry — restart ssh-proxyd after the next rotation",
		"remaining", remaining.Round(time.Second),
		"not_after", notAfter)
}

// workloadRemainingAttrsFor returns the closure both the revcheck
// poller and the minter wrap their failure logs with, so operators
// see a uniform workload_cert_remaining field on every certd-side
// failure regardless of which surface produced it. The closure
// queries the reloader on every call so a future cert refresh
// (SIGHUP hook, mtime poll) propagates without further wiring.
func workloadRemainingAttrsFor(r *certdClientReloader) func() []any {
	if r == nil {
		return nil
	}
	return func() []any {
		exp := r.LeafExpiry()
		if exp.IsZero() {
			return nil
		}
		return []any{"workload_cert_remaining", time.Until(exp).Round(time.Second)}
	}
}

// DefaultRevocationPollInterval matches revcheck.DefaultPollInterval.
// Exported here so the env-var doc + the default we surface in logs
// stay in sync.
const DefaultRevocationPollInterval = 30 * time.Second

// newTunnelServerReloaderFromEnv reads the inbound-listener TLS
// envs and returns the reloader. nil when SSH_PROXYD_TUNNEL_ADDR is
// unset (tunnel acceptance disabled). Validation of required env
// vars is shared between the reloader construction here and the
// buildTunnelListener call below; SSH_PROXYD_TUNNEL_ADDR is treated
// as the master switch.
func newTunnelServerReloaderFromEnv(log *slog.Logger) (*tunnelServerReloader, error) {
	if os.Getenv("SSH_PROXYD_TUNNEL_ADDR") == "" {
		return nil, nil
	}
	certFile := os.Getenv("SSH_PROXYD_TUNNEL_TLS_CERT")
	keyFile := os.Getenv("SSH_PROXYD_TUNNEL_TLS_KEY")
	caFile := envFirst("SSH_PROXYD_TUNNEL_CLIENT_CA", "SSH_PROXYD_WORKLOAD_CA")
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, errors.New("SSH_PROXYD_TUNNEL_TLS_CERT/_KEY and a tunnel client CA are required when SSH_PROXYD_TUNNEL_ADDR is set")
	}
	return newTunnelServerReloader(certFile, keyFile, caFile, log)
}

// buildTunnelListener returns the routing.Registry + Listener pair
// when SSH_PROXYD_TUNNEL_ADDR is configured. When unset (reloader
// is nil), both returns are nil — the proxy serves only direct-TCP
// target dials.
func buildTunnelListener(log *slog.Logger, reloader *tunnelServerReloader) (*routing.Registry, *routing.Listener, error) {
	addr := os.Getenv("SSH_PROXYD_TUNNEL_ADDR")
	if addr == "" {
		log.Warn("SSH_PROXYD_TUNNEL_ADDR unset — tunnel acceptance disabled; all sessions use direct TCP")
		return nil, nil, nil
	}
	if reloader == nil {
		return nil, nil, errors.New("tunnel server reloader is required when SSH_PROXYD_TUNNEL_ADDR is set")
	}
	registry := routing.New()
	listener, err := routing.NewListener(routing.ListenerConfig{
		Addr:      addr,
		TLSConfig: reloader.TLSConfig(),
		Registry:  registry,
		Log:       log,
	})
	if err != nil {
		return nil, nil, err
	}
	log.Info("tunnel listener configured", "addr", addr)
	return registry, listener, nil
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Printf("%s %s\n", appName, Version)
		},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadHostKey returns the SSH host signer. When SSH_PROXYD_HOST_KEY
// is set, the file is parsed via [gossh.ParsePrivateKey] which
// accepts both OpenSSH format ("OPENSSH PRIVATE KEY" PEM block, the
// default ssh-keygen writes) and PKCS#8 format. Otherwise an
// ephemeral keypair is generated at startup with a warning.
func loadHostKey(log *slog.Logger) (gossh.Signer, error) {
	if path := os.Getenv("SSH_PROXYD_HOST_KEY"); path != "" {
		signer, err := loadSSHPrivateKey(path)
		if err != nil {
			return nil, err
		}
		log.Info("ssh host key loaded", "path", path, "fingerprint", gossh.FingerprintSHA256(signer.PublicKey()))
		return signer, nil
	}
	log.Warn("SSH_PROXYD_HOST_KEY unset — generating ephemeral SSH host key (not for production; clients will see a different host key after every restart)")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral host key: %w", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	log.Info("ssh host key ready (ephemeral)", "fingerprint", gossh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}

// loadUserCA reads the user CA public key from SSH_PROXYD_USER_CA.
// The file must hold the public key in authorized_keys format
// ("ssh-ed25519 AAAA… comment").
func loadUserCA() (gossh.PublicKey, error) {
	path := os.Getenv("SSH_PROXYD_USER_CA")
	if path == "" {
		return nil, errors.New("SSH_PROXYD_USER_CA is required (path to the user CA public key in authorized_keys format)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return pub, nil
}

// loadClientSignerFunc decides how the proxy authenticates to target
// sshds. Precedence:
//
//  1. CERTD_URL set → mint a fresh short-lived SSH cert per session
//     via certd. The static client key, if also set, is ignored.
//  2. SSH_PROXYD_CLIENT_KEY set → fall back to the static long-lived
//     key. The pubkey must be authorized on every target.
//
// Exactly one must be configured; both empty fails fast at startup.
func loadClientSignerFunc(log *slog.Logger, reloader *certdClientReloader) (func(context.Context, string) (gossh.Signer, error), error) {
	if url := os.Getenv("CERTD_URL"); url != "" {
		if os.Getenv("SSH_PROXYD_CLIENT_KEY") != "" {
			log.Warn("CERTD_URL is set — ignoring SSH_PROXYD_CLIENT_KEY")
		}
		if reloader == nil {
			return nil, errors.New("certd-client reloader is required when CERTD_URL is set")
		}
		return newCertdMinter(url, log, reloader)
	}
	path := os.Getenv("SSH_PROXYD_CLIENT_KEY")
	if path == "" {
		return nil, errors.New("either CERTD_URL or SSH_PROXYD_CLIENT_KEY is required for target-side authentication")
	}
	signer, err := loadSSHPrivateKey(path)
	if err != nil {
		return nil, err
	}
	log.Info("target-side static client key loaded",
		"fingerprint", gossh.FingerprintSHA256(signer.PublicKey()))
	return pssh.StaticSigner(signer), nil
}

// newCertdMinter builds the per-session minter. Each call to the
// returned func generates a fresh Ed25519 keypair, asks certd to
// sign a user cert for the requested principal with a short TTL,
// and returns the ready-to-use [gossh.Signer].
func newCertdMinter(certdURL string, log *slog.Logger, reloader *certdClientReloader) (func(context.Context, string) (gossh.Signer, error), error) {
	remainingAttrs := workloadRemainingAttrsFor(reloader)
	client, err := certclient.NewClient(certdURL, reloader.TLSConfig())
	if err != nil {
		return nil, err
	}
	ttl := int64(300)
	if v := os.Getenv("CERTD_SESSION_TTL_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("CERTD_SESSION_TTL_SECONDS %q: must be positive integer", v)
		}
		ttl = n
	}
	log.Info("certd session minting enabled", "url", certdURL, "ttl_seconds", ttl)
	mint := func(ctx context.Context, principal string) (gossh.Signer, error) {
		// Fresh Ed25519 keypair per session — never reused, never
		// persisted. The cert lives only as long as the session.
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate session key: %w", err)
		}
		sshPub, err := gossh.NewPublicKey(priv.Public())
		if err != nil {
			return nil, fmt.Errorf("wrap session pubkey: %w", err)
		}
		pubAuth := strings.TrimRight(string(gossh.MarshalAuthorizedKey(sshPub)), "\n")
		sessionID := uuid.NewString()
		keyID := "session:" + sessionID + ":principal:" + principal

		resp, err := client.SignUserCert(ctx, certclient.SignUserRequest{
			PublicKey:  pubAuth,
			KeyID:      keyID,
			Principals: []string{principal},
			TTLSeconds: ttl,
		})
		if err != nil {
			return nil, fmt.Errorf("certd sign-user: %w", err)
		}
		// Parse the returned cert + wrap with the matching private key.
		parsed, _, _, _, err := gossh.ParseAuthorizedKey([]byte(resp.Certificate))
		if err != nil {
			return nil, fmt.Errorf("parse minted cert: %w", err)
		}
		cert, ok := parsed.(*gossh.Certificate)
		if !ok {
			return nil, errors.New("certd response is not a Certificate")
		}
		baseSigner, err := gossh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("wrap session private key: %w", err)
		}
		certSigner, err := gossh.NewCertSigner(cert, baseSigner)
		if err != nil {
			return nil, fmt.Errorf("build cert signer: %w", err)
		}
		log.Info("session cert minted",
			"session_id", sessionID,
			"principal", principal,
			"serial", resp.Serial,
			"valid_before", resp.ValidBefore,
		)
		return certSigner, nil
	}
	if remainingAttrs == nil {
		return mint, nil
	}
	// Wrap mint so failures emit workload_cert_remaining. The
	// underlying error is returned unchanged so the SSH server's
	// existing auth-failure handling stays intact.
	return func(ctx context.Context, principal string) (gossh.Signer, error) {
		signer, err := mint(ctx, principal)
		if err != nil {
			args := []any{"principal", principal, "err", err}
			args = append(args, remainingAttrs()...)
			log.Warn("certd session minting failed", args...)
		}
		return signer, err
	}, nil
}

// DefaultCAPollInterval matches the value used by cert-agentd and
// ssh-tunneld; one number for operators to remember across the
// platform.
const DefaultCAPollInterval = 30 * time.Second

// certdClientReloader owns the TLS material ssh-proxyd presents to
// certd (per-session sign-user calls + the revocation-snapshot
// poller). Cert+key are loaded once at startup; the CA bundle is
// mtime-polled by [certdClientReloader.RunPoll] so operators can
// drop in a rotated bundle (typically an [OLD, NEW] overlap) without
// restarting the proxy.
//
// When CERTD_CA_BUNDLE is empty the reloader falls back to the
// system pool — preserved for the dev path that doesn't pin trust.
// In that mode RunCAPoll is a no-op.
type certdClientReloader struct {
	certPath, keyPath, caPath string
	log                       *slog.Logger

	mu        sync.RWMutex
	cert      *tls.Certificate
	notAfter  time.Time
	certMtime time.Time
	pool      *x509.CertPool
	caMtime   time.Time
}

func newCertdClientReloader(certPath, keyPath, caPath string, log *slog.Logger) (*certdClientReloader, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("CERTD_MTLS_CERT and CERTD_MTLS_KEY are required when CERTD_URL is set")
	}
	if log == nil {
		log = slog.Default()
	}
	r := &certdClientReloader{certPath: certPath, keyPath: keyPath, caPath: caPath, log: log}
	if err := r.refreshCert(); err != nil {
		return nil, err
	}
	if caPath == "" {
		sys, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system cert pool: %w", err)
		}
		r.mu.Lock()
		r.pool = sys
		r.mu.Unlock()
	} else if err := r.refreshCABundle(); err != nil {
		return nil, fmt.Errorf("initial CA bundle: %w", err)
	}
	return r, nil
}

// refreshCert re-reads cert+key when mtime advances. No-op when
// unchanged. Logs at info on every actual swap so operators see
// external workload-cert rotations (cert-agentd, manual replace)
// propagate into this process.
func (r *certdClientReloader) refreshCert() error {
	stat, err := os.Stat(r.certPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", r.certPath, err)
	}
	r.mu.RLock()
	prev := r.certMtime
	loaded := r.cert != nil
	r.mu.RUnlock()
	if !stat.ModTime().After(prev) && loaded {
		return nil
	}
	keyPair, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load certd-client cert pair: %w", err)
	}
	var notAfter time.Time
	if len(keyPair.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse certd-client leaf %s: %w", r.certPath, err)
		}
		keyPair.Leaf = leaf
		notAfter = leaf.NotAfter
	}
	r.mu.Lock()
	r.cert = &keyPair
	r.notAfter = notAfter
	r.certMtime = stat.ModTime()
	r.mu.Unlock()
	r.log.Info("certd-client cert reloaded",
		"path", r.certPath,
		"mtime", stat.ModTime(),
		"not_after", notAfter)
	return nil
}

func (r *certdClientReloader) refreshCABundle() error {
	pool, raw, mtime, err := readPoolIfChanged(r.caPath, r.caMtime, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.pool != nil
	})
	if err != nil || pool == nil {
		return err
	}
	r.mu.Lock()
	r.pool = pool
	r.caMtime = mtime
	r.mu.Unlock()
	r.log.Info("certd-client CA bundle reloaded",
		"path", r.caPath,
		"mtime", mtime,
		"fingerprint", bundleFingerprint(raw))
	return nil
}

// RunPoll ticks every interval and reloads BOTH the workload cert
// and the CA bundle when their mtimes advance. No-op for the
// CA-bundle side when caPath is empty (system pool — can't be
// hot-reloaded from here). Returns when ctx is cancelled.
func (r *certdClientReloader) RunPoll(ctx context.Context, interval time.Duration, log *slog.Logger) error {
	if interval <= 0 {
		interval = DefaultCAPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.refreshCert(); err != nil {
				log.Warn("certd-client cert reload failed; keeping previous cert", "path", r.certPath, "err", err)
			}
			if r.caPath != "" {
				if err := r.refreshCABundle(); err != nil {
					log.Warn("certd-client CA reload failed; keeping previous pool", "path", r.caPath, "err", err)
				}
			}
		}
	}
}

func (r *certdClientReloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil, errors.New("certdClientReloader: no cert loaded yet")
	}
	return r.cert, nil
}

func (r *certdClientReloader) VerifyConnection(cs tls.ConnectionState) error {
	r.mu.RLock()
	pool := r.pool
	r.mu.RUnlock()
	if pool == nil {
		return errors.New("certdClientReloader: no CA pool loaded")
	}
	if len(cs.PeerCertificates) == 0 {
		return errors.New("certdClientReloader: peer presented no certificates")
	}
	opts := x509.VerifyOptions{
		Roots:         pool,
		DNSName:       cs.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}

// TLSConfig returns the *tls.Config the certclient HTTP transport
// uses. InsecureSkipVerify + VerifyConnection so the standard
// verifier — which freezes RootCAs at config-construction time —
// doesn't compete with hot-reload semantics.
func (r *certdClientReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetClientCertificate: r.GetClientCertificate,
		InsecureSkipVerify:   true,
		VerifyConnection:     r.VerifyConnection,
		MinVersion:           tls.VersionTLS12,
	}
}

func (r *certdClientReloader) LeafExpiry() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.notAfter
}

// tunnelServerReloader owns the TLS material ssh-proxyd presents on
// its inbound tunnel listener (server cert) plus the CA pool that
// verifies each connecting ssh-tunneld (ClientCAs). Server cert is
// loaded once at startup; the ClientCAs bundle is mtime-polled.
// Verification uses the standard verifier (ClientAuth =
// RequireAndVerifyClientCert) via [GetConfigForClient] returning a
// freshly-built config per inbound connection — that's the
// canonical Go idiom for hot-reloading ClientCAs without
// disabling the standard chain verifier.
type tunnelServerReloader struct {
	certPath, keyPath, clientCAPath string
	log                             *slog.Logger

	mu            sync.RWMutex
	cert          *tls.Certificate
	certMtime     time.Time
	clientCAPool  *x509.CertPool
	clientCAMtime time.Time
}

func newTunnelServerReloader(certPath, keyPath, clientCAPath string, log *slog.Logger) (*tunnelServerReloader, error) {
	if log == nil {
		log = slog.Default()
	}
	r := &tunnelServerReloader{certPath: certPath, keyPath: keyPath, clientCAPath: clientCAPath, log: log}
	if err := r.refreshCert(); err != nil {
		return nil, err
	}
	if err := r.refreshClientCAs(); err != nil {
		return nil, fmt.Errorf("initial tunnel client CA: %w", err)
	}
	return r, nil
}

func (r *tunnelServerReloader) refreshCert() error {
	stat, err := os.Stat(r.certPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", r.certPath, err)
	}
	r.mu.RLock()
	prev := r.certMtime
	loaded := r.cert != nil
	r.mu.RUnlock()
	if !stat.ModTime().After(prev) && loaded {
		return nil
	}
	keyPair, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load tunnel server cert: %w", err)
	}
	if len(keyPair.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse tunnel server leaf %s: %w", r.certPath, err)
		}
		keyPair.Leaf = leaf
	}
	r.mu.Lock()
	r.cert = &keyPair
	r.certMtime = stat.ModTime()
	r.mu.Unlock()
	r.log.Info("tunnel server cert reloaded",
		"path", r.certPath,
		"mtime", stat.ModTime())
	return nil
}

func (r *tunnelServerReloader) refreshClientCAs() error {
	pool, raw, mtime, err := readPoolIfChanged(r.clientCAPath, r.clientCAMtime, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.clientCAPool != nil
	})
	if err != nil || pool == nil {
		return err
	}
	r.mu.Lock()
	r.clientCAPool = pool
	r.clientCAMtime = mtime
	r.mu.Unlock()
	r.log.Info("tunnel client CA bundle reloaded",
		"path", r.clientCAPath,
		"mtime", mtime,
		"fingerprint", bundleFingerprint(raw))
	return nil
}

// RunPoll ticks every interval and reloads BOTH the server cert
// and the ClientCAs bundle when their mtimes advance. Returns
// when ctx is cancelled.
func (r *tunnelServerReloader) RunPoll(ctx context.Context, interval time.Duration, log *slog.Logger) error {
	if interval <= 0 {
		interval = DefaultCAPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.refreshCert(); err != nil {
				log.Warn("tunnel server cert reload failed; keeping previous cert", "path", r.certPath, "err", err)
			}
			if err := r.refreshClientCAs(); err != nil {
				log.Warn("tunnel client CA reload failed; keeping previous pool", "path", r.clientCAPath, "err", err)
			}
		}
	}
}

// TLSConfig returns the outer *tls.Config the listener installs.
// GetConfigForClient delivers a freshly-built per-connection config
// with the latest cert + pool so a rotated ClientCAs file takes
// effect within one poll interval, without disrupting in-flight
// connections.
func (r *tunnelServerReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetConfigForClient: r.serverConfigForClient,
		MinVersion:         tls.VersionTLS12,
	}
}

func (r *tunnelServerReloader) serverConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	r.mu.RLock()
	cert := r.cert
	pool := r.clientCAPool
	r.mu.RUnlock()
	if cert == nil || pool == nil {
		return nil, errors.New("tunnelServerReloader: TLS material not loaded")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// readPoolIfChanged returns (newPool, raw, newMtime, nil) when the
// file's mtime has advanced past prevMtime OR alreadyLoaded()
// returns false (the initial-load case). Returns
// (nil, nil, _, nil) when the file is unchanged — caller treats
// this as a no-op. raw is the PEM bytes the pool was built from,
// suitable for fingerprinting in the caller's success log.
// Shared by both reloaders so the mtime + parse logic stays in
// one place.
func readPoolIfChanged(path string, prevMtime time.Time, alreadyLoaded func() bool) (*x509.CertPool, []byte, time.Time, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if !stat.ModTime().After(prevMtime) && alreadyLoaded() {
		return nil, nil, time.Time{}, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("read %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, nil, time.Time{}, fmt.Errorf("%s contains no PEM certs", path)
	}
	return pool, pem, stat.ModTime(), nil
}

// bundleFingerprint is the first 8 bytes of sha256(pem), hex-
// encoded. Short enough for human-friendly log diffing across a
// fleet, long enough that distinct bundles don't collide in
// practice.
func bundleFingerprint(pem []byte) string {
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:8])
}

// loadSSHPrivateKey reads any supported private key file and returns
// an ssh.Signer. [gossh.ParsePrivateKey] handles OpenSSH-format
// ("OPENSSH PRIVATE KEY" PEM blocks, the default ssh-keygen writes)
// and PKCS#8 alike, so callers don't need to know which format the
// file holds.
func loadSSHPrivateKey(path string) (gossh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	signer, err := gossh.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return signer, nil
}

// envFirst returns the first non-empty env var among keys. Used for
// fallback chains (e.g. SSH_PROXYD_NATS_CA → SSH_PROXYD_WORKLOAD_CA).
func envFirst(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// openAuditSink builds the JetStream publisher Sink from
// SSH_PROXYD_NATS_URL + the CERT/KEY/CA env vars. When the URL is
// empty, returns [audit.NoopSink] — keeps the dev / no-NATS path
// working without a broker.
func openAuditSink(log *slog.Logger) (audit.Sink, error) {
	url := os.Getenv("SSH_PROXYD_NATS_URL")
	if url == "" {
		log.Warn("SSH_PROXYD_NATS_URL not set — audit sink is no-op; not for production")
		return audit.NoopSink, nil
	}
	tlsCfg, err := btls.FromFiles(
		os.Getenv("SSH_PROXYD_NATS_CERT"),
		os.Getenv("SSH_PROXYD_NATS_KEY"),
		envFirst("SSH_PROXYD_NATS_CA", "SSH_PROXYD_WORKLOAD_CA"),
	)
	if err != nil {
		return nil, fmt.Errorf("nats audit TLS: %w", err)
	}
	if tlsCfg != nil {
		log.Info("audit sink: NATS JetStream with mTLS", "url", url)
	} else {
		log.Warn("audit sink: SSH_PROXYD_NATS_CERT not set — connecting without mTLS (not for production)")
	}
	jSink, err := jetstream.NewSink(jetstream.SinkConfig{
		URL:     url,
		Subject: audit.Subject,
		TLS:     tlsCfg,
		Log:     log,
	})
	if err != nil {
		return nil, err
	}
	return journal.NewJSONSink[audit.Entry](jSink), nil
}

// closeIfCloser invokes Close on resources that implement io.Closer,
// silently ignoring values that don't (e.g., audit.NoopSink).
func closeIfCloser(v any) {
	if c, ok := v.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// loadRecordingSink returns the asciinema cast sink. When
// SSH_PROXYD_CAST_DIR is set, recordings drop into that directory
// via [recording.LocalDirSink]. Unset disables recording with a
// startup warning.
func loadRecordingSink(log *slog.Logger) (recording.Sink, error) {
	dir := os.Getenv("SSH_PROXYD_CAST_DIR")
	if dir == "" {
		log.Warn("SSH_PROXYD_CAST_DIR unset — session recording disabled")
		return nil, nil
	}
	sink, err := recording.NewLocalDirSink(dir)
	if err != nil {
		return nil, fmt.Errorf("local cast dir: %w", err)
	}
	log.Info("session recording enabled", "root", sink.Root())
	return sink, nil
}

// loadTargetHostKeyCallback returns the callback used to verify the
// host keys of target sshds the proxy dials out to. When
// SSH_PROXYD_TARGET_KNOWN_HOSTS is set, the file is parsed via
// golang.org/x/crypto/ssh/knownhosts and its callback is used.
// Otherwise InsecureIgnoreHostKey is returned with a startup warning
// — acceptable only for dev environments.
func loadTargetHostKeyCallback(log *slog.Logger) (gossh.HostKeyCallback, error) {
	if path := os.Getenv("SSH_PROXYD_TARGET_KNOWN_HOSTS"); path != "" {
		cb, err := knownhosts.New(path)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", path, err)
		}
		log.Info("target host keys verified via known_hosts", "path", path)
		return cb, nil
	}
	log.Warn("SSH_PROXYD_TARGET_KNOWN_HOSTS unset — target sshd host keys are NOT verified (dev only)")
	return gossh.InsecureIgnoreHostKey(), nil
}
