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
//	SSH_PROXYD_NATS_URL   NATS server URL (e.g., tls://nats:4222) for
//	                     audit-event publishing. When unset, audit
//	                     emission is disabled (NoopSink) with a startup
//	                     warning. Audit events land on subject
//	                     "ssh.audit.events" in stream "ssh_audit".
//	SSH_PROXYD_NATS_CERT  Publisher client cert PEM (mTLS to NATS).
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

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
	log, _ := applog.AppLogger(appName, applog.WithStdout())

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

	signerFunc, err := loadClientSignerFunc(log)
	if err != nil {
		return fmt.Errorf("client signer: %w", err)
	}

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

	registry, tunnelListener, err := buildTunnelListener(log)
	if err != nil {
		return fmt.Errorf("tunnel listener: %w", err)
	}
	if registry != nil {
		defer func() { _ = registry.Close() }()
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
	})
	if err != nil {
		return fmt.Errorf("ssh server: %w", err)
	}

	rootCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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

// buildTunnelListener returns the routing.Registry + Listener pair
// when SSH_PROXYD_TUNNEL_ADDR is configured. When unset, both
// returns are nil — the proxy serves only direct-TCP target dials.
func buildTunnelListener(log *slog.Logger) (*routing.Registry, *routing.Listener, error) {
	addr := os.Getenv("SSH_PROXYD_TUNNEL_ADDR")
	if addr == "" {
		log.Warn("SSH_PROXYD_TUNNEL_ADDR unset — tunnel acceptance disabled; all sessions use direct TCP")
		return nil, nil, nil
	}
	certFile := os.Getenv("SSH_PROXYD_TUNNEL_TLS_CERT")
	keyFile := os.Getenv("SSH_PROXYD_TUNNEL_TLS_KEY")
	caFile := envFirst("SSH_PROXYD_TUNNEL_CLIENT_CA", "SSH_PROXYD_WORKLOAD_CA")
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, nil, errors.New("SSH_PROXYD_TUNNEL_TLS_CERT/_KEY and a tunnel client CA are required when SSH_PROXYD_TUNNEL_ADDR is set")
	}

	keyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load tunnel server cert: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read tunnel client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("tunnel client CA %s contains no PEM certs", caFile)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	registry := routing.New()
	listener, err := routing.NewListener(routing.ListenerConfig{
		Addr:      addr,
		TLSConfig: tlsCfg,
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
func loadClientSignerFunc(log *slog.Logger) (func(context.Context, string) (gossh.Signer, error), error) {
	if url := os.Getenv("CERTD_URL"); url != "" {
		if os.Getenv("SSH_PROXYD_CLIENT_KEY") != "" {
			log.Warn("CERTD_URL is set — ignoring SSH_PROXYD_CLIENT_KEY")
		}
		return newCertdMinter(url, log)
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
func newCertdMinter(certdURL string, log *slog.Logger) (func(context.Context, string) (gossh.Signer, error), error) {
	tlsCfg, err := loadCertdMTLS()
	if err != nil {
		return nil, err
	}
	client, err := certclient.NewClient(certdURL, tlsCfg)
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
	return func(ctx context.Context, principal string) (gossh.Signer, error) {
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
	}, nil
}

// loadCertdMTLS builds the *tls.Config presented to certd. The proxy
// authenticates with its workload identity cert; certd's role table
// maps the cert principal to a role that allows session minting.
func loadCertdMTLS() (*tls.Config, error) {
	certFile := os.Getenv("CERTD_MTLS_CERT")
	keyFile := os.Getenv("CERTD_MTLS_KEY")
	caBundle := os.Getenv("CERTD_CA_BUNDLE")
	if certFile == "" || keyFile == "" {
		return nil, errors.New("CERTD_MTLS_CERT and CERTD_MTLS_KEY are required when CERTD_URL is set")
	}
	keyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert pair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		MinVersion:   tls.VersionTLS12,
	}
	if caBundle != "" {
		pem, err := os.ReadFile(caBundle)
		if err != nil {
			return nil, fmt.Errorf("read CERTD_CA_BUNDLE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CERTD_CA_BUNDLE %s contains no PEM certs", caBundle)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
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
