// Command ssh-tunneld is the tokyo3-ssh-proxy reverse-tunnel agent.
//
// Runs on every host that should be reachable via ssh-proxyd without
// exposing port 22 to the network. Holds a long-lived outbound mTLS
// connection to ssh-proxyd, wrapped in a yamux session; inbound
// streams from the proxy land at the local sshd (127.0.0.1:22 by
// default). Optionally renews its SSH host certificate from certd on
// the same schedule.
//
// Required env vars:
//
//	SSH_TUNNELD_PROXY_ADDR   ssh-proxyd tunnel listener address
//	                         (e.g., "proxy.internal:2223").
//	SSH_TUNNELD_TLS_CERT     Workload mTLS client cert PEM
//	                         (SPIFFE URI of the form
//	                         "spiffe://<td>/host/<fqdn>"; the proxy
//	                         derives the registered host label from
//	                         this).
//	SSH_TUNNELD_TLS_KEY      Matching private key PEM.
//	SSH_TUNNELD_TLS_CA       CA bundle that signs the proxy's tunnel
//	                         server cert.
//
// Optional env vars:
//
//	SSH_TUNNELD_PROXY_SERVER_NAME  TLS ServerName presented to the
//	                         proxy. Defaults to the host portion of
//	                         SSH_TUNNELD_PROXY_ADDR.
//	SSH_TUNNELD_LOCAL_SSHD   Local sshd address. Default 127.0.0.1:22.
//
//	SSH_TUNNELD_HOST_KEY     Path to the host's SSH private key
//	                         (e.g., /etc/ssh/ssh_host_ed25519_key).
//	                         When set, the agent renews the host cert
//	                         from certd on a 60%-TTL cadence and
//	                         writes it next to the key with the
//	                         "-cert.pub" suffix (or the path under
//	                         SSH_TUNNELD_HOST_CERT). Unset disables
//	                         the renewer.
//	SSH_TUNNELD_HOST_CERT    Override the cert output path. Defaults
//	                         to <HOST_KEY>-cert.pub.
//	SSH_TUNNELD_HOST_KEY_ID  KeyID embedded in the host cert (audit
//	                         attribution). Default "host:<hostname>".
//	SSH_TUNNELD_HOST_PRINCIPALS  Comma-separated hostnames the cert
//	                         is valid for. Defaults to "<hostname>".
//	SSH_TUNNELD_CERTD_URL    certd base URL. Required when
//	                         SSH_TUNNELD_HOST_KEY is set.
//	SSH_TUNNELD_CERTD_CA     CA bundle for verifying certd's server
//	                         cert (mTLS to certd uses the same
//	                         SSH_TUNNELD_TLS_CERT/_KEY workload
//	                         identity). Falls back to
//	                         SSH_TUNNELD_TLS_CA.
//
//	SSH_TUNNELD_NATS_URL     NATS server URL (e.g., tls://nats:4222)
//	                         for shipping operational log lines on
//	                         subject "app_log.ssh-tunneld". Unset
//	                         leaves the logger at stdout only.
//	SSH_TUNNELD_NATS_CERT    Publisher client cert PEM (mTLS to NATS).
//	                         Defaults to SSH_TUNNELD_TLS_CERT so the
//	                         single workload identity covers both the
//	                         proxy connection and log shipping.
//	SSH_TUNNELD_NATS_KEY     Matching private key. Defaults to
//	                         SSH_TUNNELD_TLS_KEY.
//	SSH_TUNNELD_NATS_CA      CA bundle that signs the NATS server cert.
//	                         Defaults to SSH_TUNNELD_TLS_CA.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abagile/tokyo3-base/applog"
	bnats "github.com/abagile/tokyo3-base/nats"
	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ssh-proxy/internal/common/certclient"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/forward"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/hostcert"
	"github.com/abagile/tokyo3-ssh-proxy/internal/tunneld/tunnel"
)

const appName = "ssh-tunneld"

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
		Short: "tokyo3-ssh-proxy reverse-tunnel agent",
	}
	root.AddCommand(runCmd(), versionCmd())
	return root
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the tunnel agent in the foreground",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cmd.Context())
		},
	}
}

func runAgent(ctx context.Context) error {
	log, drainLog := newAppLogger()
	defer drainLog()

	proxyAddr := mustEnv("SSH_TUNNELD_PROXY_ADDR")
	certPath := mustEnv("SSH_TUNNELD_TLS_CERT")
	keyPath := mustEnv("SSH_TUNNELD_TLS_KEY")
	proxyCAPath := mustEnv("SSH_TUNNELD_TLS_CA")
	certdCAPath := envFirst("SSH_TUNNELD_CERTD_CA", "SSH_TUNNELD_TLS_CA")
	if certdCAPath == "" {
		return errors.New("SSH_TUNNELD_CERTD_CA or SSH_TUNNELD_TLS_CA is required for certd verification")
	}

	reloader, err := newTLSReloader(certPath, keyPath, proxyCAPath, certdCAPath, resolveProxyServerName(proxyAddr))
	if err != nil {
		return fmt.Errorf("tls reloader: %w", err)
	}

	// Surface workload-cert remaining validity. The reloader's
	// GetClientCertificate hot-swaps the in-memory cert when an
	// external rotator (cert-agentd, manual replace) updates the
	// file — but only on the next refreshCert call. For now there's
	// no refreshCert trigger besides startup, so a long outage that
	// crosses leaf expiry still requires intervention. The 24h warn
	// surfaces that risk.
	if !reloader.LeafExpiry().IsZero() {
		if remaining := time.Until(reloader.LeafExpiry()); remaining < 24*time.Hour {
			log.Warn("workload mTLS cert near expiry — restart ssh-tunneld after the next rotation",
				"remaining", remaining.Round(time.Second),
				"not_after", reloader.LeafExpiry())
		}
	}

	// Shared closure used by both retry surfaces (dialer + host-cert
	// renewer) so operators see the same field on every failure log.
	workloadRemainingAttrs := func() []any {
		exp := reloader.LeafExpiry()
		if exp.IsZero() {
			return nil
		}
		return []any{"workload_cert_remaining", time.Until(exp).Round(time.Second)}
	}

	localAddr := envOr("SSH_TUNNELD_LOCAL_SSHD", forward.DefaultLocalAddr)
	fwd := forward.New(forward.Config{
		LocalAddr: localAddr,
		Log:       log,
	})
	log.Info("local sshd target configured", "addr", localAddr)

	dialer, err := tunnel.New(tunnel.Config{
		Target:         proxyAddr,
		TLSConfig:      reloader.ProxyTLSConfig(),
		Handler:        fwd.Handle,
		Log:            log,
		DialErrorAttrs: workloadRemainingAttrs,
	})
	if err != nil {
		return fmt.Errorf("dialer: %w", err)
	}
	log.Info("tunnel dialer configured", "proxy", proxyAddr)

	rootCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	renewer, err := buildHostCertRenewer(log, reloader, workloadRemainingAttrs)
	if err != nil {
		return fmt.Errorf("host cert renewer: %w", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 3)
	expected := 2 // dialer + CA-poll

	wg.Go(func() {
		errCh <- dialer.Run(rootCtx)
	})
	wg.Go(func() {
		errCh <- reloader.RunCAPoll(rootCtx, DefaultCAPollInterval, log)
	})

	if renewer != nil {
		expected = 3
		wg.Go(func() {
			errCh <- renewer.Run(rootCtx)
		})
	}

	// Wait for first component exit; cancel to bring the others down.
	first := <-errCh
	cancel()
	go func() {
		// Drain remaining errors so the goroutines can finish.
		for range expected - 1 {
			<-errCh
		}
	}()
	wg.Wait()

	if first != nil && !errors.Is(first, context.Canceled) {
		return fmt.Errorf("agent: %w", first)
	}
	log.Info("stopped")
	return nil
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

// openLogNATS dials a NATS connection used by applog's WithAsyncNats
// writer to ship operational log lines on subject "app_log.ssh-tunneld".
// CERT / KEY / CA default to the workload-identity material the agent
// already uses for the proxy connection, so a single set of TLS files
// covers both purposes. Returns (nil, nil) when SSH_TUNNELD_NATS_URL
// is unset.
//
// RetryOnFailedConnect + unbounded MaxReconnects mean a broker that's
// down at boot doesn't permanently disable log shipping for the
// process lifetime — entries get dropped (AsyncWriter is
// discard-on-full) while disconnected, and shipping auto-resumes
// once NATS comes back.
func openLogNATS() (*nats.Conn, error) {
	url := os.Getenv("SSH_TUNNELD_NATS_URL")
	if url == "" {
		return nil, nil
	}
	nc, err := bnats.Dial(url,
		envFirst("SSH_TUNNELD_NATS_CERT", "SSH_TUNNELD_TLS_CERT"),
		envFirst("SSH_TUNNELD_NATS_KEY", "SSH_TUNNELD_TLS_KEY"),
		envFirst("SSH_TUNNELD_NATS_CA", "SSH_TUNNELD_TLS_CA"),
		nats.Timeout(1*time.Second),
		nats.DrainTimeout(500*time.Millisecond),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("log shipping: %w", err)
	}
	return nc, nil
}

// newAppLogger builds the structured logger for ssh-tunneld. Ships
// log lines async to NATS subject "app_log.ssh-tunneld" when
// SSH_TUNNELD_NATS_URL is set; otherwise stdout-only. Returns the
// logger plus a drain callback the caller defers — no-op when log
// shipping is disabled.
func newAppLogger() (*slog.Logger, func()) {
	logNATS, logNATSErr := openLogNATS()
	drain := func() {}
	if logNATS != nil {
		drain = func() { _ = logNATS.Drain() }
	}
	writerOpts := []applog.WriterOption{applog.WithStdout()}
	if logNATS != nil {
		writerOpts = append(writerOpts, applog.WithAsyncNats(logNATS))
	}
	log, _ := applog.AppLogger(appName, writerOpts...)
	if logNATSErr != nil {
		log.Warn("operational log shipping disabled", "err", logNATSErr)
	} else if logNATS != nil {
		// "configured" rather than "shipping" — RetryOnFailedConnect
		// means the connection may still be establishing in the
		// background; entries get dropped (AsyncWriter is
		// discard-on-full) until it does.
		log.Info("operational log shipping configured", "subject", "app_log."+appName)
	}
	return log, drain
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s: %s is required\n", appName, key)
		os.Exit(2)
	}
	return v
}

func envFirst(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// tlsReloader owns the in-process TLS state ssh-tunneld presents to
// its two peers: the proxy's tunnel listener (proxyTLSConfig) and
// certd's host-cert-sign endpoint (certdTLSConfig). One workload
// identity covers both, so the cert+key are shared; the trust pools
// can differ (typically same CA, but SSH_TUNNELD_CERTD_CA may
// override). All three on-disk files are mtime-polled by
// [tlsReloader.RunCAPoll] (cheap stat calls every 30s) so operators
// can drop in a rotated bundle or fresh leaf without restarting the
// agent.
//
// TLS handshakes go through GetClientCertificate (per-handshake cert
// snapshot) and VerifyConnection (per-handshake pool snapshot), with
// tls.Config.InsecureSkipVerify=true so the standard verifier — which
// freezes RootCAs at config-construction time — doesn't compete with
// hot-reload semantics.
type tlsReloader struct {
	certPath, keyPath        string
	proxyCAPath, certdCAPath string
	proxyServerName          string

	mu           sync.RWMutex
	cert         *tls.Certificate
	notAfter     time.Time
	proxyPool    *x509.CertPool
	certdPool    *x509.CertPool
	proxyCAMtime time.Time
	certdCAMtime time.Time
}

// DefaultCAPollInterval matches cert-agentd's; one number for
// operators to remember across the platform.
const DefaultCAPollInterval = 30 * time.Second

// newTLSReloader reads cert+key + both CA bundles from disk and
// returns a populated reloader. proxyServerName is the SNI the
// dialer sets at handshake (derived from SSH_TUNNELD_PROXY_ADDR
// when SSH_TUNNELD_PROXY_SERVER_NAME is unset).
func newTLSReloader(certPath, keyPath, proxyCAPath, certdCAPath, proxyServerName string) (*tlsReloader, error) {
	r := &tlsReloader{
		certPath:        certPath,
		keyPath:         keyPath,
		proxyCAPath:     proxyCAPath,
		certdCAPath:     certdCAPath,
		proxyServerName: proxyServerName,
	}
	if err := r.refreshCert(); err != nil {
		return nil, err
	}
	if err := r.refreshProxyCA(); err != nil {
		return nil, fmt.Errorf("initial proxy CA: %w", err)
	}
	if err := r.refreshCertdCA(); err != nil {
		return nil, fmt.Errorf("initial certd CA: %w", err)
	}
	return r, nil
}

// refreshCert re-reads the workload cert+key from disk. Always
// re-reads (no mtime gate) because callers fire this on demand
// (e.g., a future SIGHUP hook) where they already know the file
// changed.
func (r *tlsReloader) refreshCert() error {
	keyPair, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load workload cert pair: %w", err)
	}
	var notAfter time.Time
	if len(keyPair.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse workload leaf %s: %w", r.certPath, err)
		}
		keyPair.Leaf = leaf
		notAfter = leaf.NotAfter
	}
	r.mu.Lock()
	r.cert = &keyPair
	r.notAfter = notAfter
	r.mu.Unlock()
	return nil
}

// refreshProxyCA / refreshCertdCA re-read the corresponding CA
// bundle when mtime advances. No-op when unchanged, atomic pool
// swap when changed. Read failures return the error; the previous
// pool stays live for VerifyConnection callers.
func (r *tlsReloader) refreshProxyCA() error {
	pool, mtime, err := readPoolIfChanged(r.proxyCAPath, r.proxyCAMtime, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.proxyPool != nil
	})
	if err != nil || pool == nil {
		return err
	}
	r.mu.Lock()
	r.proxyPool = pool
	r.proxyCAMtime = mtime
	r.mu.Unlock()
	return nil
}

func (r *tlsReloader) refreshCertdCA() error {
	pool, mtime, err := readPoolIfChanged(r.certdCAPath, r.certdCAMtime, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.certdPool != nil
	})
	if err != nil || pool == nil {
		return err
	}
	r.mu.Lock()
	r.certdPool = pool
	r.certdCAMtime = mtime
	r.mu.Unlock()
	return nil
}

// readPoolIfChanged returns (newPool, newMtime, nil) when the file's
// mtime has advanced past prevMtime OR alreadyLoaded() returns false
// (the initial-load case). Returns (nil, _, nil) when the file is
// unchanged — caller treats this as a no-op.
func readPoolIfChanged(path string, prevMtime time.Time, alreadyLoaded func() bool) (*x509.CertPool, time.Time, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if !stat.ModTime().After(prevMtime) && alreadyLoaded() {
		return nil, time.Time{}, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, time.Time{}, fmt.Errorf("%s contains no PEM certs", path)
	}
	return pool, stat.ModTime(), nil
}

// RunCAPoll ticks every interval and re-reads both bundles when
// their mtimes advance. Read failures keep the previous pool live
// and log warn so a corrupt drop-in never opens a trust window.
// Returns when ctx is cancelled.
func (r *tlsReloader) RunCAPoll(ctx context.Context, interval time.Duration, log *slog.Logger) error {
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
			if err := r.refreshProxyCA(); err != nil {
				log.Warn("proxy CA reload failed; keeping previous pool", "path", r.proxyCAPath, "err", err)
			}
			if err := r.refreshCertdCA(); err != nil {
				log.Warn("certd CA reload failed; keeping previous pool", "path", r.certdCAPath, "err", err)
			}
		}
	}
}

// GetClientCertificate satisfies tls.Config.GetClientCertificate.
// Returns the current workload cert; the handshake stack invokes
// this once per dial, so a Refresh between dials propagates without
// further coordination.
func (r *tlsReloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil, errors.New("tlsReloader: no cert loaded yet")
	}
	return r.cert, nil
}

func (r *tlsReloader) verifyAgainstPool(cs tls.ConnectionState, picker func(*tlsReloader) *x509.CertPool) error {
	r.mu.RLock()
	pool := picker(r)
	r.mu.RUnlock()
	if pool == nil {
		return errors.New("tlsReloader: no CA pool loaded")
	}
	if len(cs.PeerCertificates) == 0 {
		return errors.New("tlsReloader: peer presented no certificates")
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

// ProxyTLSConfig returns the tls.Config the dialer presents to
// ssh-proxyd's tunnel listener. ServerName is fixed at construction
// (typically the host portion of SSH_TUNNELD_PROXY_ADDR).
func (r *tlsReloader) ProxyTLSConfig() *tls.Config {
	return &tls.Config{
		GetClientCertificate: r.GetClientCertificate,
		InsecureSkipVerify:   true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return r.verifyAgainstPool(cs, func(rr *tlsReloader) *x509.CertPool { return rr.proxyPool })
		},
		ServerName: r.proxyServerName,
		MinVersion: tls.VersionTLS12,
	}
}

// CertdTLSConfig returns the tls.Config the host-cert renewer's
// HTTP client uses for certd. ServerName is set by http.Transport
// from the URL host so it's left empty here.
func (r *tlsReloader) CertdTLSConfig() *tls.Config {
	return &tls.Config{
		GetClientCertificate: r.GetClientCertificate,
		InsecureSkipVerify:   true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return r.verifyAgainstPool(cs, func(rr *tlsReloader) *x509.CertPool { return rr.certdPool })
		},
		MinVersion: tls.VersionTLS12,
	}
}

// LeafExpiry returns the loaded cert's NotAfter. Zero when no cert
// has been loaded (only happens in test scaffolding).
func (r *tlsReloader) LeafExpiry() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.notAfter
}

// resolveProxyServerName picks the SNI to present to ssh-proxyd:
// the explicit override if set, otherwise the host portion of the
// proxy address.
func resolveProxyServerName(proxyAddr string) string {
	serverName := os.Getenv("SSH_TUNNELD_PROXY_SERVER_NAME")
	if serverName != "" {
		return serverName
	}
	host, _, splitErr := net.SplitHostPort(proxyAddr)
	if splitErr != nil {
		return proxyAddr
	}
	return host
}

// buildHostCertRenewer returns a configured renewer when
// SSH_TUNNELD_HOST_KEY is set; otherwise nil so the caller skips the
// renewal goroutine. The certd HTTP client reuses the reloader's
// certd-facing TLS config so the workload identity and trust pool
// stay hot-reloadable.
func buildHostCertRenewer(log *slog.Logger, reloader *tlsReloader, signErrorAttrs func() []any) (*hostcert.Renewer, error) {
	hostKeyPath := os.Getenv("SSH_TUNNELD_HOST_KEY")
	if hostKeyPath == "" {
		log.Warn("SSH_TUNNELD_HOST_KEY unset — host cert renewer disabled")
		return nil, nil
	}
	certdURL := os.Getenv("SSH_TUNNELD_CERTD_URL")
	if certdURL == "" {
		return nil, errors.New("SSH_TUNNELD_CERTD_URL is required when SSH_TUNNELD_HOST_KEY is set")
	}

	client, err := certclient.NewClient(certdURL, reloader.CertdTLSConfig())
	if err != nil {
		return nil, fmt.Errorf("certd client: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	keyID := envOr("SSH_TUNNELD_HOST_KEY_ID", "host:"+hostname)
	principals := []string{hostname}
	if raw := os.Getenv("SSH_TUNNELD_HOST_PRINCIPALS"); raw != "" {
		principals = principals[:0]
		for p := range strings.SplitSeq(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				principals = append(principals, p)
			}
		}
	}
	certOut := envOr("SSH_TUNNELD_HOST_CERT", hostKeyPath+"-cert.pub")

	r, err := hostcert.New(hostcert.Config{
		Signer:         client,
		HostKeyPath:    hostKeyPath,
		CertOutputPath: certOut,
		KeyID:          keyID,
		Principals:     principals,
		Log:            log,
		SignErrorAttrs: signErrorAttrs,
	})
	if err != nil {
		return nil, err
	}
	log.Info("host cert renewer configured",
		"key_id", keyID, "principals", principals,
		"host_key", hostKeyPath, "cert_out", certOut)
	return r, nil
}
