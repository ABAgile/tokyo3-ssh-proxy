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

	"github.com/abagile/tokyo3-base/applog"
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
	log, _ := applog.AppLogger(appName, applog.WithStdout())

	proxyAddr := mustEnv("SSH_TUNNELD_PROXY_ADDR")
	tlsCfg, err := loadWorkloadTLS(proxyAddr)
	if err != nil {
		return fmt.Errorf("workload tls: %w", err)
	}

	localAddr := envOr("SSH_TUNNELD_LOCAL_SSHD", forward.DefaultLocalAddr)
	fwd := forward.New(forward.Config{
		LocalAddr: localAddr,
		Log:       log,
	})
	log.Info("local sshd target configured", "addr", localAddr)

	dialer, err := tunnel.New(tunnel.Config{
		Target:    proxyAddr,
		TLSConfig: tlsCfg,
		Handler:   fwd.Handle,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("dialer: %w", err)
	}
	log.Info("tunnel dialer configured", "proxy", proxyAddr)

	rootCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	renewer, err := buildHostCertRenewer(log, tlsCfg)
	if err != nil {
		return fmt.Errorf("host cert renewer: %w", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- dialer.Run(rootCtx)
	}()

	if renewer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- renewer.Run(rootCtx)
		}()
	}

	// Wait for first component exit; cancel to bring the other down.
	first := <-errCh
	cancel()
	go func() {
		// Drain remaining errors so the goroutines can finish.
		for range cap(errCh) - 1 {
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

// loadWorkloadTLS builds the *tls.Config the dialer presents to
// ssh-proxyd's tunnel listener. Caller identity comes from the
// workload cert (SPIFFE URI); the CA bundle verifies the proxy's
// server cert. ServerName defaults to the host portion of proxyAddr
// but can be overridden when DNS doesn't match the cert's
// presented SAN.
func loadWorkloadTLS(proxyAddr string) (*tls.Config, error) {
	certFile := mustEnv("SSH_TUNNELD_TLS_CERT")
	keyFile := mustEnv("SSH_TUNNELD_TLS_KEY")
	caFile := mustEnv("SSH_TUNNELD_TLS_CA")

	keyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load workload cert pair: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA %s contains no PEM certs", caFile)
	}

	serverName := os.Getenv("SSH_TUNNELD_PROXY_SERVER_NAME")
	if serverName == "" {
		host, _, splitErr := net.SplitHostPort(proxyAddr)
		if splitErr != nil {
			serverName = proxyAddr
		} else {
			serverName = host
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// buildHostCertRenewer returns a configured renewer when
// SSH_TUNNELD_HOST_KEY is set; otherwise nil so the caller skips the
// renewal goroutine. Reuses the workload mTLS config (workloadTLS)
// for the certd HTTP client when SSH_TUNNELD_CERTD_CA is unset.
func buildHostCertRenewer(log *slog.Logger, workloadTLS *tls.Config) (*hostcert.Renewer, error) {
	hostKeyPath := os.Getenv("SSH_TUNNELD_HOST_KEY")
	if hostKeyPath == "" {
		log.Warn("SSH_TUNNELD_HOST_KEY unset — host cert renewer disabled")
		return nil, nil
	}
	certdURL := os.Getenv("SSH_TUNNELD_CERTD_URL")
	if certdURL == "" {
		return nil, errors.New("SSH_TUNNELD_CERTD_URL is required when SSH_TUNNELD_HOST_KEY is set")
	}

	certdTLS, err := loadCertdMTLS(workloadTLS)
	if err != nil {
		return nil, err
	}
	client, err := certclient.NewClient(certdURL, certdTLS)
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
		for _, p := range strings.Split(raw, ",") {
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
	})
	if err != nil {
		return nil, err
	}
	log.Info("host cert renewer configured",
		"key_id", keyID, "principals", principals,
		"host_key", hostKeyPath, "cert_out", certOut)
	return r, nil
}

// loadCertdMTLS returns a *tls.Config for the certd HTTP client.
// Reuses the workload mTLS Certificates so a single workload identity
// authenticates to both the proxy and certd. The CA bundle may be
// overridden via SSH_TUNNELD_CERTD_CA when certd's server cert is
// signed by a different CA than the proxy's.
func loadCertdMTLS(workloadTLS *tls.Config) (*tls.Config, error) {
	caFile := envFirst("SSH_TUNNELD_CERTD_CA", "SSH_TUNNELD_TLS_CA")
	if caFile == "" {
		return nil, errors.New("SSH_TUNNELD_CERTD_CA or SSH_TUNNELD_TLS_CA is required for certd verification")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read certd CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("certd CA %s contains no PEM certs", caFile)
	}
	return &tls.Config{
		Certificates: workloadTLS.Certificates,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
