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
//	SSH_TUNNELD_INSTANCE     Per-host identifier appended to the NATS
//	                         subject and added as an "instance" log
//	                         attribute on every line. Defaults to
//	                         os.Hostname(). Override when hostnames
//	                         aren't stable or distinguishable across
//	                         the fleet (e.g., Kubernetes pod names).
package main

import (
	"context"
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
	"github.com/abagile/tokyo3-base/envutil"
	"github.com/abagile/tokyo3-base/tls/reloader"
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
	log, _, drainLog := applog.AppLoggerWithNATS(applog.Config{
		App:      appName,
		Instance: envutil.Or("SSH_TUNNELD_INSTANCE", envutil.HostnameOrEmpty()),
	}, applog.NATSConfig{
		URL:      os.Getenv("SSH_TUNNELD_NATS_URL"),
		CertFile: envutil.First("SSH_TUNNELD_NATS_CERT", "SSH_TUNNELD_TLS_CERT"),
		KeyFile:  envutil.First("SSH_TUNNELD_NATS_KEY", "SSH_TUNNELD_TLS_KEY"),
		CAFile:   envutil.First("SSH_TUNNELD_NATS_CA", "SSH_TUNNELD_TLS_CA"),
	}, applog.WithStdout())
	defer drainLog()

	proxyAddr := envutil.MustEnv("SSH_TUNNELD_PROXY_ADDR")
	certPath := envutil.MustEnv("SSH_TUNNELD_TLS_CERT")
	keyPath := envutil.MustEnv("SSH_TUNNELD_TLS_KEY")
	proxyCAPath := envutil.MustEnv("SSH_TUNNELD_TLS_CA")
	certdCAPath := envutil.First("SSH_TUNNELD_CERTD_CA", "SSH_TUNNELD_TLS_CA")
	if certdCAPath == "" {
		return errors.New("SSH_TUNNELD_CERTD_CA or SSH_TUNNELD_TLS_CA is required for certd verification")
	}

	r, err := reloader.New(reloader.Config{
		CertPath: certPath,
		KeyPath:  keyPath,
		Pools: map[string]string{
			"proxy": proxyCAPath,
			"certd": certdCAPath,
		},
		PollCert: true,
		Log:      log,
	})
	if err != nil {
		return fmt.Errorf("tls reloader: %w", err)
	}

	// Surface workload-cert remaining validity. The reloader's
	// GetClientCertificate hot-swaps the in-memory cert when an
	// external rotator (cert-agentd, manual replace) updates the
	// file. The 24h warn fires once at startup when the cert is
	// already close to expiry.
	r.WarnIfNearExpiry(24*time.Hour, "workload mTLS cert near expiry — restart ssh-tunneld after the next rotation")

	// Shared closure used by both retry surfaces (dialer + host-cert
	// renewer) so operators see the same field on every failure log.
	workloadRemainingAttrs := r.ExpiryAttrs("workload_cert_remaining")

	localAddr := envutil.Or("SSH_TUNNELD_LOCAL_SSHD", forward.DefaultLocalAddr)
	fwd := forward.New(forward.Config{
		LocalAddr: localAddr,
		Log:       log,
	})
	log.Info("local sshd target configured", "addr", localAddr)

	dialer, err := tunnel.New(tunnel.Config{
		Target:         proxyAddr,
		TLSConfig:      r.TLSConfig("proxy", reloader.WithServerName(resolveProxyServerName(proxyAddr))),
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

	renewer, err := buildHostCertRenewer(log, r, workloadRemainingAttrs)
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
		errCh <- r.RunPoll(rootCtx, reloader.DefaultPollInterval)
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
func buildHostCertRenewer(log *slog.Logger, tlsR *reloader.Reloader, signErrorAttrs func() []any) (*hostcert.Renewer, error) {
	hostKeyPath := os.Getenv("SSH_TUNNELD_HOST_KEY")
	if hostKeyPath == "" {
		log.Warn("SSH_TUNNELD_HOST_KEY unset — host cert renewer disabled")
		return nil, nil
	}
	certdURL := os.Getenv("SSH_TUNNELD_CERTD_URL")
	if certdURL == "" {
		return nil, errors.New("SSH_TUNNELD_CERTD_URL is required when SSH_TUNNELD_HOST_KEY is set")
	}

	client, err := certclient.NewClient(certdURL, tlsR.TLSConfig("certd"))
	if err != nil {
		return nil, fmt.Errorf("certd client: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	keyID := envutil.Or("SSH_TUNNELD_HOST_KEY_ID", "host:"+hostname)
	principals := []string{hostname}
	if raw := os.Getenv("SSH_TUNNELD_HOST_PRINCIPALS"); raw != "" {
		principals = principals[:0]
		for p := range strings.SplitSeq(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				principals = append(principals, p)
			}
		}
	}
	certOut := envutil.Or("SSH_TUNNELD_HOST_CERT", hostKeyPath+"-cert.pub")

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
