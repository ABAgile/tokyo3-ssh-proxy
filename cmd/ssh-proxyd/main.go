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
//	SSH_PROXYD_USER_CA   Path to the SSH user CA public key in
//	                     authorized_keys format (e.g., the contents of
//	                     `ssh-ed25519 AAAA… tokyo3-ca`). Without this,
//	                     ssh-proxyd has no idea which user certs to
//	                     trust and refuses to start.
//
// Optional env vars:
//
//	SSH_PROXYD_ADDR      TCP listen address (default ":2222").
//	SSH_PROXYD_HOST_KEY  Path to a PKCS#8 Ed25519 private key PEM used
//	                     as the proxy's SSH host key. When unset,
//	                     ssh-proxyd generates an ephemeral key at
//	                     startup — dev only; clients will see a
//	                     different host key after every restart.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/abagile/tokyo3-base/applog"
	gossh "golang.org/x/crypto/ssh"

	"github.com/spf13/cobra"

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

	srv, err := pssh.New(pssh.Config{
		Addr:          addr,
		Log:           log,
		HostSigner:    hostSigner,
		TrustedUserCA: userCA,
	})
	if err != nil {
		return fmt.Errorf("ssh server: %w", err)
	}

	rootCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.ListenAndServe(rootCtx); err != nil {
		return fmt.Errorf("serve: %w", err)
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

// loadHostKey returns the SSH host signer. When SSH_PROXYD_HOST_KEY
// is set, the file is read as a PKCS#8 Ed25519 PEM block; otherwise
// an ephemeral keypair is generated at startup with a warning.
func loadHostKey(log *slog.Logger) (gossh.Signer, error) {
	if path := os.Getenv("SSH_PROXYD_HOST_KEY"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("%s does not contain a PEM block", path)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: expected ed25519 private key, got %T", path, key)
		}
		signer, err := gossh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("wrap host key as ssh.Signer: %w", err)
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
