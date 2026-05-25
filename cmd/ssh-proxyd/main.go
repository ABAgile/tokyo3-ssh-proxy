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
//	SSH_PROXYD_CLIENT_KEY   Path to a PKCS#8 Ed25519 private key PEM
//	                        the proxy uses to authenticate to target
//	                        sshds (as an SSH client). The pubkey must
//	                        be in each target's authorized_keys for
//	                        the relevant remote user. Later slices
//	                        swap this for per-session certs minted by
//	                        certd.
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
//	SSH_PROXYD_CAST_DIR  Directory where asciinema cast files are
//	                     written, one per recorded session. When
//	                     unset, session recording is disabled — the
//	                     proxy still forwards traffic but produces
//	                     no audit cast files.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/abagile/tokyo3-base/applog"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/spf13/cobra"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
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

	clientSigner, err := loadClientKey()
	if err != nil {
		return fmt.Errorf("client key: %w", err)
	}
	log.Info("target-side client key ready",
		"fingerprint", gossh.FingerprintSHA256(clientSigner.PublicKey()))

	hostKeyCB, err := loadTargetHostKeyCallback(log)
	if err != nil {
		return fmt.Errorf("target host key callback: %w", err)
	}

	sink, err := loadRecordingSink(log)
	if err != nil {
		return fmt.Errorf("recording sink: %w", err)
	}

	srv, err := pssh.New(pssh.Config{
		Addr:                  addr,
		Log:                   log,
		HostSigner:            hostSigner,
		TrustedUserCA:         userCA,
		ClientSigner:          clientSigner,
		TargetHostKeyCallback: hostKeyCB,
		RecordingSink:         sink,
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

// loadClientKey reads the proxy's outbound (target-side) SSH client
// key from SSH_PROXYD_CLIENT_KEY. Required. Accepts both OpenSSH
// format (the ssh-keygen default) and PKCS#8 PEM.
func loadClientKey() (gossh.Signer, error) {
	path := os.Getenv("SSH_PROXYD_CLIENT_KEY")
	if path == "" {
		return nil, errors.New("SSH_PROXYD_CLIENT_KEY is required (Ed25519 private key the proxy authenticates to targets with; OpenSSH or PKCS#8 PEM)")
	}
	return loadSSHPrivateKey(path)
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
