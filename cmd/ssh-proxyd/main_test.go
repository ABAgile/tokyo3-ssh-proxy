package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePEMCertKey generates a self-signed ECDSA cert + key and
// writes them to certPath / keyPath. cn becomes both Subject CN and
// a DNS SAN so the modern x509 verifier finds a hostname match in
// VerifyConnection-style tests.
func writePEMCertKey(t *testing.T, certPath, keyPath, cn string, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// ── buildTunnelServerTLS ────────────────────────────────────────────────────────

// buildTunnelServerTLS now delegates the hot-reload mechanics to
// reloader.ServerTLS (covered by base's own tests). These cases pin the
// env-wiring this binary owns: the master switch, the required-vars check,
// and the mTLS posture (RequireAndVerifyClientCert on the inbound listener).
func TestBuildTunnelServerTLS_DisabledWhenAddrUnset(t *testing.T) {
	t.Setenv("SSH_PROXYD_TUNNEL_ADDR", "")
	cfg, err := buildTunnelServerTLS(nil)
	if err != nil {
		t.Fatalf("buildTunnelServerTLS: %v", err)
	}
	if cfg != nil {
		t.Errorf("cfg = %v, want nil when SSH_PROXYD_TUNNEL_ADDR unset", cfg)
	}
}

func TestBuildTunnelServerTLS_RequiresMaterial(t *testing.T) {
	t.Setenv("SSH_PROXYD_TUNNEL_ADDR", ":2223")
	t.Setenv("SSH_PROXYD_TUNNEL_TLS_CERT", "")
	t.Setenv("SSH_PROXYD_TUNNEL_TLS_KEY", "")
	t.Setenv("SSH_PROXYD_TUNNEL_CLIENT_CA", "")
	t.Setenv("SSH_PROXYD_WORKLOAD_CA", "")
	if _, err := buildTunnelServerTLS(nil); err == nil {
		t.Fatal("expected error when TLS material missing")
	}
}

func TestBuildTunnelServerTLS_RequiresClientCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "ssh-proxyd", time.Now().Add(time.Hour))
	b, _ := os.ReadFile(certPath)
	if err := os.WriteFile(caPath, b, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	t.Setenv("SSH_PROXYD_TUNNEL_ADDR", ":2223")
	t.Setenv("SSH_PROXYD_TUNNEL_TLS_CERT", certPath)
	t.Setenv("SSH_PROXYD_TUNNEL_TLS_KEY", keyPath)
	t.Setenv("SSH_PROXYD_TUNNEL_CLIENT_CA", caPath)

	cfg, err := buildTunnelServerTLS(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildTunnelServerTLS: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil")
	}
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate is nil — server cert not wired")
	}
}
