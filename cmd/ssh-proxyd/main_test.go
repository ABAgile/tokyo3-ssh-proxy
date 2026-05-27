package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

// ── certdClientReloader ───────────────────────────────────────────────────────

func TestCertdClientReloader_LoadsLeafExpiry(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	want := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	writePEMCertKey(t, certPath, keyPath, "ssh-proxyd", want)
	b, _ := os.ReadFile(certPath)
	if err := os.WriteFile(caPath, b, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	r, err := newCertdClientReloader(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("newCertdClientReloader: %v", err)
	}
	if got := r.LeafExpiry(); !got.Equal(want) {
		t.Errorf("LeafExpiry = %v, want %v", got, want)
	}
}

func TestCertdClientReloader_FallsBackToSystemPoolWhenCAPathEmpty(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writePEMCertKey(t, certPath, keyPath, "ssh-proxyd", time.Now().Add(time.Hour))

	r, err := newCertdClientReloader(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("newCertdClientReloader (empty CA): %v", err)
	}
	// Non-nil pool — populated from x509.SystemCertPool. Can't
	// inspect contents portably, but a populated pool proves the
	// fallback path was taken.
	if r.pool == nil {
		t.Error("pool should be set to system pool when caPath is empty")
	}
}

func TestCertdClientReloader_VerifyConnection(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "ssh-proxyd", time.Now().Add(time.Hour))
	// Trusted CA bundle: the agent's own self-signed cert.
	b, _ := os.ReadFile(certPath)
	if err := os.WriteFile(caPath, b, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	r, err := newCertdClientReloader(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("newCertdClientReloader: %v", err)
	}

	trustedBlock, _ := pem.Decode(b)
	trustedLeaf, _ := x509.ParseCertificate(trustedBlock.Bytes)
	cs := tls.ConnectionState{
		ServerName:       "ssh-proxyd",
		PeerCertificates: []*x509.Certificate{trustedLeaf},
	}
	if err := r.VerifyConnection(cs); err != nil {
		t.Errorf("VerifyConnection (trusted): %v", err)
	}

	// Untrusted peer: a fresh self-signed cert not in the bundle.
	otherCertPath := filepath.Join(dir, "other.pem")
	otherKeyPath := filepath.Join(dir, "other.key")
	writePEMCertKey(t, otherCertPath, otherKeyPath, "ssh-proxyd", time.Now().Add(time.Hour))
	otherPEM, _ := os.ReadFile(otherCertPath)
	otherBlock, _ := pem.Decode(otherPEM)
	otherLeaf, _ := x509.ParseCertificate(otherBlock.Bytes)
	cs.PeerCertificates = []*x509.Certificate{otherLeaf}
	if err := r.VerifyConnection(cs); err == nil {
		t.Error("VerifyConnection (untrusted) should reject peer signed outside bundle")
	}
}

func TestCertdClientReloader_RefreshCABundleOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "ssh-proxyd", time.Now().Add(time.Hour))
	caV1Path := filepath.Join(dir, "ca-v1.pem")
	caV2Path := filepath.Join(dir, "ca-v2.pem")
	writePEMCertKey(t, caV1Path, filepath.Join(dir, "ca-v1.key"), "ca-v1", time.Now().Add(time.Hour))
	writePEMCertKey(t, caV2Path, filepath.Join(dir, "ca-v2.key"), "ca-v2", time.Now().Add(time.Hour))
	caV1, _ := os.ReadFile(caV1Path)
	caV2, _ := os.ReadFile(caV2Path)
	if err := os.WriteFile(caPath, caV1, 0o644); err != nil {
		t.Fatalf("write initial bundle: %v", err)
	}

	r, err := newCertdClientReloader(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("newCertdClientReloader: %v", err)
	}
	initial := r.caMtime

	if err := r.refreshCABundle(); err != nil {
		t.Fatalf("refreshCABundle (unchanged): %v", err)
	}
	if !r.caMtime.Equal(initial) {
		t.Errorf("caMtime advanced without change: %v → %v", initial, r.caMtime)
	}

	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(caPath, append(caV1, caV2...), 0o644); err != nil {
		t.Fatalf("write expanded bundle: %v", err)
	}
	if err := r.refreshCABundle(); err != nil {
		t.Fatalf("refreshCABundle (after change): %v", err)
	}
	if !r.caMtime.After(initial) {
		t.Errorf("caMtime did not advance: %v → %v", initial, r.caMtime)
	}
}

// ── tunnelServerReloader ──────────────────────────────────────────────────────

func TestTunnelServerReloader_ServerConfigForClient(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "ssh-proxyd", time.Now().Add(time.Hour))
	b, _ := os.ReadFile(certPath)
	if err := os.WriteFile(caPath, b, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	r, err := newTunnelServerReloader(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("newTunnelServerReloader: %v", err)
	}
	cfg, err := r.serverConfigForClient(nil)
	if err != nil {
		t.Fatalf("serverConfigForClient: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates len = %d, want 1", len(cfg.Certificates))
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil")
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
}

func TestTunnelServerReloader_RefreshClientCAsOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "ssh-proxyd", time.Now().Add(time.Hour))
	caV1Path := filepath.Join(dir, "ca-v1.pem")
	caV2Path := filepath.Join(dir, "ca-v2.pem")
	writePEMCertKey(t, caV1Path, filepath.Join(dir, "ca-v1.key"), "ca-v1", time.Now().Add(time.Hour))
	writePEMCertKey(t, caV2Path, filepath.Join(dir, "ca-v2.key"), "ca-v2", time.Now().Add(time.Hour))
	caV1, _ := os.ReadFile(caV1Path)
	caV2, _ := os.ReadFile(caV2Path)
	if err := os.WriteFile(caPath, caV1, 0o644); err != nil {
		t.Fatalf("write initial bundle: %v", err)
	}

	r, err := newTunnelServerReloader(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("newTunnelServerReloader: %v", err)
	}
	initial := r.clientCAMtime

	if err := r.refreshClientCAs(); err != nil {
		t.Fatalf("refreshClientCAs (unchanged): %v", err)
	}
	if !r.clientCAMtime.Equal(initial) {
		t.Errorf("clientCAMtime advanced without change: %v → %v", initial, r.clientCAMtime)
	}

	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(caPath, append(caV1, caV2...), 0o644); err != nil {
		t.Fatalf("write expanded bundle: %v", err)
	}
	if err := r.refreshClientCAs(); err != nil {
		t.Fatalf("refreshClientCAs (after change): %v", err)
	}
	if !r.clientCAMtime.After(initial) {
		t.Errorf("clientCAMtime did not advance: %v → %v", initial, r.clientCAMtime)
	}
}
