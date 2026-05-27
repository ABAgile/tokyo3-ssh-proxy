package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePEMCertKey generates a self-signed ECDSA cert + key and writes
// them to certPath / keyPath. cn becomes both the Subject CN and a
// DNS SAN so VerifyConnection can match it as a hostname. notAfter
// sets the leaf's NotAfter so tests can dial in the remaining-
// validity window.
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

func TestNewTLSReloader_LoadsLeafExpiry(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	want := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	writePEMCertKey(t, certPath, keyPath, "agent", want)
	// CA bundle: re-use the agent's own cert as a trusted CA — the
	// reloader only parses PEM here, no chain check at load time.
	b, _ := os.ReadFile(certPath)
	if err := os.WriteFile(caPath, b, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	r, err := newTLSReloader(certPath, keyPath, caPath, caPath, "proxy.example.com", nil)
	if err != nil {
		t.Fatalf("newTLSReloader: %v", err)
	}
	if got := r.LeafExpiry(); !got.Equal(want) {
		t.Errorf("LeafExpiry = %v, want %v", got, want)
	}
}

// TestTLSReloader_RefreshProxyCAOnMtimeChange asserts the
// mtime-poll path for the proxy bundle. Same shape for the certd
// bundle, but exercising both isn't useful — the helper
// (readPoolIfChanged) is shared.
func TestTLSReloader_RefreshProxyCAOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "agent", time.Now().Add(time.Hour))
	caV1Path := filepath.Join(dir, "ca-v1.pem")
	caV2Path := filepath.Join(dir, "ca-v2.pem")
	writePEMCertKey(t, caV1Path, filepath.Join(dir, "ca-v1.key"), "ca-v1", time.Now().Add(time.Hour))
	writePEMCertKey(t, caV2Path, filepath.Join(dir, "ca-v2.key"), "ca-v2", time.Now().Add(time.Hour))
	caV1, _ := os.ReadFile(caV1Path)
	caV2, _ := os.ReadFile(caV2Path)
	if err := os.WriteFile(caPath, caV1, 0o644); err != nil {
		t.Fatalf("write initial bundle: %v", err)
	}

	r, err := newTLSReloader(certPath, keyPath, caPath, caPath, "proxy", nil)
	if err != nil {
		t.Fatalf("newTLSReloader: %v", err)
	}
	initialMtime := r.proxyCAMtime

	// Unchanged file → no-op.
	if err := r.refreshProxyCA(); err != nil {
		t.Fatalf("refreshProxyCA (unchanged): %v", err)
	}
	if !r.proxyCAMtime.Equal(initialMtime) {
		t.Errorf("proxyCAMtime advanced without file change: %v → %v", initialMtime, r.proxyCAMtime)
	}

	// Drop in an expanded bundle. Sleep so the filesystem records a
	// different mtime (second-granularity filesystems would otherwise
	// collapse two rapid writes onto the same stamp).
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(caPath, append(caV1, caV2...), 0o644); err != nil {
		t.Fatalf("write expanded bundle: %v", err)
	}
	if err := r.refreshProxyCA(); err != nil {
		t.Fatalf("refreshProxyCA (after change): %v", err)
	}
	if !r.proxyCAMtime.After(initialMtime) {
		t.Errorf("proxyCAMtime did not advance: %v → %v", initialMtime, r.proxyCAMtime)
	}
}

// TestTLSReloader_VerifyConnection exercises both per-face
// verifiers end-to-end through a synthesised tls.ConnectionState.
// A peer signed by the bundle CA verifies; one signed outside does
// not. Symmetric for both proxy- and certd-facing configs.
func TestTLSReloader_VerifyConnection(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	proxyCAPath := filepath.Join(dir, "proxy-ca.pem")
	certdCAPath := filepath.Join(dir, "certd-ca.pem")
	writePEMCertKey(t, certPath, keyPath, "agent", time.Now().Add(time.Hour))
	// Use the agent's own cert as a self-trusted CA for the proxy
	// face. Use a separate self-signed cert as the certd-face CA so
	// the two pools are demonstrably distinct.
	b, _ := os.ReadFile(certPath)
	if err := os.WriteFile(proxyCAPath, b, 0o644); err != nil {
		t.Fatalf("write proxy CA: %v", err)
	}
	certdCAPath2 := filepath.Join(dir, "certd-ca-leaf.pem")
	certdCAKeyPath := filepath.Join(dir, "certd-ca.key")
	writePEMCertKey(t, certdCAPath2, certdCAKeyPath, "certd-ca", time.Now().Add(time.Hour))
	certdCABytes, _ := os.ReadFile(certdCAPath2)
	if err := os.WriteFile(certdCAPath, certdCABytes, 0o644); err != nil {
		t.Fatalf("write certd CA: %v", err)
	}

	r, err := newTLSReloader(certPath, keyPath, proxyCAPath, certdCAPath, "agent", nil)
	if err != nil {
		t.Fatalf("newTLSReloader: %v", err)
	}

	proxyCfg := r.ProxyTLSConfig()
	certdCfg := r.CertdTLSConfig()

	// Trusted by proxy pool: the agent's own cert.
	trustedBlock, _ := pem.Decode(b)
	trustedLeaf, _ := x509.ParseCertificate(trustedBlock.Bytes)
	csTrusted := tls.ConnectionState{
		ServerName:       "agent",
		PeerCertificates: []*x509.Certificate{trustedLeaf},
	}
	if err := proxyCfg.VerifyConnection(csTrusted); err != nil {
		t.Errorf("proxy VerifyConnection (trusted): %v", err)
	}
	// Same leaf is NOT trusted by certd pool.
	if err := certdCfg.VerifyConnection(csTrusted); err == nil {
		t.Error("certd VerifyConnection should reject agent's cert (signed outside certd bundle)")
	}

	// Trusted by certd pool: the certd-ca leaf.
	certdBlock, _ := pem.Decode(certdCABytes)
	certdLeaf, _ := x509.ParseCertificate(certdBlock.Bytes)
	csCertdTrusted := tls.ConnectionState{
		ServerName:       "certd-ca",
		PeerCertificates: []*x509.Certificate{certdLeaf},
	}
	if err := certdCfg.VerifyConnection(csCertdTrusted); err != nil {
		t.Errorf("certd VerifyConnection (trusted): %v", err)
	}
	// Same leaf is NOT trusted by proxy pool.
	if err := proxyCfg.VerifyConnection(csCertdTrusted); err == nil {
		t.Error("proxy VerifyConnection should reject certd-ca cert (signed outside proxy bundle)")
	}
}

// TestTLSReloader_LogsOnBundleReload asserts the info log
// operators rely on for rotation coordination fires only when a
// bundle actually swaps. No-op polls stay silent.
func TestTLSReloader_LogsOnBundleReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertKey(t, certPath, keyPath, "agent", time.Now().Add(time.Hour))
	caV1Path := filepath.Join(dir, "ca-v1.pem")
	caV2Path := filepath.Join(dir, "ca-v2.pem")
	writePEMCertKey(t, caV1Path, filepath.Join(dir, "ca-v1.key"), "ca-v1", time.Now().Add(time.Hour))
	writePEMCertKey(t, caV2Path, filepath.Join(dir, "ca-v2.key"), "ca-v2", time.Now().Add(time.Hour))
	caV1, _ := os.ReadFile(caV1Path)
	caV2, _ := os.ReadFile(caV2Path)
	if err := os.WriteFile(caPath, caV1, 0o644); err != nil {
		t.Fatalf("write initial bundle: %v", err)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	r, err := newTLSReloader(certPath, keyPath, caPath, caPath, "agent", log)
	if err != nil {
		t.Fatalf("newTLSReloader: %v", err)
	}
	// Constructor's initial load fires one cert log + two bundle
	// logs (proxy + certd, both pointing at the same file).
	if got := strings.Count(buf.String(), "workload cert reloaded"); got != 1 {
		t.Errorf("workload cert reload count = %d, want 1", got)
	}
	if got := strings.Count(buf.String(), "proxy CA bundle reloaded"); got != 1 {
		t.Errorf("proxy CA reload count = %d, want 1", got)
	}
	if got := strings.Count(buf.String(), "certd CA bundle reloaded"); got != 1 {
		t.Errorf("certd CA reload count = %d, want 1", got)
	}
	wantFP := bundleFingerprint(caV1)
	if !strings.Contains(buf.String(), "fingerprint="+wantFP) {
		t.Errorf("constructor log missing fingerprint=%s; got:\n%s", wantFP, buf.String())
	}

	// No-op polls stay silent.
	buf.Reset()
	if err := r.refreshProxyCA(); err != nil {
		t.Fatalf("refreshProxyCA (no-op): %v", err)
	}
	if err := r.refreshCertdCA(); err != nil {
		t.Fatalf("refreshCertdCA (no-op): %v", err)
	}
	if err := r.refreshCert(); err != nil {
		t.Fatalf("refreshCert (no-op): %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("no-op polls logged: %s", buf.String())
	}

	// Drop in expanded bundle — both proxy + certd reloads log
	// with the new fingerprint, since they share caPath.
	time.Sleep(1100 * time.Millisecond)
	expanded := append(caV1, caV2...)
	if err := os.WriteFile(caPath, expanded, 0o644); err != nil {
		t.Fatalf("write expanded bundle: %v", err)
	}
	if err := r.refreshProxyCA(); err != nil {
		t.Fatalf("refreshProxyCA: %v", err)
	}
	wantFP2 := bundleFingerprint(expanded)
	if !strings.Contains(buf.String(), "fingerprint="+wantFP2) {
		t.Errorf("expected log with fingerprint=%s; got:\n%s", wantFP2, buf.String())
	}
}

// TestTLSReloader_RefreshCertOnMtimeChange asserts the cert mtime
// gate: only re-reads + logs when the file on disk has advanced.
func TestTLSReloader_RefreshCertOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	wantExpiry1 := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	writePEMCertKey(t, certPath, keyPath, "agent", wantExpiry1)
	b, _ := os.ReadFile(certPath)
	if err := os.WriteFile(caPath, b, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	r, err := newTLSReloader(certPath, keyPath, caPath, caPath, "agent", nil)
	if err != nil {
		t.Fatalf("newTLSReloader: %v", err)
	}
	if !r.LeafExpiry().Equal(wantExpiry1) {
		t.Errorf("initial LeafExpiry = %v, want %v", r.LeafExpiry(), wantExpiry1)
	}

	// Same file → no-op.
	if err := r.refreshCert(); err != nil {
		t.Fatalf("refreshCert (no-op): %v", err)
	}
	if !r.LeafExpiry().Equal(wantExpiry1) {
		t.Errorf("LeafExpiry changed after no-op refresh: %v", r.LeafExpiry())
	}

	// New cert with later NotAfter; mtime advances.
	time.Sleep(1100 * time.Millisecond)
	wantExpiry2 := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	writePEMCertKey(t, certPath, keyPath, "agent", wantExpiry2)
	if err := r.refreshCert(); err != nil {
		t.Fatalf("refreshCert: %v", err)
	}
	if !r.LeafExpiry().Equal(wantExpiry2) {
		t.Errorf("after refresh: LeafExpiry = %v, want %v", r.LeafExpiry(), wantExpiry2)
	}
}
