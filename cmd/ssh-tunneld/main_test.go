package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePEMCertKey generates a self-signed ECDSA cert + key and writes
// them to certPath / keyPath. notAfter sets the leaf's NotAfter so
// tests can dial in the remaining-validity window.
func writePEMCertKey(t *testing.T, certPath, keyPath string, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ssh-tunneld-test"},
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

func TestLoadWorkloadTLS_ReturnsLeafExpiry(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	want := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	writePEMCertKey(t, certPath, keyPath, want)
	// CA bundle: reuse the same cert as a self-trusted CA — the
	// function only parses the PEM, it doesn't verify a chain.
	caPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read CA copy: %v", err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	t.Setenv("SSH_TUNNELD_TLS_CERT", certPath)
	t.Setenv("SSH_TUNNELD_TLS_KEY", keyPath)
	t.Setenv("SSH_TUNNELD_TLS_CA", caPath)

	_, notAfter, err := loadWorkloadTLS("proxy.example.com:9090")
	if err != nil {
		t.Fatalf("loadWorkloadTLS: %v", err)
	}
	if !notAfter.Equal(want) {
		t.Errorf("notAfter = %v, want %v", notAfter, want)
	}
}
