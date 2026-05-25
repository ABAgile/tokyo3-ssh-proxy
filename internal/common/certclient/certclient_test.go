package certclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ssh-proxy/internal/common/certclient"
)

// mockCertd stands in for the certd service: it accepts POST
// /api/v1/ssh/sign-user, captures the request for assertions, and
// returns a canned response (or status code) configured by the test.
type mockCertd struct {
	server *httptest.Server

	gotReq    certclient.SignUserRequest
	respCode  int
	respBody  []byte
	respDelay time.Duration
}

func newMockCertd(t *testing.T) *mockCertd {
	t.Helper()
	m := &mockCertd{respCode: http.StatusOK}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/ssh/sign-user" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&m.gotReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if m.respDelay > 0 {
			time.Sleep(m.respDelay)
		}
		w.WriteHeader(m.respCode)
		_, _ = w.Write(m.respBody)
	}))
	t.Cleanup(m.server.Close)
	return m
}

// respond sets the canned response body for mockCertd. Pass any value
// JSON-marshalable as the body.
func (m *mockCertd) respond(t *testing.T, status int, body any) {
	t.Helper()
	m.respCode = status
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal mock response: %v", err)
	}
	m.respBody = b
}

func TestNewClient_RejectsEmptyBaseURL(t *testing.T) {
	_, err := certclient.NewClient("", nil)
	if err == nil || !strings.Contains(err.Error(), "baseURL is required") {
		t.Errorf("err = %v, want 'baseURL is required'", err)
	}
}

func TestClient_SignUserCert_HappyPath(t *testing.T) {
	m := newMockCertd(t)
	now := time.Date(2026, 5, 25, 13, 0, 0, 0, time.UTC)
	m.respond(t, http.StatusOK, certclient.SignUserResponse{
		Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA...",
		Serial:      42,
		KeyID:       "session:abc-123:user:alice@example.com",
		Principals:  []string{"alice"},
		ValidAfter:  now,
		ValidBefore: now.Add(5 * time.Minute),
	})

	client, err := certclient.NewClient(m.server.URL, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req := certclient.SignUserRequest{
		PublicKey:  "ssh-ed25519 AAAA...",
		KeyID:      "session:abc-123:user:alice@example.com",
		Principals: []string{"alice"},
		TTLSeconds: 300,
	}
	resp, err := client.SignUserCert(context.Background(), req)
	if err != nil {
		t.Fatalf("SignUserCert: %v", err)
	}
	if resp.Serial != 42 {
		t.Errorf("Serial = %d, want 42", resp.Serial)
	}
	if resp.KeyID != "session:abc-123:user:alice@example.com" {
		t.Errorf("KeyID = %q", resp.KeyID)
	}
	if !strings.HasPrefix(resp.Certificate, "ssh-ed25519-cert-v01@openssh.com") {
		t.Errorf("Certificate = %q", resp.Certificate)
	}

	// And the request body that hit certd matches what we sent.
	if m.gotReq.KeyID != req.KeyID {
		t.Errorf("server saw KeyID = %q, want %q", m.gotReq.KeyID, req.KeyID)
	}
	if m.gotReq.TTLSeconds != 300 {
		t.Errorf("server saw TTL = %d, want 300", m.gotReq.TTLSeconds)
	}
}

func TestClient_SignUserCert_PropagatesUpstreamError(t *testing.T) {
	m := newMockCertd(t)
	m.respond(t, http.StatusForbidden, map[string]string{
		"error": "no role matches the caller's groups",
	})

	client, _ := certclient.NewClient(m.server.URL, nil)
	_, err := client.SignUserCert(context.Background(), certclient.SignUserRequest{
		PublicKey: "ssh-ed25519 AAAA", KeyID: "k", Principals: []string{"alice"},
	})
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should contain status code: %v", err)
	}
	if !strings.Contains(err.Error(), "no role matches") {
		t.Errorf("error should surface the upstream body: %v", err)
	}
}

func TestClient_SignUserCert_RespectsContextCancellation(t *testing.T) {
	m := newMockCertd(t)
	m.respDelay = 200 * time.Millisecond
	m.respond(t, http.StatusOK, certclient.SignUserResponse{Serial: 1})

	client, _ := certclient.NewClient(m.server.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := client.SignUserCert(ctx, certclient.SignUserRequest{
		PublicKey: "ssh-ed25519 AAAA", KeyID: "k", Principals: []string{"alice"},
	})
	if err == nil {
		t.Fatal("expected context-cancelled error")
	}
	if !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("error should mention context/deadline: %v", err)
	}
}

func TestClient_SignUserCert_RejectsMalformedResponse(t *testing.T) {
	m := newMockCertd(t)
	m.respCode = http.StatusOK
	m.respBody = []byte("not json")

	client, _ := certclient.NewClient(m.server.URL, nil)
	_, err := client.SignUserCert(context.Background(), certclient.SignUserRequest{
		PublicKey: "ssh-ed25519 AAAA", KeyID: "k", Principals: []string{"alice"},
	})
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode error, got %v", err)
	}
}
