// Package certclient is the HTTP client ssh-proxyd uses to mint
// short-lived SSH certificates from certd. Each inbound user session
// triggers a SignUserCert call so the proxy can authenticate to the
// target sshd with a cert tied to the original user — rather than a
// long-lived shared client key that every target has to authorize.
//
// Authentication to certd is mTLS: the proxy presents its workload
// identity cert, certd applies its role table (the proxy maps to a
// "ssh-proxy-service" role with broad principal-minting permissions).
// The /api/v1/ssh/sign-user endpoint is the one certd already exposes
// for human cert issuance; the proxy uses the same primitive.
package certclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout caps each HTTP call. certd is on the same private
// network as the proxy; 5s is generous.
const DefaultTimeout = 5 * time.Second

// Client is a thin wrapper around [http.Client] tailored to certd's
// signing endpoints. Safe for concurrent use.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient builds a client for certd at baseURL ("https://certd.example.com").
// tlsCfg supplies the mTLS material — the proxy's client cert + the
// CA bundle that signs certd's server cert. Pass nil tlsCfg to skip
// TLS (test only; production must always use mTLS).
func NewClient(baseURL string, tlsCfg *tls.Config) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("baseURL is required")
	}
	baseURL = strings.TrimRight(baseURL, "/")
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Transport: transport,
			Timeout:   DefaultTimeout,
		},
	}, nil
}

// SignUserRequest mirrors certd's POST /api/v1/ssh/sign-user body.
// Fields match the certd handler — keep in sync when certd's API
// evolves.
type SignUserRequest struct {
	PublicKey       string            `json:"public_key"`
	KeyID           string            `json:"key_id"`
	Principals      []string          `json:"principals"`
	Groups          []string          `json:"groups,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty"`
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	TTLSeconds      int64             `json:"ttl_seconds,omitempty"`
}

// SignUserResponse mirrors certd's response shape.
type SignUserResponse struct {
	Certificate string    `json:"certificate"` // authorized_keys-format cert
	Serial      uint64    `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// SignUserCert calls certd's /api/v1/ssh/sign-user endpoint and
// returns the signed cert (in authorized_keys format) plus its
// validity envelope. ctx caps the call; the HTTP client also enforces
// [DefaultTimeout].
//
// Non-2xx responses are returned as errors with the response body
// surfaced so debugging upstream config issues doesn't require
// breaking out tcpdump.
func (c *Client) SignUserCert(ctx context.Context, req SignUserRequest) (*SignUserResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal sign-user request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/ssh/sign-user", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sign-user http call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read sign-user response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("sign-user returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out SignUserResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode sign-user response: %w", err)
	}
	return &out, nil
}
