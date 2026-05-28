// Package certclient is the HTTP client tokyo3-ssh-proxy components
// use to mint short-lived SSH certificates from certd. ssh-proxyd
// triggers a [Client.SignUserCert] call per inbound session so it can
// authenticate to the target sshd with a cert tied to the original
// user; ssh-tunneld triggers a [Client.SignHostCert] call periodically
// to keep its host cert fresh.
//
// Authentication to certd is mTLS: the caller presents its workload
// identity cert, certd applies its role table (the proxy maps to a
// "ssh-proxy-service" role with broad principal-minting permissions;
// each tunneld instance maps to a "ssh-tunnel-host" role scoped to its
// own host principal). The /api/v1/ssh/sign-user and sign-host
// endpoints are the same primitives certd exposes for human and
// host-key issuance.
package certclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/api"
)

// DefaultTimeout caps each HTTP call. certd is on the same private
// network as the proxy; 5s is generous.
const DefaultTimeout = 5 * time.Second

// Client is a thin wrapper around base/api's Resty client tailored
// to certd's signing endpoints. Safe for concurrent use.
type Client struct {
	api *api.RestyClient
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
	opts := []api.RestyClientOption{api.CO.WithTimeout(DefaultTimeout)}
	if tlsCfg != nil {
		opts = append(opts, api.CO.WithTransport(&http.Transport{TLSClientConfig: tlsCfg}))
	}
	return &Client{api: api.NewRestClient(baseURL, opts...)}, nil
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
// Non-2xx responses surface as wrapped *[api.ApiError] values whose
// Error() string includes the response body so upstream policy
// denial messages land in operator logs without further plumbing.
func (c *Client) SignUserCert(ctx context.Context, req SignUserRequest) (*SignUserResponse, error) {
	var out SignUserResponse
	if err := c.api.R(ctx, http.MethodPost, "/api/v1/ssh/sign-user", &out,
		api.RO.WithBody(req)); err != nil {
		return nil, fmt.Errorf("sign-user: %w", err)
	}
	return &out, nil
}

// SignHostRequest mirrors certd's POST /api/v1/ssh/sign-host body.
// Fields match the certd handler — keep in sync when certd's API
// evolves. Principals are the hostnames the cert is valid for
// (sshd matches the connecting client's destination hostname against
// these). KeyID is recorded in certd's audit log as the issuance
// subject — convention is "host:<hostname>".
type SignHostRequest struct {
	PublicKey  string   `json:"public_key"`
	KeyID      string   `json:"key_id"`
	Principals []string `json:"principals"`
	Groups     []string `json:"groups,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
}

// SignHostResponse mirrors certd's response shape. Structurally
// identical to [SignUserResponse]; kept as a distinct type so callers
// document which signing endpoint they're using and so future
// divergence (e.g., host-only fields) doesn't ripple through user-cert
// consumers.
type SignHostResponse struct {
	Certificate string    `json:"certificate"`
	Serial      uint64    `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

// SignHostCert calls certd's /api/v1/ssh/sign-host endpoint and
// returns the signed host cert (in authorized_keys format) plus its
// validity envelope. Behaves identically to [Client.SignUserCert]
// regarding context, timeouts, and error surfacing.
func (c *Client) SignHostCert(ctx context.Context, req SignHostRequest) (*SignHostResponse, error) {
	var out SignHostResponse
	if err := c.api.R(ctx, http.MethodPost, "/api/v1/ssh/sign-host", &out,
		api.RO.WithBody(req)); err != nil {
		return nil, fmt.Errorf("sign-host: %w", err)
	}
	return &out, nil
}
