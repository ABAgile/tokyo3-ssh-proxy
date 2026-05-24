// Package certclient is a thin wrapper around the certd HTTP client
// (imported from github.com/abagile/tokyo3-ca/internal/client) that
// adds ssh-proxy-specific concerns — request signing for per-session
// cert minting, host-cert renewal calls, and retry/backoff defaults.
package certclient
