// Package routing holds the tunnel registry — the in-memory map from
// host labels and FQDNs to live ssh-tunneld stream IDs — and dispatches
// new session streams to the right tunnel.
package routing
