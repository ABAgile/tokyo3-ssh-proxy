// Package tunnel is ssh-tunneld's outbound multiplexed tunnel client —
// dials ssh-proxyd over mTLS, negotiates the mux protocol (yamux),
// emits heartbeats, and reconnects with exponential backoff. Streams
// inbound from the proxy are handed off to package forward.
package tunnel
