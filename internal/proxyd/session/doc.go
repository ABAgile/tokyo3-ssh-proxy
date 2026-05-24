// Package session owns the lifecycle of a single SSH session at the
// proxy — from cert validation through to teardown. Coordinates with
// package routing for tunnel selection, package recording for PTY
// mirroring, and package rbac for cert-extension enforcement.
package session
