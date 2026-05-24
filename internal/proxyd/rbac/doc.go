// Package rbac enforces what the user cert says — the allowed-principals
// list and the host-pattern extension certd embedded at sign time. The
// proxy never reads a policy DB; it trusts the cert's claims and rejects
// session requests that violate them.
package rbac
