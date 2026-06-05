package portal

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
)

// BasicAuthConfig wires the optional HTTP Basic auth gate. When
// either field is empty, the portal stays open — operators front it
// with oauth2-proxy, an mTLS reverse proxy, or another identity-aware
// edge instead.
//
// Production single-user deployments are the target: an admin sets
// the credentials in deployment secrets and the browser carries them
// after the first 401 challenge. Multi-user / role-aware auth is a
// follow-up.
type BasicAuthConfig struct {
	// Username is the only accepted login. Empty disables the gate.
	Username string

	// Password is the corresponding secret. Empty disables the gate.
	Password string

	// Realm is the value sent in the WWW-Authenticate header on
	// rejection. Empty ⇒ "ssh-proxyd portal".
	Realm string
}

// enabled reports whether the gate is configured. Returns false when
// either credential is empty so accidental misconfiguration doesn't
// silently lock everyone out.
func (c BasicAuthConfig) enabled() bool {
	return c.Username != "" && c.Password != ""
}

// requireBasicAuth wraps next with an HTTP Basic gate. When the
// config is disabled, returns next unchanged. When enabled, every
// request must present the configured Username + Password (constant-
// time compare on a sha256 digest of each side — equal-length
// inputs to subtle.ConstantTimeCompare regardless of attacker
// guess length).
//
// The /healthz endpoint is exempt so external watchdogs can probe
// the portal without sharing the admin credentials.
func requireBasicAuth(cfg BasicAuthConfig, next http.Handler) http.Handler {
	if !cfg.enabled() {
		return next
	}
	realm := cfg.Realm
	if realm == "" {
		realm = "ssh-proxyd portal"
	}
	// Pre-hash the expected credentials once so each request avoids
	// re-hashing the configured secret.
	wantUser := sha256.Sum256([]byte(cfg.Username))
	wantPass := sha256.Sum256([]byte(cfg.Password))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			challenge(w, realm)
			return
		}
		gotUser := sha256.Sum256([]byte(user))
		gotPass := sha256.Sum256([]byte(pass))
		userOK := subtle.ConstantTimeCompare(gotUser[:], wantUser[:])
		passOK := subtle.ConstantTimeCompare(gotPass[:], wantPass[:])
		if userOK&passOK != 1 {
			challenge(w, realm)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// challenge returns 401 with the WWW-Authenticate header so browsers
// pop their credential prompt and curl/CI know to retry with -u.
func challenge(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}
