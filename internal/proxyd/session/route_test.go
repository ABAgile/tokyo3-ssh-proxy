package session_test

import (
	"strings"
	"testing"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/session"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in       string
		wantUser string
		wantHost string
		wantErr  string
	}{
		{"alice@db-1.prod.internal", "alice", "db-1.prod.internal", ""},
		{"root@10.0.0.1", "root", "10.0.0.1", ""},
		{"deploy@host-with-dashes", "deploy", "host-with-dashes", ""},

		// Last "@" wins: account-style usernames containing "@" still parse correctly.
		{"alice@CORP.EXAMPLE.COM@db-1", "alice@CORP.EXAMPLE.COM", "db-1", ""},

		{"alice", "", "", `no "@"`},
		{"", "", "", `no "@"`},
		{"@db-1", "", "", "empty remote-user"},
		{"alice@", "", "", "empty target-host"},
		{"@", "", "", "empty remote-user"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			user, host, err := session.ParseTarget(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got none", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q should contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user != tc.wantUser {
				t.Errorf("user = %q, want %q", user, tc.wantUser)
			}
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
		})
	}
}
