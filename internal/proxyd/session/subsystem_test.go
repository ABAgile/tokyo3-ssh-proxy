package session

import (
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestDetectSubsystem_SCPExec(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		wantOK  bool
		wantCmd string
	}{
		{"scp -t", "scp -t /tmp/foo", true, "scp -t /tmp/foo"},
		{"scp -f", "scp -f /tmp/foo", true, "scp -f /tmp/foo"},
		{"scp bare", "scp", true, "scp"},
		{"scp tab", "scp\tfoo", true, "scp\tfoo"},
		{"trailing ws is trimmed", "  scp -t x  ", true, "scp -t x"},
		{"non-scp exec", "ls -la /tmp", false, ""},
		{"scp-prefix not at boundary", "scpfoo", false, ""},
		{"empty", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &gossh.Request{
				Type:    "exec",
				Payload: gossh.Marshal(struct{ Command string }{tc.cmd}),
			}
			kind, gotCmd, ok := detectSubsystem(req)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if kind != subsystemSCP {
				t.Errorf("kind = %q, want scp", kind)
			}
			if gotCmd != tc.wantCmd {
				t.Errorf("command = %q, want %q", gotCmd, tc.wantCmd)
			}
		})
	}
}

func TestDetectSubsystem_SFTPSubsystem(t *testing.T) {
	req := &gossh.Request{
		Type:    "subsystem",
		Payload: gossh.Marshal(struct{ Name string }{"sftp"}),
	}
	kind, cmd, ok := detectSubsystem(req)
	if !ok {
		t.Fatal("expected sftp detection")
	}
	if kind != subsystemSFTP {
		t.Errorf("kind = %q, want sftp", kind)
	}
	if cmd != "" {
		t.Errorf("command = %q, want empty (sftp has no command tail)", cmd)
	}
}

func TestDetectSubsystem_OtherSubsystemIgnored(t *testing.T) {
	req := &gossh.Request{
		Type:    "subsystem",
		Payload: gossh.Marshal(struct{ Name string }{"netconf"}),
	}
	if _, _, ok := detectSubsystem(req); ok {
		t.Error("non-sftp subsystems should not be detected as file-transfer")
	}
}

func TestDetectSubsystem_OtherRequestTypesIgnored(t *testing.T) {
	for _, typ := range []string{"pty-req", "window-change", "shell", "env"} {
		req := &gossh.Request{Type: typ, Payload: nil}
		if _, _, ok := detectSubsystem(req); ok {
			t.Errorf("%q should not match", typ)
		}
	}
}

func TestDetectSubsystem_MalformedPayload(t *testing.T) {
	// gossh.Unmarshal rejects payloads it can't decode — the
	// detector must return false rather than panicking.
	req := &gossh.Request{Type: "exec", Payload: []byte{0x00, 0x01}} // too short for the length prefix
	if _, _, ok := detectSubsystem(req); ok {
		t.Error("malformed payload should not be detected")
	}
}
