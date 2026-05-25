package recording_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/recording"
)

func TestNewLocalDirSink_RejectsEmptyRoot(t *testing.T) {
	_, err := recording.NewLocalDirSink("")
	if err == nil || !strings.Contains(err.Error(), "root is required") {
		t.Errorf("err = %v, want 'root is required'", err)
	}
}

func TestNewLocalDirSink_CreatesRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "casts")
	sink, err := recording.NewLocalDirSink(root)
	if err != nil {
		t.Fatalf("NewLocalDirSink: %v", err)
	}
	info, err := os.Stat(sink.Root())
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("Root is not a directory")
	}
}

func TestLocalDirSink_OpenCast_WritesUnderDayDir(t *testing.T) {
	sink, _ := recording.NewLocalDirSink(t.TempDir())
	started := time.Date(2026, 5, 25, 14, 30, 0, 0, time.UTC)
	wc, _, err := sink.OpenCast(context.Background(), recording.CastMeta{
		SessionID: "abc-123",
		User:      "alice",
		Target:    "db-1",
		Started:   started,
	})
	if err != nil {
		t.Fatalf("OpenCast: %v", err)
	}
	if _, err := io.WriteString(wc, "header\n[0.1,\"o\",\"hello\"]\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := wc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	want := filepath.Join(sink.Root(), "2026-05-25", "abc-123.cast")
	contents, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read back cast file: %v", err)
	}
	if !strings.Contains(string(contents), `"o","hello"`) {
		t.Errorf("cast file contents = %q", string(contents))
	}

	// Mode is 0600 — audit data.
	info, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o, want 0600", mode)
	}
}

func TestLocalDirSink_OpenCast_SanitizesSessionID(t *testing.T) {
	sink, _ := recording.NewLocalDirSink(t.TempDir())
	wc, _, err := sink.OpenCast(context.Background(), recording.CastMeta{
		SessionID: "../etc/passwd",
		Started:   time.Now(),
	})
	if err != nil {
		t.Fatalf("OpenCast: %v", err)
	}
	defer wc.Close()
	// Should never escape the root.
	entries, _ := os.ReadDir(filepath.Dir(sink.Root()))
	for _, e := range entries {
		if e.Name() == "passwd" {
			t.Error("session ID escaped sink root")
		}
	}
}

func TestLocalDirSink_OpenCast_RejectsMissingSessionID(t *testing.T) {
	sink, _ := recording.NewLocalDirSink(t.TempDir())
	_, _, err := sink.OpenCast(context.Background(), recording.CastMeta{})
	if err == nil || !strings.Contains(err.Error(), "SessionID is required") {
		t.Errorf("err = %v, want 'SessionID is required'", err)
	}
}

func TestLocalDirSink_OpenCast_RejectsDuplicateID(t *testing.T) {
	// Two sessions with the same SessionID in the same day → second
	// OpenCast errors (O_EXCL) so we don't silently overwrite an
	// existing audit record.
	sink, _ := recording.NewLocalDirSink(t.TempDir())
	meta := recording.CastMeta{SessionID: "dup", Started: time.Now()}
	wc1, _, err := sink.OpenCast(context.Background(), meta)
	if err != nil {
		t.Fatalf("first OpenCast: %v", err)
	}
	_ = wc1.Close()
	_, _, err = sink.OpenCast(context.Background(), meta)
	if err == nil {
		t.Fatal("second OpenCast with same SessionID/day succeeded; want O_EXCL refusal")
	}
}

func TestNopSink_DiscardsWrites(t *testing.T) {
	wc, loc, err := (recording.NopSink{}).OpenCast(context.Background(), recording.CastMeta{SessionID: "x"})
	if err != nil {
		t.Fatalf("OpenCast: %v", err)
	}
	if loc != "" {
		t.Errorf("NopSink location = %q, want empty", loc)
	}
	if _, err := io.WriteString(wc, "ignored"); err != nil {
		t.Errorf("write: %v", err)
	}
	if err := wc.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}
