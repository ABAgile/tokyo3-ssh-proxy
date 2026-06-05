package portal_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/portal"
)

func newTestPortal(t *testing.T) *portal.Server {
	t.Helper()
	p, err := portal.New(portal.Config{
		Version: "v0.0.1-test",
		Now:     func() time.Time { return time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("portal.New: %v", err)
	}
	return p
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	return readAll(t, resp)
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf)
}

// stubSessionStore is the read-only portal.SessionStore test double.
type stubSessionStore struct{ sessions []portal.Session }

func (s *stubSessionStore) Sessions() []portal.Session { return s.sessions }

// mockSource is a minimal journal.Source: tests push payloads onto
// out; Subscribe returns out so the tracker's goroutine sees them.
// Close is a no-op.
type mockSource struct {
	out chan journal.Msg
}

func newMockSource() *mockSource {
	return &mockSource{out: make(chan journal.Msg, 16)}
}

func (m *mockSource) Subscribe(_ context.Context, _ int, _ uint64) (<-chan journal.Msg, error) {
	return m.out, nil
}

func (m *mockSource) Close() error { return nil }

// pushEntry serializes a recording.completed entry shape and pushes
// it onto the mock source. The shape matches what ssh-proxy's
// internal/audit.Entry JSON-encodes.
func pushEntry(t *testing.T, src *mockSource, action, sessionID, user, target, remoteUser, recordingPath string, durationSec float64, when time.Time) {
	t.Helper()
	md, _ := json.Marshal(map[string]any{"duration_seconds": durationSec})
	payload, _ := json.Marshal(map[string]any{
		"action":         action,
		"session_id":     sessionID,
		"user":           user,
		"target":         target,
		"remote_user":    remoteUser,
		"recording_path": recordingPath,
		"metadata":       string(md),
		"occurred_at":    when,
	})
	src.out <- journal.Msg{Seq: 1, Time: when, Data: payload}
}

// fakeCastStore lets tests assert on which path the handler asked
// for without touching the filesystem.
type fakeCastStore struct {
	wantPath string
	body     string
	err      error
}

func (s *fakeCastStore) Open(p string) (io.ReadCloser, int64, error) {
	if s.err != nil {
		return nil, 0, s.err
	}
	s.wantPath = p
	return io.NopCloser(strings.NewReader(s.body)), int64(len(s.body)), nil
}

// itoa is a tiny replacement for strconv.Itoa so the test files'
// import surface stays tight.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
