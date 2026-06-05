package portal_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/portal"
)

func TestNewLocalCastStore_RequiresRoot(t *testing.T) {
	_, err := portal.NewLocalCastStore("")
	if err == nil || !strings.Contains(err.Error(), "cast root is required") {
		t.Errorf("err = %v, want root-required", err)
	}
}

func TestNewLocalCastStore_RejectsMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-subdir")
	_, err := portal.NewLocalCastStore(missing)
	if err == nil {
		t.Error("expected error for missing root")
	}
}

func TestNewLocalCastStore_RejectsFile(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	_ = os.WriteFile(notADir, []byte("x"), 0o644)
	_, err := portal.NewLocalCastStore(notADir)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("err = %v, want not-a-dir rejection", err)
	}
}

func TestLocalCastStore_OpensFileWithinRoot(t *testing.T) {
	root := t.TempDir()
	day := filepath.Join(root, "2026-05-26")
	_ = os.MkdirAll(day, 0o755)
	castPath := filepath.Join(day, "sess-abc.cast")
	body := "{\"version\":2}\n[0.1,\"o\",\"hello\"]\n"
	_ = os.WriteFile(castPath, []byte(body), 0o644)

	store, err := portal.NewLocalCastStore(root)
	if err != nil {
		t.Fatalf("NewLocalCastStore: %v", err)
	}
	rc, size, err := store.Open(castPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
	if size != int64(len(body)) {
		t.Errorf("size = %d, want %d", size, len(body))
	}
	got, _ := io.ReadAll(rc)
	if string(got) != body {
		t.Errorf("body mismatch")
	}
}

func TestLocalCastStore_RejectsPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "evil.cast")
	_ = os.WriteFile(outside, []byte("hax"), 0o644)

	store, _ := portal.NewLocalCastStore(root)
	_, _, err := store.Open(outside)
	if !errors.Is(err, portal.ErrCastOutsideRoot) {
		t.Errorf("err = %v, want ErrCastOutsideRoot", err)
	}
}

func TestLocalCastStore_RejectsTraversal(t *testing.T) {
	root := t.TempDir()
	// "/root/../something" gets cleaned to "/something" by filepath.Abs.
	// Even after filepath.EvalSymlinks, the result lands outside Root.
	parent := filepath.Dir(root)
	target := filepath.Join(parent, "outside.cast")
	_ = os.WriteFile(target, []byte("hax"), 0o644)
	defer os.Remove(target)

	store, _ := portal.NewLocalCastStore(root)
	// Construct a traversal path that, naively joined, looks like
	// it's inside Root.
	traversal := filepath.Join(root, "..", filepath.Base(target))
	_, _, err := store.Open(traversal)
	if !errors.Is(err, portal.ErrCastOutsideRoot) {
		t.Errorf("err = %v, want ErrCastOutsideRoot for traversal", err)
	}
}

func TestLocalCastStore_NotFoundForMissingFile(t *testing.T) {
	root := t.TempDir()
	store, _ := portal.NewLocalCastStore(root)
	_, _, err := store.Open(filepath.Join(root, "ghost.cast"))
	if !errors.Is(err, portal.ErrCastNotFound) {
		t.Errorf("err = %v, want ErrCastNotFound", err)
	}
}

func TestLocalCastStore_NotFoundForEmptyPath(t *testing.T) {
	root := t.TempDir()
	store, _ := portal.NewLocalCastStore(root)
	_, _, err := store.Open("")
	if !errors.Is(err, portal.ErrCastNotFound) {
		t.Errorf("err = %v, want ErrCastNotFound", err)
	}
}

func TestLocalCastStore_RejectsDirectory(t *testing.T) {
	root := t.TempDir()
	day := filepath.Join(root, "2026-05-26")
	_ = os.MkdirAll(day, 0o755)
	store, _ := portal.NewLocalCastStore(root)
	_, _, err := store.Open(day)
	if !errors.Is(err, portal.ErrCastNotFound) {
		t.Errorf("err = %v, want ErrCastNotFound when opening a dir", err)
	}
}

func TestPortal_SessionDetail_RendersAndEmbedsPlayer(t *testing.T) {
	store := &stubSessionStore{sessions: []portal.Session{
		{
			SessionID:     "sess-abc",
			User:          "user:alice",
			Target:        "db-1:22",
			RemoteUser:    "alice",
			RecordingPath: "/var/lib/casts/sess-abc.cast",
			Duration:      4 * time.Second,
			CompletedAt:   time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
		},
	}}
	p, _ := portal.New(portal.Config{
		Version:      "v",
		SessionStore: store,
		CastStore:    &fakeCastStore{body: "header"},
		Now:          time.Now,
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/sessions/sess-abc")
	for _, want := range []string{
		`<h1>Session <code>sess-abc</code></h1>`,
		`asciinema-player`,
		`/sessions/sess-abc/cast`,
		`db-1:22`,
		`alice`,
		`4s`,
		`2026-05-26T12:00:00Z`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_SessionDetail_404ForUnknownID(t *testing.T) {
	p, _ := portal.New(portal.Config{Version: "v", SessionStore: &stubSessionStore{}, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/sessions/ghost")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPortal_SessionDetail_HidesPlayerWhenNoCastStore(t *testing.T) {
	store := &stubSessionStore{sessions: []portal.Session{
		{SessionID: "sess-x", RecordingPath: "/var/lib/casts/x.cast"},
	}}
	p, _ := portal.New(portal.Config{Version: "v", SessionStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/sessions/sess-x")
	if strings.Contains(body, "asciinema-player") {
		t.Errorf("player should not embed without a CastStore:\n%s", body)
	}
	if !strings.Contains(body, "cast store is not configured") {
		t.Errorf("expected the no-store message:\n%s", body)
	}
}

func TestPortal_SessionDetail_HidesPlayerWhenNoRecording(t *testing.T) {
	// PTY-less exec sessions (no recording.completed metadata produced
	// a RecordingPath) should surface the message + skip the player.
	store := &stubSessionStore{sessions: []portal.Session{
		{SessionID: "sess-no-pty", RecordingPath: ""},
	}}
	p, _ := portal.New(portal.Config{
		Version: "v", SessionStore: store, CastStore: &fakeCastStore{}, Now: time.Now,
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/sessions/sess-no-pty")
	if strings.Contains(body, "asciinema-player") {
		t.Errorf("player should not embed when there's no recording:\n%s", body)
	}
	if !strings.Contains(body, "was not PTY-recorded") {
		t.Errorf("expected the no-recording message:\n%s", body)
	}
}

func TestPortal_SessionCast_StreamsCastBytes(t *testing.T) {
	store := &stubSessionStore{sessions: []portal.Session{
		{SessionID: "sess-x", RecordingPath: "/var/lib/casts/x.cast"},
	}}
	cast := &fakeCastStore{body: `{"version":2}` + "\n" + `[0.1,"o","hi"]` + "\n"}
	p, _ := portal.New(portal.Config{Version: "v", SessionStore: store, CastStore: cast, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/sessions/sess-x/cast")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != cast.body {
		t.Errorf("body mismatch:\ngot  %q\nwant %q", string(body), cast.body)
	}
	if cast.wantPath != "/var/lib/casts/x.cast" {
		t.Errorf("cast store saw path %q, want /var/lib/casts/x.cast", cast.wantPath)
	}
}

func TestPortal_SessionCast_404WhenSessionUnknown(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version: "v", SessionStore: &stubSessionStore{}, CastStore: &fakeCastStore{}, Now: time.Now,
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/sessions/ghost/cast")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPortal_SessionCast_403WhenStoreReportsOutsideRoot(t *testing.T) {
	store := &stubSessionStore{sessions: []portal.Session{
		{SessionID: "sess-x", RecordingPath: "/etc/passwd"},
	}}
	cast := &fakeCastStore{err: portal.ErrCastOutsideRoot}
	p, _ := portal.New(portal.Config{Version: "v", SessionStore: store, CastStore: cast, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/sessions/sess-x/cast")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestPortal_SessionCast_503WhenNoCastStore(t *testing.T) {
	store := &stubSessionStore{sessions: []portal.Session{
		{SessionID: "sess-x", RecordingPath: "/x"},
	}}
	p, _ := portal.New(portal.Config{Version: "v", SessionStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/sessions/sess-x/cast")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}
