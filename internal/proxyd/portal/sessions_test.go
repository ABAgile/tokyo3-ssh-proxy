package portal_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/portal"
)

func TestNewSessionTracker_RequiresSource(t *testing.T) {
	_, err := portal.NewSessionTracker(portal.SessionTrackerConfig{})
	if err == nil || !strings.Contains(err.Error(), "source is required") {
		t.Errorf("err = %v, want source-required", err)
	}
}

func TestSessionTracker_IngestsRecordingCompleted(t *testing.T) {
	src := newMockSource()
	tracker, err := portal.NewSessionTracker(portal.SessionTrackerConfig{Source: src})
	if err != nil {
		t.Fatalf("NewSessionTracker: %v", err)
	}
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	when := time.Date(2026, 5, 26, 13, 0, 0, 0, time.UTC)
	pushEntry(t, src, "ssh.recording.completed",
		"sess-abc", "user:alice@example.com", "db-1.prod:22", "alice",
		"/var/lib/ssh-proxyd/casts/2026-05-26/sess-abc.cast",
		12.5, when)

	// Poll for ingest — the tracker decodes on the subscriber goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := tracker.Sessions(); len(got) == 1 {
			s := got[0]
			if s.SessionID != "sess-abc" {
				t.Errorf("SessionID = %q", s.SessionID)
			}
			if s.User != "user:alice@example.com" {
				t.Errorf("User = %q", s.User)
			}
			if s.Target != "db-1.prod:22" {
				t.Errorf("Target = %q", s.Target)
			}
			if s.RemoteUser != "alice" {
				t.Errorf("RemoteUser = %q", s.RemoteUser)
			}
			if s.RecordingPath == "" || !strings.HasSuffix(s.RecordingPath, "sess-abc.cast") {
				t.Errorf("RecordingPath = %q", s.RecordingPath)
			}
			if d := s.Duration; d < 12*time.Second || d > 13*time.Second {
				t.Errorf("Duration = %v, want ~12.5s", d)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker never ingested the recording.completed event; sessions=%v", tracker.Sessions())
}

func TestSessionTracker_IgnoresOtherActions(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewSessionTracker(portal.SessionTrackerConfig{Source: src})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	pushEntry(t, src, "ssh.session.opened", "sess-1", "user:x", "host:22", "alice", "", 0, time.Now())
	pushEntry(t, src, "ssh.channel.rejected", "sess-2", "user:y", "host:22", "alice", "", 0, time.Now())
	time.Sleep(50 * time.Millisecond)
	if got := len(tracker.Sessions()); got != 0 {
		t.Errorf("Sessions len = %d, want 0 (non-recording.completed actions should be ignored)", got)
	}
}

func TestSessionTracker_BoundedByMaxSessions(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewSessionTracker(portal.SessionTrackerConfig{Source: src, MaxSessions: 3})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	for i := range 6 {
		pushEntry(t, src, "ssh.recording.completed",
			"sess-"+itoa(i), "u", "h:22", "alice", "/cast", 1, time.Now())
	}
	// Wait for the LAST-pushed event to surface at the head of the
	// ring. Polling on len(Sessions()) >= 3 races: the slice hits 3
	// after sess-2 ingests but before sess-3/4/5 do, so the test can
	// observe a stale newest=sess-2 head. Pinning on sess-5 means we
	// only continue once the producer side is fully drained.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := tracker.Sessions()
		if len(got) > 0 && got[0].SessionID == "sess-5" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := tracker.Sessions()
	if len(got) != 3 {
		t.Errorf("Sessions len = %d, want 3 (bounded by MaxSessions)", len(got))
	}
	// Newest-first: the last-pushed event ("sess-5") leads.
	if got[0].SessionID != "sess-5" {
		t.Errorf("newest = %q, want sess-5", got[0].SessionID)
	}
}

func TestSessionTracker_SilentlyDropsMalformedPayloads(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewSessionTracker(portal.SessionTrackerConfig{Source: src})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	src.out <- journal.Msg{Seq: 1, Time: time.Now(), Data: []byte("{not json")}
	pushEntry(t, src, "ssh.recording.completed", "sess-good", "u", "h:22", "alice", "/cast", 1, time.Now())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := tracker.Sessions(); len(got) == 1 && got[0].SessionID == "sess-good" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker did not recover from malformed payload; sessions=%v", tracker.Sessions())
}

func TestPortal_SessionsIndex_RendersList(t *testing.T) {
	store := &stubSessionStore{sessions: []portal.Session{
		{
			SessionID:     "sess-abc",
			User:          "user:alice@example.com",
			Target:        "db-1.prod:22",
			RemoteUser:    "alice",
			RecordingPath: "/var/lib/casts/2026-05-26/sess-abc.cast",
			CompletedAt:   time.Date(2026, 5, 26, 13, 0, 0, 0, time.UTC),
			Duration:      12500 * time.Millisecond,
		},
	}}
	p, _ := portal.New(portal.Config{Version: "v", SessionStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/sessions")
	for _, want := range []string{
		`<h1>Sessions</h1>`,
		`sess-abc`,
		`user:alice@example.com`,
		`db-1.prod:22`,
		`alice`,
		`sess-abc.cast`,
		`12.5s`,
		`2026-05-26T13:00:00Z`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_SessionsIndex_EmptyStore(t *testing.T) {
	p, _ := portal.New(portal.Config{Version: "v", SessionStore: &stubSessionStore{}, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/sessions")
	if !strings.Contains(body, "No recorded sessions yet") {
		t.Errorf("expected empty-state message:\n%s", body)
	}
}

func TestPortal_SessionsIndex_503WhenNoSessionStore(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/sessions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestPortal_Index_FlipsSessionsToReadyWhenSessionStoreWired(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version:      "v",
		Now:          func() time.Time { return time.Now() },
		SessionStore: &stubSessionStore{},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/")
	if !strings.Contains(body, `<a href="/sessions">Sessions</a>`) {
		t.Errorf("Sessions entry not clickable when SessionStore is wired:\n%s", body)
	}
}
