package portal_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/journal"

	"github.com/abagile/tokyo3-ssh-proxy/internal/proxyd/portal"
)

// stubAuditStore is the read-only portal.AuditStore test double.
type stubAuditStore struct{ events []portal.AuditEvent }

func (s *stubAuditStore) Events() []portal.AuditEvent { return s.events }

// pushAuditEvent marshals an ssh-proxy-shaped audit Entry onto the mock
// source (User / Target / ClientIP / SessionID / Reason fields).
func pushAuditEvent(t *testing.T, src *mockSource, action, user, target, clientIP, sessionID, reason string, when time.Time) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"id":          "evt-" + action,
		"action":      action,
		"user":        user,
		"target":      target,
		"client_ip":   clientIP,
		"session_id":  sessionID,
		"reason":      reason,
		"metadata":    `{"duration_seconds":3}`,
		"occurred_at": when,
	})
	src.out <- journal.Msg{Seq: 1, Time: when, Data: payload}
}

func TestNewAuditTracker_RequiresSource(t *testing.T) {
	_, err := portal.NewAuditTracker(portal.AuditTrackerConfig{})
	if err == nil || !strings.Contains(err.Error(), "source is required") {
		t.Errorf("err = %v, want source-required", err)
	}
}

func TestAuditTracker_IngestsSshProxyShape(t *testing.T) {
	src := newMockSource()
	tracker, err := portal.NewAuditTracker(portal.AuditTrackerConfig{Source: src})
	if err != nil {
		t.Fatalf("NewAuditTracker: %v", err)
	}
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	now := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	pushAuditEvent(t, src, "ssh.session.opened", "user:alice", "db-1.prod:22", "10.0.0.1", "sess-abc", "", now)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := tracker.Events(); len(events) == 1 {
			e := events[0]
			// ssh-proxy fields: Actor = User, Subject = Target, IP = ClientIP.
			if e.Actor != "user:alice" || e.Subject != "db-1.prod:22" || e.IP != "10.0.0.1" {
				t.Errorf("fields: actor=%q subject=%q ip=%q", e.Actor, e.Subject, e.IP)
			}
			if e.SessionID != "sess-abc" {
				t.Errorf("SessionID = %q", e.SessionID)
			}
			if !strings.Contains(e.Detail, "duration_seconds") {
				t.Errorf("Detail not preserved: %q", e.Detail)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker did not ingest the event; got=%v", tracker.Events())
}

func TestAuditTracker_SortsNewestFirst(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Source: src,
	})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	base := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	pushAuditEvent(t, src, "ssh.session.opened", "u", "h:22", "ip", "s1", "", base.Add(2*time.Second))
	pushAuditEvent(t, src, "ssh.session.closed", "u", "h:22", "ip", "s2", "", base)
	pushAuditEvent(t, src, "ssh.channel.rejected", "u", "h:22", "ip", "s3", "denied", base.Add(1*time.Second))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := tracker.Events(); len(events) == 3 {
			if !events[0].OccurredAt.After(events[1].OccurredAt) ||
				!events[1].OccurredAt.After(events[2].OccurredAt) {
				t.Errorf("not sorted newest-first: %v %v %v",
					events[0].OccurredAt, events[1].OccurredAt, events[2].OccurredAt)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker did not ingest 3 events; got=%d", len(tracker.Events()))
}

func TestAuditTracker_BoundedByMaxEvents(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Source:    src,
		MaxEvents: 3,
	})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	base := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	for i := range 6 {
		pushAuditEvent(t, src, "ssh.session.opened", "u", "h:22", "ip", "s", "", base.Add(time.Duration(i)*time.Second))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(tracker.Events()) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(tracker.Events()); got != 3 {
		t.Errorf("Events len = %d, want 3 (bounded)", got)
	}
}

func TestAuditTracker_SkipsMalformedAndIncompleteEvents(t *testing.T) {
	src := newMockSource()
	tracker, _ := portal.NewAuditTracker(portal.AuditTrackerConfig{
		Source: src,
	})
	ctx := t.Context()
	go func() { _ = tracker.Run(ctx) }()

	// 1. Garbage JSON.
	src.out <- journal.Msg{Seq: 1, Time: time.Now(), Data: []byte("{not json")}
	// 2. Missing action (skipped — would render a useless row).
	payload, _ := json.Marshal(map[string]any{"id": "x", "user": "alice", "occurred_at": time.Now()})
	src.out <- journal.Msg{Seq: 2, Time: time.Now(), Data: payload}
	// 3. Valid event.
	pushAuditEvent(t, src, "ssh.session.opened", "alice", "h:22", "ip", "s", "", time.Now())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := tracker.Events(); len(got) == 1 && got[0].Action == "ssh.session.opened" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("tracker did not recover; events=%v", tracker.Events())
}

func TestPortal_AuditIndex_RendersList(t *testing.T) {
	when := time.Date(2026, 5, 26, 14, 0, 0, 0, time.UTC)
	store := &stubAuditStore{events: []portal.AuditEvent{
		{
			Action:     "ssh.session.opened",
			Actor:      "user:alice",
			Subject:    "db-1.prod:22",
			IP:         "10.0.0.1",
			OccurredAt: when,
			Detail:     `{"duration_seconds":3}`,
		},
		{
			Action:     "ssh.channel.rejected",
			Actor:      "user:bob",
			Subject:    "db-1:22",
			OccurredAt: when.Add(time.Second),
			Reason:     "policy denied principal 'bob' for db-1",
		},
	}}
	p, _ := portal.New(portal.Config{Version: "v", AuditStore: store, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	body := getBody(t, srv.URL+"/audit")
	for _, want := range []string{
		`<h1>Audit</h1>`,
		`<code>ssh.session.opened</code>`,
		`<code>ssh.channel.rejected</code>`,
		`user:alice`,
		`db-1:22`,
		`policy denied principal`,
		`duration_seconds`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestPortal_AuditIndex_EmptyStore(t *testing.T) {
	p, _ := portal.New(portal.Config{Version: "v", AuditStore: &stubAuditStore{}, Now: time.Now})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/audit")
	if !strings.Contains(body, "No audit events yet") {
		t.Errorf("expected empty-state:\n%s", body)
	}
}

func TestPortal_AuditIndex_503WhenNoAuditStore(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/audit")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestPortal_Index_FlipsAuditToReadyWhenAuditStoreWired(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version:    "v",
		Now:        func() time.Time { return time.Now() },
		AuditStore: &stubAuditStore{},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()
	body := getBody(t, srv.URL+"/")
	if !strings.Contains(body, `<a href="/audit">Audit</a>`) {
		t.Errorf("Audit entry not clickable when AuditStore is wired:\n%s", body)
	}
}
