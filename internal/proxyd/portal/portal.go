// Package portal serves ssh-proxyd's web UI — a recorded-SSH-session
// list with asciinema-player replay. Server-rendered HTML, no
// client-side framework; pages render fully on the server.
//
// This is ssh-proxyd's first web surface. The portal is mounted by
// [Server.Routes] (typically on its own HTTP listener) and is optional:
// it runs only when an address is configured. Session data is hydrated
// from a [SessionTracker] tailing ssh-proxyd's own ssh_audit JetStream
// stream; cast replay streams files from a [CastStore] rooted at the
// recorder's cast directory.
package portal

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-base/httpauth"
)

// Server is the portal's HTTP handler. Construct via [New] and mount
// the result of [Server.Routes] under the prefix you want; the routes
// are absolute internally so the prefix is caller-chosen.
type Server struct {
	cfg   Config
	pages map[string]*template.Template
}

// Config wires a [Server]. Optional fields default sensibly.
type Config struct {
	// Version is the build-time semver / commit identifier surfaced
	// in the page footer. Empty acceptable but discouraged in
	// deployed builds.
	Version string

	// Log is the structured logger used for request-time events.
	// nil ⇒ slog.Default.
	Log *slog.Logger

	// Now is the clock used for the "rendered at" footer. nil ⇒
	// time.Now. Tests inject a fixed clock for stable assertions.
	Now func() time.Time

	// SessionStore powers the /sessions page (recent recording.completed
	// events on the ssh_audit JetStream stream). When nil, /sessions
	// returns 503.
	SessionStore SessionStore

	// CastStore opens the asciinema cast files referenced by
	// /sessions/{id}/cast. When nil, the cast endpoint returns 503 and
	// the session-detail page hides its embed.
	CastStore CastStore

	// AuditStore powers the /audit page (live tail of ssh-proxyd's
	// ssh_audit stream). When nil, /audit returns 503.
	AuditStore AuditStore

	// BasicAuth gates the portal behind HTTP Basic credentials. When
	// Username + Password are both populated, every request (except
	// /healthz) must present matching Basic creds; otherwise the
	// portal stays open and operators front it with their own
	// identity-aware edge.
	BasicAuth httpauth.BasicAuthConfig
}

// New parses the portal templates and returns a ready [Server].
// Returns an error rather than panicking so callers see template
// authoring bugs at startup.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pages, err := parsePages()
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{cfg: cfg, pages: pages}, nil
}

// render dispatches to the per-page template set keyed by name and
// executes its "page" entry — the in-set wrapper that pulls the
// page-specific title/body into the shared base layout.
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	tmpl, ok := s.pages[page]
	if !ok {
		s.cfg.Log.Error("portal render: unknown page", "page", page)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "page", data); err != nil {
		s.cfg.Log.Error("portal render", "page", page, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// Routes returns the portal's handler tree. Mount under any prefix;
// the routes use a relative path so the prefix is caller-chosen.
// When [Config.BasicAuth] is enabled, every request except /healthz
// must present matching Basic credentials.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /sessions", s.handleSessionsIndex)
	mux.HandleFunc("GET /sessions/{id}", s.handleSessionDetail)
	mux.HandleFunc("GET /sessions/{id}/cast", s.handleSessionCast)
	mux.HandleFunc("GET /audit", s.handleAuditIndex)
	return httpauth.BasicAuth(s.cfg.BasicAuth, mux, "/healthz")
}

// indexData is the model passed to the landing page template.
type indexData struct {
	Version    string
	RenderedAt time.Time
	Pages      []pageEntry
}

type pageEntry struct {
	Name        string
	Path        string
	Description string
	Status      string // "ready" or "planned"
}

// landingPages returns the dashboard's nav entries. Each page flips
// to "ready" when its data source is wired; otherwise stays planned.
func (s *Server) landingPages() []pageEntry {
	status := func(wired bool) string {
		if wired {
			return "ready"
		}
		return "planned"
	}
	return []pageEntry{
		{Name: "Sessions", Path: "/sessions", Description: "Recent recorded SSH sessions with asciinema replay", Status: status(s.cfg.SessionStore != nil)},
		{Name: "Audit", Path: "/audit", Description: "Live audit-event viewer (session lifecycle, channels, recordings, port-forwards)", Status: status(s.cfg.AuditStore != nil)},
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "index", indexData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Pages:      s.landingPages(),
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

// sessionsIndexData is the model for the sessions list page.
type sessionsIndexData struct {
	Version    string
	RenderedAt time.Time
	Sessions   []Session
}

func (s *Server) handleSessionsIndex(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.SessionStore == nil {
		http.Error(w, "session store not configured", http.StatusServiceUnavailable)
		return
	}
	s.render(w, "sessions", sessionsIndexData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Sessions:   s.cfg.SessionStore.Sessions(),
	})
}

// sessionDetailData is the model for the single-session page.
type sessionDetailData struct {
	Version    string
	RenderedAt time.Time
	ID         string
	Session    Session
	Found      bool
	// CastAvailable indicates whether a CastStore is wired AND the
	// session has a RecordingPath. Drives the player embed.
	CastAvailable bool
}

func (s *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SessionStore == nil {
		http.Error(w, "session store not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	data := sessionDetailData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		ID:         id,
	}
	for _, sess := range s.cfg.SessionStore.Sessions() {
		if sess.SessionID == id {
			data.Session = sess
			data.Found = true
			data.CastAvailable = s.cfg.CastStore != nil && sess.RecordingPath != ""
			break
		}
	}
	if !data.Found {
		w.WriteHeader(http.StatusNotFound)
	}
	s.render(w, "session_detail", data)
}

// handleSessionCast streams the raw cast bytes for {id}. The session
// is resolved through SessionStore; the CastStore is asked to open
// the file at the session's RecordingPath (the store enforces the
// path-root guard). Content-Type is "text/plain" since the cast
// format is asciinema's NDJSON — letting browsers preview it
// directly is fine and aligns with what asciinema-player loads.
func (s *Server) handleSessionCast(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SessionStore == nil {
		http.Error(w, "session store not configured", http.StatusServiceUnavailable)
		return
	}
	if s.cfg.CastStore == nil {
		http.Error(w, "cast store not configured", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	var sess Session
	var found bool
	for _, candidate := range s.cfg.SessionStore.Sessions() {
		if candidate.SessionID == id {
			sess = candidate
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if sess.RecordingPath == "" {
		http.Error(w, "session has no recording", http.StatusNotFound)
		return
	}
	rc, size, err := s.cfg.CastStore.Open(sess.RecordingPath)
	if err != nil {
		switch {
		case errors.Is(err, ErrCastNotFound):
			http.Error(w, "cast file not found", http.StatusNotFound)
		case errors.Is(err, ErrCastOutsideRoot):
			s.cfg.Log.Warn("portal: cast path outside configured root — refusing to serve",
				"session_id", id, "path", sess.RecordingPath)
			http.Error(w, "cast outside allowed root", http.StatusForbidden)
		default:
			s.cfg.Log.Error("portal: open cast", "session_id", id, "err", err)
			http.Error(w, "cast open failed", http.StatusInternalServerError)
		}
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if size > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, rc)
}

// auditIndexData is the model for the audit list page.
type auditIndexData struct {
	Version    string
	RenderedAt time.Time
	Events     []AuditEvent
}

func (s *Server) handleAuditIndex(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.AuditStore == nil {
		http.Error(w, "audit store not configured", http.StatusServiceUnavailable)
		return
	}
	s.render(w, "audit", auditIndexData{
		Version:    s.cfg.Version,
		RenderedAt: s.cfg.Now(),
		Events:     s.cfg.AuditStore.Events(),
	})
}

func parsePages() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"fmtTime": func(t time.Time) string {
			return t.UTC().Format(time.RFC3339)
		},
		"fmtDuration": func(d time.Duration) string {
			if d == 0 {
				return "-"
			}
			return d.String()
		},
	}
	pages := map[string]string{
		"index":          indexTemplate,
		"sessions":       sessionsTemplate,
		"session_detail": sessionDetailTemplate,
		"audit":          auditTemplate,
	}
	out := make(map[string]*template.Template, len(pages))
	for name, body := range pages {
		t := template.New(name).Funcs(funcs)
		if _, err := t.Parse(baseTemplate); err != nil {
			return nil, fmt.Errorf("%s base: %w", name, err)
		}
		if _, err := t.Parse(body); err != nil {
			return nil, fmt.Errorf("%s page: %w", name, err)
		}
		if t.Lookup("page") == nil || t.Lookup("title") == nil || t.Lookup("body") == nil {
			return nil, fmt.Errorf("%s missing required define{}: page/title/body", name)
		}
		out[name] = t
	}
	return out, nil
}

const baseTemplate = `{{define "base"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{template "title" .}} · ssh-proxyd</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 60em; margin: 2em auto; padding: 0 1em; color: #1a1a1a; }
header, footer { padding: 0.5em 0; border-bottom: 1px solid #ddd; }
footer { border-bottom: none; border-top: 1px solid #ddd; margin-top: 2em; padding-top: 0.5em; font-size: 0.85em; color: #666; }
h1 { margin-top: 0.5em; }
table { border-collapse: collapse; width: 100%; margin-top: 1em; }
th, td { text-align: left; padding: 0.4em 0.6em; border-bottom: 1px solid #eee; }
.status-planned { color: #888; }
.status-ready { color: #1a7f37; font-weight: 600; }
</style>
</head>
<body>
<header><strong>ssh-proxyd portal</strong></header>
<main>{{template "body" .}}</main>
<footer>ssh-proxyd {{.Version}} · rendered {{fmtTime .RenderedAt}}</footer>
</body>
</html>{{end}}`

const indexTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}home{{end}}
{{define "body"}}
<h1>Welcome</h1>
<p>The ssh-proxyd portal surfaces the SSH sessions this proxy has
recorded, with in-browser asciinema replay.</p>
<table>
<thead><tr><th>Page</th><th>Description</th><th>Status</th></tr></thead>
<tbody>
{{range .Pages}}
<tr>
  <td>{{if eq .Status "ready"}}<a href="{{.Path}}">{{.Name}}</a>{{else}}{{.Name}}{{end}}</td>
  <td>{{.Description}}</td>
  <td class="status-{{.Status}}">{{.Status}}</td>
</tr>
{{end}}
</tbody>
</table>
{{end}}`

const sessionsTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}sessions{{end}}
{{define "body"}}
<p><a href="/">&larr; home</a></p>
<h1>Sessions</h1>
<p>Recent SSH sessions ssh-proxyd has finished recording. Hydrated
from the <code>recording.completed</code> audit events on the
<code>ssh_audit</code> JetStream stream — order is newest-first.
Click a session ID for metadata and asciinema replay.</p>
{{if .Sessions}}
<table>
<thead>
<tr>
  <th>Completed at</th>
  <th>User</th>
  <th>Target</th>
  <th>Remote user</th>
  <th>Duration</th>
  <th>Recording</th>
  <th>Session ID</th>
</tr>
</thead>
<tbody>
{{range .Sessions}}
<tr>
  <td>{{fmtTime .CompletedAt}}</td>
  <td>{{if .User}}<code>{{.User}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Target}}<code>{{.Target}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .RemoteUser}}<code>{{.RemoteUser}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{fmtDuration .Duration}}</td>
  <td>{{if .RecordingPath}}<code>{{.RecordingPath}}</code>{{else}}<em>-</em>{{end}}</td>
  <td><a href="/sessions/{{.SessionID}}"><code>{{.SessionID}}</code></a></td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p><em>No recorded sessions yet. Hold tight — recording.completed events arrive when ssh-proxyd finishes a PTY session.</em></p>
{{end}}
{{end}}`

const sessionDetailTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}session · {{.ID}}{{end}}
{{define "body"}}
<p><a href="/sessions">&larr; sessions</a></p>
{{if not .Found}}
<h1>Not found</h1>
<p>No session with ID <code>{{.ID}}</code> is in the recent buffer.
Older sessions may have aged out of the in-memory ring; query
JetStream directly to find them.</p>
{{else}}
<h1>Session <code>{{.Session.SessionID}}</code></h1>
<table>
<tbody>
<tr><th>Completed at</th><td>{{fmtTime .Session.CompletedAt}}</td></tr>
<tr><th>Duration</th><td>{{fmtDuration .Session.Duration}}</td></tr>
<tr><th>User</th><td>{{if .Session.User}}<code>{{.Session.User}}</code>{{else}}<em>-</em>{{end}}</td></tr>
<tr><th>Target</th><td>{{if .Session.Target}}<code>{{.Session.Target}}</code>{{else}}<em>-</em>{{end}}</td></tr>
<tr><th>Remote user</th><td>{{if .Session.RemoteUser}}<code>{{.Session.RemoteUser}}</code>{{else}}<em>-</em>{{end}}</td></tr>
<tr><th>Principals</th><td>{{if .Session.Principals}}<code>{{.Session.Principals}}</code>{{else}}<em>-</em>{{end}}</td></tr>
<tr><th>Client IP</th><td>{{if .Session.ClientIP}}<code>{{.Session.ClientIP}}</code>{{else}}<em>-</em>{{end}}</td></tr>
<tr><th>Recording path</th><td>{{if .Session.RecordingPath}}<code>{{.Session.RecordingPath}}</code>{{else}}<em>-</em>{{end}}</td></tr>
</tbody>
</table>
{{if .CastAvailable}}
<h2>Replay</h2>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/asciinema-player@3.10.0/dist/bundle/asciinema-player.css">
<div id="asciinema-player"></div>
<script src="https://cdn.jsdelivr.net/npm/asciinema-player@3.10.0/dist/bundle/asciinema-player.min.js"></script>
<script>
AsciinemaPlayer.create('/sessions/{{.Session.SessionID}}/cast',
  document.getElementById('asciinema-player'),
  {fit: 'width', terminalLineHeight: 1.2});
</script>
<p><a href="/sessions/{{.Session.SessionID}}/cast">Download raw cast</a></p>
{{else}}
<p><em>No replay available — </em>{{if not .Session.RecordingPath}}the session was not PTY-recorded.{{else}}the cast store is not configured on this ssh-proxyd.{{end}}</p>
{{end}}
{{end}}
{{end}}`

const auditTemplate = `{{define "page"}}{{template "base" .}}{{end}}
{{define "title"}}audit{{end}}
{{define "body"}}
<p><a href="/">&larr; home</a></p>
<h1>Audit</h1>
<p>Live tail of ssh-proxyd's <code>ssh_audit</code> stream — session
lifecycle, channel, recording, and port-forward events. Newest first.
The buffer caps at the tracker's MaxEvents (default 500); to dig
deeper, query JetStream directly.</p>
{{if .Events}}
<table>
<thead>
<tr>
  <th>Time</th>
  <th>Action</th>
  <th>Actor</th>
  <th>Subject</th>
  <th>IP</th>
  <th>Detail</th>
</tr>
</thead>
<tbody>
{{range .Events}}
<tr>
  <td>{{fmtTime .OccurredAt}}</td>
  <td><code>{{.Action}}</code></td>
  <td>{{if .Actor}}<code>{{.Actor}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Subject}}<code>{{.Subject}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .IP}}<code>{{.IP}}</code>{{else}}<em>-</em>{{end}}</td>
  <td>{{if .Reason}}<em>{{.Reason}}</em>{{else if .Detail}}<details><summary>view</summary><pre>{{.Detail}}</pre></details>{{else}}<em>-</em>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p><em>No audit events yet. Events appear here once ssh-proxyd starts emitting to the stream.</em></p>
{{end}}
{{end}}`
