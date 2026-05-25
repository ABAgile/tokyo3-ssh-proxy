package recording

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Sink persists a completed asciinema cast. Implementations live
// outside this package when they wrap external storage (S3, GCS);
// [LocalDirSink] is the in-process fallback for dev / first run.
//
// OpenCast returns an io.WriteCloser the [Recorder] streams events
// to plus a string location identifying where the cast lives so
// audit / the portal can find it later. For file sinks the location
// is an absolute path; for object stores it would be a URL.
// Calling Close on the writer finalises the cast — for file sinks
// that means fsync + chmod; for object stores it means uploading
// the buffered bytes.
type Sink interface {
	OpenCast(ctx context.Context, meta CastMeta) (out io.WriteCloser, location string, err error)
}

// CastMeta describes one recording so a Sink can name + locate it.
// Field semantics are stable across slices; new fields are additive.
type CastMeta struct {
	// SessionID is the unique identifier the session handler picks
	// before recording starts (UUID or similar). Keeps casts from
	// the same user separate even when titles collide.
	SessionID string
	// User is the bearer's identity from the cert KeyID — used in
	// generated filenames + the asciinema title.
	User string
	// Target is the host the user reached, for filename + title.
	Target string
	// Started is the session start time. Sinks use it for naming
	// (e.g., date-prefixed subdirectories).
	Started time.Time
}

// LocalDirSink writes each cast to <Root>/<YYYY-MM-DD>/<SessionID>.cast.
// Suitable for dev or single-node deployments; production should
// swap to an object-store sink that survives node loss.
type LocalDirSink struct {
	root string

	mu sync.Mutex // guards mkdir-once semantics for the day directory
}

// NewLocalDirSink validates root exists (or can be created) and
// returns a sink that drops new casts under it.
func NewLocalDirSink(root string) (*LocalDirSink, error) {
	if root == "" {
		return nil, errors.New("root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", abs, err)
	}
	return &LocalDirSink{root: abs}, nil
}

// Root returns the absolute root directory for tests + audit attribution.
func (s *LocalDirSink) Root() string { return s.root }

// OpenCast satisfies [Sink]. Builds the day subdirectory on first
// touch, then opens <root>/<date>/<session-id>.cast for writing.
// The returned writer is created with 0600 (audit data — the
// operator decides who reads it). The returned location is the
// absolute file path.
func (s *LocalDirSink) OpenCast(_ context.Context, meta CastMeta) (io.WriteCloser, string, error) {
	if meta.SessionID == "" {
		return nil, "", errors.New("CastMeta.SessionID is required")
	}
	if meta.Started.IsZero() {
		meta.Started = time.Now()
	}
	day := meta.Started.UTC().Format("2006-01-02")
	dir := filepath.Join(s.root, day)
	s.mu.Lock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.mu.Unlock()
		return nil, "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	s.mu.Unlock()

	path := filepath.Join(dir, sanitizeFilename(meta.SessionID)+".cast")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("create %s: %w", path, err)
	}
	return f, path, nil
}

// sanitizeFilename strips path separators + control chars from
// session IDs so a malicious caller can't escape the sink's root
// directory via "../whatever". Conservatively keeps only ASCII
// letters, digits, "-", and "_".
func sanitizeFilename(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// NopSink discards every cast — useful for tests that want to drive
// the Proxier with recording wired but don't care about the bytes.
type NopSink struct{}

// OpenCast satisfies [Sink]. Returns a writer that discards
// everything and an empty location (no on-disk artefact to point at).
func (NopSink) OpenCast(context.Context, CastMeta) (io.WriteCloser, string, error) {
	return nopWriteCloser{}, "", nil
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

// Compile-time interface check — fails fast if [LocalDirSink] drifts
// out of the [Sink] contract.
var _ Sink = (*LocalDirSink)(nil)
var _ Sink = NopSink{}
var _ io.WriteCloser = nopWriteCloser{}
