package portal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CastStore opens an asciinema cast file for replay. The recording's
// path comes from the audit event ssh-proxyd published; the store is
// responsible for enforcing path-traversal safety so the portal
// can't be tricked into serving arbitrary files when a malicious
// recording.completed event embeds an attacker-controlled path.
type CastStore interface {
	// Open returns a reader for the cast bytes plus the file size.
	// Callers must Close the reader when done. The cast format is
	// asciinema v2 (header line + NDJSON events); the portal does
	// not parse it — it just streams to the asciinema-player JS.
	Open(recordingPath string) (rc io.ReadCloser, size int64, err error)
}

// ErrCastNotFound is returned by [CastStore.Open] when the file is
// missing on disk. Distinct from [ErrCastOutsideRoot] so handlers
// can map it to 404 (legitimate stale audit reference) vs 403
// (suspected traversal attempt).
var ErrCastNotFound = errors.New("cast file not found")

// ErrCastOutsideRoot is returned when the requested path lies
// outside the configured root. Indicates either misconfiguration
// (the recorded path and the portal's cast root point at different
// mount points) or a malicious audit payload trying to escape the
// allowed directory.
var ErrCastOutsideRoot = errors.New("cast path is outside the configured root")

// LocalCastStore reads casts from the directory tree
// ssh-proxyd's [recording.LocalDirSink] writes to. The recorder emits
// absolute paths in its recording.completed events; the store
// resolves each requested path against Root and rejects anything
// outside it.
//
// Typical deployment: the recorder writes to SSH_PROXYD_CAST_DIR and
// the portal (same process) serves replays out of that same root, so
// the recording_path values resolve correctly.
type LocalCastStore struct {
	root string // absolute, evaluated through filepath.EvalSymlinks at construction
}

// NewLocalCastStore validates root (must exist + be a directory) and
// returns a store rooted there. Returns an error rather than
// panicking so the operator sees misconfiguration at startup.
func NewLocalCastStore(root string) (*LocalCastStore, error) {
	if root == "" {
		return nil, errors.New("cast root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("cast root abs: %w", err)
	}
	// Resolve symlinks once so the prefix check at Open time
	// compares apples to apples (the requested path is also
	// resolved before comparison).
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("cast root resolve: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat cast root %s: %w", resolved, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("cast root %s is not a directory", resolved)
	}
	return &LocalCastStore{root: resolved}, nil
}

// Root returns the resolved absolute root directory. Useful for
// diagnostics; the value is what Open will refuse to serve outside
// of.
func (s *LocalCastStore) Root() string { return s.root }

// Open resolves recordingPath, confirms it's within Root, and
// returns the file reader + size. Symlinks inside the root are
// traversed; symlinks that escape are rejected.
func (s *LocalCastStore) Open(recordingPath string) (io.ReadCloser, int64, error) {
	if recordingPath == "" {
		return nil, 0, ErrCastNotFound
	}
	abs, err := filepath.Abs(recordingPath)
	if err != nil {
		return nil, 0, fmt.Errorf("cast path abs: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrCastNotFound
		}
		return nil, 0, fmt.Errorf("cast path resolve: %w", err)
	}
	// Compare with a trailing-separator check so "/a/bcd" doesn't
	// match root "/a/b".
	rootWithSep := s.root + string(os.PathSeparator)
	if resolved != s.root && !strings.HasPrefix(resolved, rootWithSep) {
		return nil, 0, ErrCastOutsideRoot
	}
	info, err := os.Stat(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrCastNotFound
		}
		return nil, 0, fmt.Errorf("stat cast: %w", err)
	}
	if info.IsDir() {
		return nil, 0, ErrCastNotFound // can't replay a directory
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, 0, err
	}
	return f, info.Size(), nil
}
