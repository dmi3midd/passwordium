package passwordium

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// DefaultMaxFileSize is the default maximum vault size accepted by FileStorage.Load (64 MiB).
const DefaultMaxFileSize int64 = 64 * 1024 * 1024

// Storage defines the persistence backend for serialized encrypted vaults.
// Implementations must be safe for concurrent use by multiple goroutines.
type Storage interface {
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, data []byte) error
}

// FileStorageOption configures FileStorage.
type FileStorageOption func(*FileStorage)

// WithMaxFileSize sets the maximum number of bytes FileStorage.Load will read.
func WithMaxFileSize(maxBytes int64) FileStorageOption {
	return func(s *FileStorage) {
		s.maxSize = maxBytes
	}
}

// FileStorage persists the vault to a single file using atomic temporary-file
// writes and 0600 file permissions.
type FileStorage struct {
	mu      sync.RWMutex
	path    string
	maxSize int64
}

// NewFileStorage creates a FileStorage targeting path. By default Load rejects
// files larger than DefaultMaxFileSize.
func NewFileStorage(path string, opts ...FileStorageOption) *FileStorage {
	s := &FileStorage{path: path, maxSize: DefaultMaxFileSize}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Load reads the vault file from disk. It returns ErrNotFound if the file does not
// exist, ErrInvalidStorageFile if the path is not a regular file (symlinks, FIFOs,
// devices, and directories are rejected before opening, so Load cannot block on them),
// and ErrVaultTooLarge if the file exceeds the configured size limit.
func (s *FileStorage) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.path == "" {
		return nil, errors.New("passwordium: file storage path is empty")
	}
	if s.maxSize <= 0 {
		return nil, errors.New("passwordium: max file size must be positive")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	linfo, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("passwordium: stat vault file: %w", err)
	}
	if !linfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: mode %s", ErrInvalidStorageFile, linfo.Mode().Type())
	}
	if linfo.Size() > s.maxSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds limit %d", ErrVaultTooLarge, linfo.Size(), s.maxSize)
	}

	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("passwordium: open vault file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Guard against the path being swapped between Lstat and Open.
	finfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("passwordium: fstat vault file: %w", err)
	}
	if !finfo.Mode().IsRegular() || !os.SameFile(linfo, finfo) {
		return nil, fmt.Errorf("%w: file changed during open", ErrInvalidStorageFile)
	}

	data, err := io.ReadAll(io.LimitReader(f, s.maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("passwordium: read vault file: %w", err)
	}
	if int64(len(data)) > s.maxSize {
		return nil, fmt.Errorf("%w: exceeds limit %d bytes", ErrVaultTooLarge, s.maxSize)
	}
	return data, nil
}

// Save atomically writes data to disk via a 0600 temporary file in the same
// directory, fsyncing before renaming into place.
func (s *FileStorage) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.path == "" {
		return errors.New("passwordium: file storage path is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	base := filepath.Base(s.path)

	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("passwordium: create temp vault file: %w", err)
	}
	tmpName := tmp.Name()
	tmpClosed := false
	cleanup := func() {
		if !tmpClosed {
			_ = tmp.Close()
			tmpClosed = true
		}
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("passwordium: chmod temp vault file: %w", err)
	}

	for written := 0; written < len(data); {
		n, err := tmp.Write(data[written:])
		written += n
		if err != nil {
			cleanup()
			return fmt.Errorf("passwordium: write temp vault file: %w", err)
		}
	}

	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("passwordium: sync temp vault file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		tmpClosed = true
		_ = os.Remove(tmpName)
		return fmt.Errorf("passwordium: close temp vault file: %w", err)
	}
	tmpClosed = true

	if err := ctx.Err(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("passwordium: rename vault file: %w", err)
	}

	// Best-effort directory sync so the rename metadata reaches stable storage.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return nil
}

// MemoryStorage is a thread-safe in-memory Storage implementation intended for tests
// and ephemeral vaults.
type MemoryStorage struct {
	mu     sync.RWMutex
	exists bool
	data   []byte
}

// NewMemoryStorage returns an empty MemoryStorage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{}
}

// Load returns a copy of the stored vault bytes, or ErrNotFound if nothing has been saved.
func (m *MemoryStorage) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !m.exists {
		return nil, ErrNotFound
	}
	return bytes.Clone(m.data), nil
}

// Save stores a defensive copy of data in memory.
func (m *MemoryStorage) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	m.data = bytes.Clone(data)
	m.exists = true
	return nil
}
