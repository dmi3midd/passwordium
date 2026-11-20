package passwordium

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Storage defines the persistence backend for serialized encrypted vaults.
// Implementations must be safe for concurrent use by multiple goroutines.
type Storage interface {
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, data []byte) error
}

// FileStorage persists the vault to a single file using atomic temporary-file
// writes and 0600 file permissions.
type FileStorage struct {
	mu   sync.RWMutex
	path string
}

// NewFileStorage creates a FileStorage targeting path.
func NewFileStorage(path string) *FileStorage {
	return &FileStorage{path: path}
}

// Load reads the vault file from disk, returning ErrNotFound if it does not exist.
func (s *FileStorage) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.path == "" {
		return nil, errors.New("passwordium: file storage path is empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("passwordium: read vault file: %w", err)
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
