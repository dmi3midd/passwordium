package passwordium

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
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

// existenceChecker is an optional Storage extension that checks whether a vault
// exists without reading the entire payload into memory.
type existenceChecker interface {
	Exists(ctx context.Context) (bool, error)
}

// exclusiveSaver is an optional Storage extension that atomically persists a new
// vault only if no vault currently exists in the backend.
type exclusiveSaver interface {
	SaveNew(ctx context.Context, data []byte) error
}

// conditionalSaver is an optional Storage extension that atomically persists data
// only if the currently stored vault bytes still match expectedDigest.
type conditionalSaver interface {
	SaveIfMatch(ctx context.Context, data []byte, expectedDigest [32]byte) error
}

type fileSaveMode int

const (
	saveModeOverwrite fileSaveMode = iota
	saveModeExclusive
	saveModeIfMatch
)

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

// Exists reports whether a regular vault file exists at s.path without reading its contents.
// It returns ErrInvalidStorageFile if the path exists and is not a regular file.
func (s *FileStorage) Exists(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.path == "" {
		return false, errors.New("passwordium: file storage path is empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return false, err
	}

	linfo, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("passwordium: stat vault file: %w", err)
	}
	if !linfo.Mode().IsRegular() {
		return false, fmt.Errorf("%w: mode %s", ErrInvalidStorageFile, linfo.Mode().Type())
	}
	return true, nil
}

// Save atomically writes data to disk via a 0600 temporary file in the same
// directory, fsyncing before renaming into place. It returns ErrInvalidStorageFile
// if the target path exists and is not a regular file.
func (s *FileStorage) Save(ctx context.Context, data []byte) error {
	return s.save(ctx, data, saveModeOverwrite, [32]byte{})
}

// SaveNew atomically writes data to disk only if no file currently exists at s.path,
// returning ErrAlreadyExists if a regular file is already present or ErrInvalidStorageFile
// if the path is a symlink or other non-regular file.
func (s *FileStorage) SaveNew(ctx context.Context, data []byte) error {
	return s.save(ctx, data, saveModeExclusive, [32]byte{})
}

// SaveIfMatch atomically writes data to disk only if the existing regular file at s.path
// still has SHA-256 digest expectedDigest, returning ErrConcurrentModification otherwise.
func (s *FileStorage) SaveIfMatch(ctx context.Context, data []byte, expectedDigest [32]byte) error {
	return s.save(ctx, data, saveModeIfMatch, expectedDigest)
}

func (s *FileStorage) readLockedDigest() (os.FileInfo, [32]byte, error) {
	maxSize := s.maxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}

	linfo, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, [32]byte{}, ErrConcurrentModification
		}
		return nil, [32]byte{}, fmt.Errorf("passwordium: stat vault file: %w", err)
	}
	if !linfo.Mode().IsRegular() {
		return nil, [32]byte{}, fmt.Errorf("%w: mode %s", ErrInvalidStorageFile, linfo.Mode().Type())
	}
	if linfo.Size() > maxSize {
		return nil, [32]byte{}, ErrConcurrentModification
	}

	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, [32]byte{}, ErrConcurrentModification
		}
		return nil, [32]byte{}, fmt.Errorf("passwordium: open vault file: %w", err)
	}
	defer func() { _ = f.Close() }()

	finfo, err := f.Stat()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("passwordium: fstat vault file: %w", err)
	}
	if !finfo.Mode().IsRegular() || !os.SameFile(linfo, finfo) {
		return nil, [32]byte{}, fmt.Errorf("%w: file changed during open", ErrInvalidStorageFile)
	}

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("passwordium: read vault file: %w", err)
	}
	if n > maxSize {
		return nil, [32]byte{}, ErrConcurrentModification
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return linfo, digest, nil
}

func (s *FileStorage) save(ctx context.Context, data []byte, mode fileSaveMode, expectedDigest [32]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.path == "" {
		return errors.New("passwordium: file storage path is empty")
	}
	if s.maxSize <= 0 {
		return errors.New("passwordium: max file size must be positive")
	}
	if int64(len(data)) > s.maxSize {
		return fmt.Errorf("%w: %d bytes exceeds limit %d", ErrVaultTooLarge, len(data), s.maxSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	var origInfo os.FileInfo
	switch mode {
	case saveModeExclusive:
		linfo, err := os.Lstat(s.path)
		if err == nil {
			if !linfo.Mode().IsRegular() {
				return fmt.Errorf("%w: mode %s", ErrInvalidStorageFile, linfo.Mode().Type())
			}
			return ErrAlreadyExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("passwordium: stat vault file: %w", err)
		}
	case saveModeIfMatch:
		linfo, actualDigest, err := s.readLockedDigest()
		if err != nil {
			return err
		}
		if actualDigest != expectedDigest {
			return ErrConcurrentModification
		}
		origInfo = linfo
	case saveModeOverwrite:
		linfo, err := os.Lstat(s.path)
		if err == nil {
			if !linfo.Mode().IsRegular() {
				return fmt.Errorf("%w: mode %s", ErrInvalidStorageFile, linfo.Mode().Type())
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("passwordium: stat vault file: %w", err)
		}
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

	switch mode {
	case saveModeExclusive:
		if err := os.Link(tmpName, s.path); err != nil {
			_ = os.Remove(tmpName)
			if errors.Is(err, os.ErrExist) {
				if linfo, lerr := os.Lstat(s.path); lerr == nil && !linfo.Mode().IsRegular() {
					return fmt.Errorf("%w: mode %s", ErrInvalidStorageFile, linfo.Mode().Type())
				}
				return ErrAlreadyExists
			}
			return fmt.Errorf("passwordium: link vault file: %w", err)
		}
		_ = os.Remove(tmpName)
	case saveModeIfMatch:
		linfo, actualDigest, err := s.readLockedDigest()
		if err != nil {
			_ = os.Remove(tmpName)
			return err
		}
		if !os.SameFile(origInfo, linfo) || actualDigest != expectedDigest {
			_ = os.Remove(tmpName)
			return ErrConcurrentModification
		}
		if err := os.Rename(tmpName, s.path); err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("passwordium: rename vault file: %w", err)
		}
	case saveModeOverwrite:
		if linfo, err := os.Lstat(s.path); err == nil {
			if !linfo.Mode().IsRegular() {
				_ = os.Remove(tmpName)
				return fmt.Errorf("%w: mode %s", ErrInvalidStorageFile, linfo.Mode().Type())
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(tmpName)
			return fmt.Errorf("passwordium: stat vault file: %w", err)
		}
		if err := os.Rename(tmpName, s.path); err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("passwordium: rename vault file: %w", err)
		}
	}

	// Best-effort directory sync so the rename/link metadata reaches stable storage.
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

// NewMemoryStorageWithData returns a MemoryStorage pre-populated with a defensive copy
// of data. This is useful when importing or opening an encrypted vault byte slice
// received from a mobile file picker, clipboard, or network stream.
func NewMemoryStorageWithData(data []byte) *MemoryStorage {
	return &MemoryStorage{
		exists: true,
		data:   bytes.Clone(data),
	}
}

// sameStorage reports whether a and b refer to the same underlying storage target.
func sameStorage(a, b Storage) bool {
	if a == nil || b == nil {
		return false
	}
	if reflect.TypeOf(a).Comparable() && reflect.TypeOf(b).Comparable() && a == b {
		return true
	}
	fa, okA := a.(*FileStorage)
	fb, okB := b.(*FileStorage)
	if !okA || !okB || fa.path == "" || fb.path == "" {
		return false
	}
	absA, errA := filepath.Abs(fa.path)
	absB, errB := filepath.Abs(fb.path)
	if errA == nil && errB == nil && absA == absB {
		return true
	}
	infoA, errA := os.Lstat(fa.path)
	infoB, errB := os.Lstat(fb.path)
	if errA == nil && errB == nil && os.SameFile(infoA, infoB) {
		return true
	}
	return false
}

// Exists reports whether any vault data has been saved in memory.
func (m *MemoryStorage) Exists(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return false, err
	}
	return m.exists, nil
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

// SaveNew stores a defensive copy of data only if the MemoryStorage is currently empty,
// returning ErrAlreadyExists otherwise.
func (m *MemoryStorage) SaveNew(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if m.exists {
		return ErrAlreadyExists
	}
	m.data = bytes.Clone(data)
	m.exists = true
	return nil
}

// SaveIfMatch atomically replaces the stored bytes only if their current SHA-256 digest
// equals expectedDigest, returning ErrConcurrentModification otherwise.
func (m *MemoryStorage) SaveIfMatch(ctx context.Context, data []byte, expectedDigest [32]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.exists || sha256.Sum256(m.data) != expectedDigest {
		return ErrConcurrentModification
	}
	m.data = bytes.Clone(data)
	return nil
}
