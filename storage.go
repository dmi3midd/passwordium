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

// DefaultMaxFileSize is the default maximum serialized vault size in bytes (64 MiB)
// accepted by FileStorage on both Load and Save operations when WithMaxFileSize is
// not specified.
const DefaultMaxFileSize int64 = 64 * 1024 * 1024

// Storage defines the persistence backend contract for reading and writing serialized
// encrypted vault envelopes.
//
// Implementations must be safe for concurrent use by multiple goroutines and must not
// retain or mutate byte slices passed to Save after Save returns, nor mutate byte slices
// returned from Load.
//
// In addition to Load and Save, a Storage implementation may optionally implement the
// following method signatures to enable atomic existence checks, exclusive creation, and
// optimistic concurrency control (both FileStorage and MemoryStorage implement all three):
//   - Exists(ctx context.Context) (bool, error): checks whether a vault exists without
//     loading the entire payload into memory.
//   - SaveNew(ctx context.Context, data []byte) error: atomically persists data only if
//     no vault currently exists, returning ErrAlreadyExists otherwise.
//   - SaveIfMatch(ctx context.Context, data []byte, expectedDigest [32]byte) error:
//     atomically persists data only if the currently stored vault bytes have SHA-256
//     digest expectedDigest, returning ErrConcurrentModification otherwise.
type Storage interface {
	// Load retrieves the complete serialized encrypted vault envelope from the backend.
	//
	// Load must honor ctx cancellation and deadlines. If no vault exists in the backend
	// yet, Load must return ErrNotFound (or an error wrapping ErrNotFound). The returned
	// byte slice is owned by the caller and must not alias mutable internal state.
	Load(ctx context.Context) ([]byte, error)

	// Save atomically persists the serialized encrypted vault envelope data to the backend,
	// replacing any previously stored vault data.
	//
	// Save must honor ctx cancellation and deadlines and must leave any previously stored
	// vault intact if an error occurs. Implementations must not mutate data.
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

// FileStorageOption configures a FileStorage instance during construction in NewFileStorage.
// Passing a nil FileStorageOption to NewFileStorage is safely ignored.
type FileStorageOption func(*FileStorage)

// WithMaxFileSize sets the maximum size in bytes that FileStorage will read on Load
// or write on Save, SaveNew, and SaveIfMatch.
//
// Payloads exceeding maxBytes are rejected with ErrVaultTooLarge before reading the full
// file or writing a temporary file to disk. Configuring a non-positive maxBytes (<= 0)
// causes subsequent Load and Save operations on the FileStorage to fail with an error.
func WithMaxFileSize(maxBytes int64) FileStorageOption {
	return func(s *FileStorage) {
		s.maxSize = maxBytes
	}
}

// FileStorage is a thread-safe Storage implementation that persists an encrypted vault
// to a single regular file on the local filesystem.
//
// FileStorage enforces strict filesystem safety invariants:
//   - Non-regular files (symbolic links, directories, FIFOs, sockets, and device nodes)
//     are rejected via os.Lstat before opening or overwriting, and inode identity is
//     re-verified with f.Stat and os.SameFile after opening to prevent TOCTOU swaps.
//   - Writes are performed atomically via a temporary file created in the target directory
//     with 0600 permissions, flushed to stable storage via Sync, and moved into place via
//     os.Link (for exclusive creation in SaveNew) or os.Rename (for Save and SaveIfMatch),
//     followed by a best-effort parent directory Sync.
//   - Concurrent calls within the same process on the same FileStorage instance are
//     serialized by an internal read-write mutex.
type FileStorage struct {
	mu      sync.RWMutex
	path    string
	maxSize int64
}

// NewFileStorage constructs a FileStorage targeting the filesystem file at path.
//
// By default, NewFileStorage sets the maximum allowed file size to DefaultMaxFileSize
// (64 MiB); supply WithMaxFileSize in opts to customize this limit. NewFileStorage
// does not perform any disk I/O; path validation occurs on subsequent Load, Exists,
// or Save calls.
func NewFileStorage(path string, opts ...FileStorageOption) *FileStorage {
	s := &FileStorage{path: path, maxSize: DefaultMaxFileSize}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Load reads and returns the encrypted vault file from disk at the FileStorage's path.
//
// Load checks ctx before and after acquiring the read lock, verifies via os.Lstat that
// the target path is a regular file whose size does not exceed the configured maximum,
// opens the file, re-verifies with f.Stat and os.SameFile that the path was not swapped
// during open, and reads at most maxSize + 1 bytes.
//
// It returns ctx.Err() if ctx is canceled, an error if the configured path is empty or
// maxSize <= 0, ErrNotFound if the file does not exist, ErrInvalidStorageFile if the
// path is a symlink or other non-regular file (or changed during open), ErrVaultTooLarge
// if the file size exceeds maxSize, or a wrapped I/O error.
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

// Exists reports whether a regular vault file currently exists at the FileStorage's path
// without reading the file's contents into memory.
//
// Exists returns (false, nil) when the path does not exist, (true, nil) when a regular
// file exists at the path, ctx.Err() if ctx is canceled, an error if the path is empty,
// ErrInvalidStorageFile if the path exists and is a symlink, directory, or other
// non-regular file, or a wrapped filesystem stat error.
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

// Save atomically writes data to the FileStorage's path, creating the file if it does
// not exist or replacing the existing regular file.
//
// Save writes data to a temporary file in the same directory with 0600 permissions,
// calls Sync and Close on the temporary file, renames it over the target path, and
// performs a best-effort Sync on the parent directory. If any step fails or ctx is
// canceled before the rename, the temporary file is removed and the existing file at
// the target path is left untouched.
//
// Save returns ctx.Err() if ctx is canceled, an error if the path is empty or
// maxSize <= 0, ErrVaultTooLarge if len(data) exceeds maxSize, ErrInvalidStorageFile
// if the target path exists and is not a regular file, or a wrapped I/O error.
func (s *FileStorage) Save(ctx context.Context, data []byte) error {
	return s.save(ctx, data, saveModeOverwrite, [32]byte{})
}

// SaveNew atomically writes data to the FileStorage's path only if no file currently
// exists at that path.
//
// SaveNew writes and syncs a 0600 temporary file in the target directory and uses
// os.Link to link it into place atomically without overwriting existing files,
// removing the temporary link afterwards.
//
// SaveNew returns ErrAlreadyExists if a regular file already exists at the target path,
// ErrInvalidStorageFile if the path exists as a symlink, directory, or other non-regular
// file, ErrVaultTooLarge if len(data) exceeds maxSize, ctx.Err() if ctx is canceled,
// or a wrapped I/O error.
func (s *FileStorage) SaveNew(ctx context.Context, data []byte) error {
	return s.save(ctx, data, saveModeExclusive, [32]byte{})
}

// SaveIfMatch atomically writes data to the FileStorage's path only if the existing
// regular file on disk still has the SHA-256 digest expectedDigest.
//
// SaveIfMatch verifies the existing file's inode and SHA-256 digest while holding the
// FileStorage write lock both before creating the 0600 temporary file and immediately
// before renaming the synced temporary file over the target path.
//
// SaveIfMatch returns ErrConcurrentModification if the target file does not exist,
// exceeds maxSize on disk, changed inode, or has a SHA-256 digest different from
// expectedDigest. It returns ErrVaultTooLarge if len(data) exceeds maxSize,
// ErrInvalidStorageFile if the target path is not a regular file, ctx.Err() if ctx is
// canceled, or a wrapped I/O error.
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

// MemoryStorage is a thread-safe in-memory Storage implementation intended for unit tests,
// ephemeral vaults, and byte-slice import/export workflows.
//
// MemoryStorage clones all byte slices on input and output so callers cannot mutate the
// stored ciphertext envelope out-of-band, and implements Exists, SaveNew, and SaveIfMatch
// for full parity with FileStorage.
type MemoryStorage struct {
	mu     sync.RWMutex
	exists bool
	data   []byte
}

// NewMemoryStorage constructs an empty, uninitialized MemoryStorage instance for which
// Load initially returns ErrNotFound and Exists returns (false, nil).
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{}
}

// NewMemoryStorageWithData constructs a MemoryStorage pre-populated with a defensive
// copy of data and marked as existing (even if data is nil or empty).
//
// This constructor is useful when opening or importing an encrypted vault byte slice
// received in memory from a mobile file picker, clipboard, database blob, or network stream.
// Subsequent mutations to the caller's data slice do not affect the returned MemoryStorage.
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

// Exists reports whether vault data has been persisted in m.
//
// Exists honors ctx cancellation and returns (false, ctx.Err()) if ctx is already done;
// otherwise it returns (true, nil) if m was initialized via NewMemoryStorageWithData or
// a prior Save/SaveNew call, or (false, nil) if m is empty.
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

// Load returns a defensive copy of the encrypted vault bytes stored in m.
//
// Load returns ctx.Err() if ctx is canceled, or ErrNotFound if no vault data has been
// stored in m yet. Mutating the returned slice does not affect m's internal buffer.
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

// Save stores a defensive copy of data in m, overwriting any previously stored bytes
// and marking m as populated.
//
// Save returns ctx.Err() without modifying m if ctx is canceled.
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

// SaveNew atomically stores a defensive copy of data in m only if m does not currently
// hold any vault data.
//
// SaveNew returns ctx.Err() if ctx is canceled, or ErrAlreadyExists without modifying
// the stored bytes if m is already populated.
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

// SaveIfMatch atomically replaces the bytes stored in m with a defensive copy of data
// only if m is currently populated and the SHA-256 digest of its stored bytes equals
// expectedDigest.
//
// SaveIfMatch returns ctx.Err() if ctx is canceled, or ErrConcurrentModification without
// modifying m if m is empty or its current SHA-256 digest differs from expectedDigest.
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
