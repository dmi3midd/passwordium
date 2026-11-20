package passwordium

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMemoryStorage(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()

	if _, err := store.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty Load err = %v, want ErrNotFound", err)
	}

	payload := []byte("encrypted-vault-bytes")
	if err := store.Save(ctx, payload); err != nil {
		t.Fatalf("Save: %v", err)
	}
	payload[0] ^= 0xff

	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(loaded, []byte("encrypted-vault-bytes")) {
		t.Fatalf("Load = %q, want %q", loaded, "encrypted-vault-bytes")
	}

	loaded[0] ^= 0xff
	loaded2, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if !bytes.Equal(loaded2, []byte("encrypted-vault-bytes")) {
		t.Fatal("MemoryStorage leaked mutable internal slice")
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Save(cancelCtx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Save err = %v, want context.Canceled", err)
	}
	if _, err := store.Load(cancelCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Load err = %v, want context.Canceled", err)
	}

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range 20 {
				if (i+j)%2 == 0 {
					_ = store.Save(ctx, []byte{byte(i), byte(j)})
				} else {
					_, _ = store.Load(ctx)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestFileStorage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "vault.psdm")
	store := NewFileStorage(path)
	ctx := context.Background()

	if _, err := store.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file Load err = %v, want ErrNotFound", err)
	}

	first := []byte("first-version-bytes")
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("Save #1: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file perm = %o, want 0600", perm)
	}

	got, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load #1: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("Load #1 = %q, want %q", got, first)
	}

	second := []byte("second-version-bytes-updated")
	if err := store.Save(ctx, second); err != nil {
		t.Fatalf("Save #2: %v", err)
	}
	got2, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if !bytes.Equal(got2, second) {
		t.Fatalf("Load #2 = %q, want %q", got2, second)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "vault.psdm" {
		t.Fatalf("unexpected files in dir: %+v", entries)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Save(cancelCtx, []byte("should-not-write")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Save err = %v, want context.Canceled", err)
	}
	got3, err := store.Load(ctx)
	if err != nil || !bytes.Equal(got3, second) {
		t.Fatalf("file mutated on canceled Save: got=%q err=%v", got3, err)
	}
}

// FINDING-03: bounded reads and rejection of non-regular files.
func TestFileStorageLoadHardening(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()

	t.Run("size_limit", func(t *testing.T) {
		path := filepath.Join(dir, "big.psdm")
		if err := os.WriteFile(path, bytes.Repeat([]byte{0xAB}, 1025), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := NewFileStorage(path, WithMaxFileSize(1024)).Load(ctx); !errors.Is(err, ErrVaultTooLarge) {
			t.Fatalf("oversized Load err = %v, want ErrVaultTooLarge", err)
		}
		data, err := NewFileStorage(path, WithMaxFileSize(1025)).Load(ctx)
		if err != nil || len(data) != 1025 {
			t.Fatalf("Load at exact limit: len=%d err=%v", len(data), err)
		}
		if _, err := NewFileStorage(path, WithMaxFileSize(0)).Load(ctx); err == nil {
			t.Fatal("non-positive max size must be rejected")
		}
	})

	t.Run("symlink_rejected", func(t *testing.T) {
		target := filepath.Join(dir, "target.psdm")
		if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		link := filepath.Join(dir, "link.psdm")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unsupported: %v", err)
		}
		if _, err := NewFileStorage(link).Load(ctx); !errors.Is(err, ErrInvalidStorageFile) {
			t.Fatalf("symlink Load err = %v, want ErrInvalidStorageFile", err)
		}
	})

	t.Run("directory_rejected", func(t *testing.T) {
		sub := filepath.Join(dir, "subdir")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if _, err := NewFileStorage(sub).Load(ctx); !errors.Is(err, ErrInvalidStorageFile) {
			t.Fatalf("directory Load err = %v, want ErrInvalidStorageFile", err)
		}
	})

	t.Run("empty_path", func(t *testing.T) {
		if _, err := NewFileStorage("").Load(ctx); err == nil {
			t.Fatal("empty path Load must fail")
		}
		if err := NewFileStorage("").Save(ctx, []byte("x")); err == nil {
			t.Fatal("empty path Save must fail")
		}
	})
}
