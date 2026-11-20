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

	// Mutating caller slice after Save must not affect stored bytes.
	payload[0] ^= 0xff

	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(loaded, []byte("encrypted-vault-bytes")) {
		t.Fatalf("Load = %q, want %q", loaded, "encrypted-vault-bytes")
	}

	// Mutating returned slice must not affect subsequent Load.
	loaded[0] ^= 0xff
	loaded2, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load #2: %v", err)
	}
	if !bytes.Equal(loaded2, []byte("encrypted-vault-bytes")) {
		t.Fatal("MemoryStorage leaked mutable internal slice")
	}

	// Context cancellation.
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Save(cancelCtx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Save err = %v, want context.Canceled", err)
	}
	if _, err := store.Load(cancelCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Load err = %v, want context.Canceled", err)
	}

	// Concurrent reads and writes under -race.
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

	// Overwrite atomically and check no temp files remain.
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

	// Context cancellation should not write or overwrite.
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
