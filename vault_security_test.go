package passwordium

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dmi3midd/passwordium/internal/crypto"
	"github.com/dmi3midd/passwordium/internal/vaultpb"
	"google.golang.org/protobuf/proto"
)

// craftEnvelope builds a syntactically valid envelope with arbitrary header params
// and a junk ciphertext, simulating an attacker-modified vault file.
func craftEnvelope(p Argon2Params) []byte {
	hdr := header{Version: currentVersion, Params: p}.marshal()
	return packEnvelope(hdr, make([]byte, crypto.NonceSize), make([]byte, crypto.Overhead+8))
}

// FINDING-01: Open must reject resource-exhausting headers before running Argon2id.
func TestOpenRejectsDoSHeadersBeforeKDF(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := map[string]Argon2Params{
		"hard_max_everything": {Time: 100, MemoryKiB: 4 * 1024 * 1024, Threads: 255},
		"memory_4GiB":         {Time: 1, MemoryKiB: 4 * 1024 * 1024, Threads: 1},
		"threads_255":         {Time: 1, MemoryKiB: 64, Threads: 255},
		"time_100":            {Time: 100, MemoryKiB: 64, Threads: 1},
		"work_product":        {Time: 16, MemoryKiB: 512 * 1024, Threads: 1},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := NewMemoryStorage()
			if err := store.Save(ctx, craftEnvelope(p)); err != nil {
				t.Fatalf("Save: %v", err)
			}
			start := time.Now()
			_, err := Open(ctx, store, []byte("any"))
			if !errors.Is(err, ErrInvalidArgon2Params) {
				t.Fatalf("Open err = %v, want ErrInvalidArgon2Params", err)
			}
			// Rejection must happen during header parsing, not after a multi-GiB KDF run.
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("Open took %v; header limits were not applied before KDF", elapsed)
			}
		})
	}
}

// FINDING-01: WithMaxArgon2Params tightens or raises limits per call and validates its own input.
func TestOpenWithMaxArgon2Params(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	pass := []byte("max-params-pass")
	store := NewMemoryStorage()
	v, err := Create(ctx, store, pass, fastTestArgon2()) // Time=1, MemoryKiB=64, Threads=1
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = v.Close()

	// Tighter than the stored params -> rejected.
	if _, err := Open(ctx, store, pass, WithMaxArgon2Params(Argon2Params{Time: 1, MemoryKiB: 32, Threads: 1})); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("tight limit Open err = %v, want ErrInvalidArgon2Params", err)
	}
	// Exactly matching -> accepted.
	v2, err := Open(ctx, store, pass, WithMaxArgon2Params(Argon2Params{Time: 1, MemoryKiB: 64, Threads: 1}))
	if err != nil {
		t.Fatalf("exact limit Open: %v", err)
	}
	_ = v2.Close()

	// Invalid limits themselves -> rejected.
	if _, err := Open(ctx, store, pass, WithMaxArgon2Params(Argon2Params{Time: 0, MemoryKiB: 64, Threads: 1})); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("invalid limit Open err = %v, want ErrInvalidArgon2Params", err)
	}

	// Raised limits let a header past parsing that defaults would reject (Time=20 > 16);
	// the junk ciphertext then fails authentication.
	raisedStore := NewMemoryStorage()
	if err := raisedStore.Save(ctx, craftEnvelope(Argon2Params{Time: 20, MemoryKiB: 64, Threads: 1})); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Open(ctx, raisedStore, pass); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("default-limit Open err = %v, want ErrInvalidArgon2Params", err)
	}
	if _, err := Open(ctx, raisedStore, pass, WithMaxArgon2Params(Argon2Params{Time: 32, MemoryKiB: 64, Threads: 1})); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("raised-limit Open err = %v, want ErrInvalidPassword", err)
	}
}

// FINDING-02: Create rejects weak Argon2id memory (KiB/MiB confusion); helper avoids it.
func TestCreateRejectsWeakArgon2Params(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()

	weak := Argon2Params{Time: 3, MemoryKiB: 64, Threads: 2} // developer meant 64 MiB
	if _, err := Create(ctx, store, []byte("pw"), WithArgon2Params(weak)); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("Create(weak) err = %v, want ErrInvalidArgon2Params", err)
	}
	if _, err := store.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected Create must not persist anything, Load err = %v", err)
	}

	if got := Argon2ParamsMiB(3, 64, 2); got != (Argon2Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 2}) {
		t.Fatalf("Argon2ParamsMiB = %+v", got)
	}
	if got := Argon2ParamsMiB(1, math.MaxUint32, 1); got.MemoryKiB != math.MaxUint32 {
		t.Fatalf("Argon2ParamsMiB overflow must saturate, got %d", got.MemoryKiB)
	}
	if _, err := Create(ctx, store, []byte("pw"), WithArgon2Params(Argon2ParamsMiB(1, math.MaxUint32, 1))); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("Create(overflowed) err = %v, want ErrInvalidArgon2Params", err)
	}

	// The 16 MiB floor itself is accepted.
	v, err := Create(ctx, store, []byte("pw"), WithArgon2Params(Argon2ParamsMiB(1, 16, 1)))
	if err != nil {
		t.Fatalf("Create(16 MiB): %v", err)
	}
	_ = v.Close()
}

// FINDING-04: the Vault must not retain any raw key material, only AEAD instances.
func TestVaultRetainsNoRawKeyFields(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(Vault{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Type == reflect.TypeOf([]byte(nil)) {
			t.Errorf("Vault field %q is a raw []byte; key material must not be retained", f.Name)
		}
	}
}

// FINDING-06: DeleteContext honors cancellation and rolls back on save failure.
func TestDeleteContextHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	v, err := Create(ctx, store, []byte("del-ctx"), fastTestArgon2(), WithAutoSave(true))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = v.Close() }()

	id, err := v.Put(ctx, EntryMeta{Title: "keep"}, Secret{Password: "pw"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := v.DeleteContext(canceled, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("DeleteContext(canceled) err = %v, want context.Canceled", err)
	}
	if _, err := v.GetSecret(id); err != nil {
		t.Fatalf("entry must survive canceled delete: %v", err)
	}

	// Context expiring inside Storage.Save must roll back the deletion.
	blocking := &ctxStorage{inner: store}
	v.mu.Lock()
	v.store = blocking
	v.mu.Unlock()
	deadline, cancel2 := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel2()
	if err := v.DeleteContext(deadline, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DeleteContext(deadline) err = %v, want DeadlineExceeded", err)
	}
	if _, err := v.GetMeta(id); err != nil {
		t.Fatalf("entry must be restored after failed autosave: %v", err)
	}

	v.mu.Lock()
	v.store = store
	v.mu.Unlock()
	if err := v.DeleteContext(ctx, id); err != nil {
		t.Fatalf("DeleteContext: %v", err)
	}
	if _, err := v.GetMeta(id); !errors.Is(err, ErrEntryNotFound) {
		t.Fatalf("GetMeta after delete err = %v", err)
	}
}

// ctxStorage blocks Save until ctx is done, emulating a hung network backend.
type ctxStorage struct{ inner Storage }

func (c *ctxStorage) Load(ctx context.Context) ([]byte, error) { return c.inner.Load(ctx) }
func (c *ctxStorage) Save(ctx context.Context, _ []byte) error {
	<-ctx.Done()
	return ctx.Err()
}

// FINDING-07: Create refuses to overwrite an existing vault unless WithOverwrite(true).
func TestCreateDoesNotOverwriteExistingVault(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	pass := []byte("original")

	v, err := Create(ctx, store, pass, fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id, err := v.Put(ctx, EntryMeta{Title: "precious"}, Secret{Password: "keep-me"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(ctx); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_ = v.Close()

	if _, err := Create(ctx, store, []byte("attacker"), fastTestArgon2()); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("second Create err = %v, want ErrAlreadyExists", err)
	}

	reopened, err := Open(ctx, store, pass)
	if err != nil {
		t.Fatalf("original vault must still open: %v", err)
	}
	if sec, err := reopened.GetSecret(id); err != nil || sec.Password != "keep-me" {
		t.Fatalf("original data lost: %+v, %v", sec, err)
	}
	_ = reopened.Close()

	fresh, err := Create(ctx, store, []byte("new-owner"), fastTestArgon2(), WithOverwrite(true))
	if err != nil {
		t.Fatalf("Create(WithOverwrite): %v", err)
	}
	if fresh.Len() != 0 {
		t.Fatalf("overwritten vault Len = %d, want 0", fresh.Len())
	}
	_ = fresh.Close()
	if _, err := Open(ctx, store, pass); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("old password after overwrite err = %v, want ErrInvalidPassword", err)
	}
}

// FINDING-08: options are split by call site; WithAutoSave works for Open too.
// (Passing WithArgon2Params to Open, or WithMaxArgon2Params to Create, is a compile error.)
func TestOpenWithAutoSave(t *testing.T) {
	t.Parallel()

	var _ CreateOption = WithAutoSave(true)
	var _ OpenOption = WithAutoSave(true)
	var _ CreateOption = WithArgon2Params(DefaultArgon2Params())
	var _ CreateOption = WithOverwrite(true)
	var _ OpenOption = WithMaxArgon2Params(DefaultMaxArgon2Params())
	if _, ok := WithArgon2Params(DefaultArgon2Params()).(OpenOption); ok {
		t.Fatal("WithArgon2Params must not be accepted by Open")
	}
	if _, ok := WithMaxArgon2Params(DefaultMaxArgon2Params()).(CreateOption); ok {
		t.Fatal("WithMaxArgon2Params must not be accepted by Create")
	}

	ctx := context.Background()
	store := NewMemoryStorage()
	pass := []byte("open-autosave")
	v, err := Create(ctx, store, pass, fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = v.Close()

	v2, err := Open(ctx, store, pass, WithAutoSave(true))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id, err := v2.Put(ctx, EntryMeta{Title: "auto"}, Secret{Password: "persisted"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if v2.Dirty() {
		t.Fatal("autosave Put left vault dirty")
	}

	reader, err := Open(ctx, store, pass)
	if err != nil {
		t.Fatalf("reader Open: %v", err)
	}
	defer func() { _ = reader.Close() }()
	if sec, err := reader.GetSecret(id); err != nil || sec.Password != "persisted" {
		t.Fatalf("autosaved entry not persisted: %+v, %v", sec, err)
	}
	_ = v2.Close()
}

// FINDING-09: removing redundant map clones must not introduce aliasing.
func TestCustomFieldsNotAliased(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	v, err := Create(ctx, NewMemoryStorage(), []byte("alias"), fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = v.Close() }()

	fields := map[string]string{"otp": "111111"}
	id, err := v.Put(ctx, EntryMeta{Title: "x"}, Secret{CustomFields: fields})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	fields["otp"] = "MUTATED"
	fields["extra"] = "added"

	s1, err := v.GetSecret(id)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if len(s1.CustomFields) != 1 || s1.CustomFields["otp"] != "111111" {
		t.Fatalf("caller mutation after Put leaked into vault: %+v", s1.CustomFields)
	}
	s1.CustomFields["otp"] = "MUTATED"

	s2, err := v.GetSecret(id)
	if err != nil || s2.CustomFields["otp"] != "111111" {
		t.Fatalf("mutation of GetSecret result leaked: %+v, %v", s2.CustomFields, err)
	}
}

// Sanity: the craftEnvelope header layout matches what parseHeader expects.
func TestCraftEnvelopeLayout(t *testing.T) {
	t.Parallel()
	raw := craftEnvelope(Argon2Params{Time: 2, MemoryKiB: 128, Threads: 3})
	if binary.BigEndian.Uint32(raw[38:42]) != 2 || binary.BigEndian.Uint32(raw[42:46]) != 128 || binary.BigEndian.Uint32(raw[46:50]) != 3 {
		t.Fatal("craftEnvelope wrote unexpected header params")
	}
}

// Audit FINDING-01: concurrent Create calls without WithOverwrite(true) must not overwrite
// each other, and Create must not read the entire existing file into memory just to fail.
func TestConcurrentCreateDoesNotOverwriteAndAvoidsFullRead(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// 1. Existing oversized file is detected via Lstat (Exists) without reading it into RAM.
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.psdm")
	bigStore := NewFileStorage(path, WithMaxFileSize(128))
	if err := bigStore.Save(ctx, bytes.Repeat([]byte{0x42}, 1024)); err != nil {
		t.Fatalf("Save oversized fixture: %v", err)
	}
	if _, err := Create(ctx, bigStore, []byte("pw"), fastTestArgon2()); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Create on existing oversized file err = %v, want ErrAlreadyExists", err)
	}

	// 2. Concurrent Create race on both MemoryStorage and FileStorage.
	backends := []struct {
		name  string
		store func(t *testing.T) Storage
	}{
		{
			name:  "MemoryStorage",
			store: func(t *testing.T) Storage { return NewMemoryStorage() },
		},
		{
			name: "FileStorage",
			store: func(t *testing.T) Storage {
				return NewFileStorage(filepath.Join(t.TempDir(), "race.psdm"))
			},
		},
	}

	for _, tc := range backends {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store(t)

			const contenders = 6
			start := make(chan struct{})
			type result struct {
				pass []byte
				v    *Vault
				err  error
			}
			results := make(chan result, contenders)

			var wg sync.WaitGroup
			for i := range contenders {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					pw := []byte(fmt.Sprintf("contender-pass-%d", idx))
					<-start
					v, err := Create(ctx, store, pw, fastTestArgon2())
					results <- result{pass: pw, v: v, err: err}
				}(i)
			}
			close(start)
			wg.Wait()
			close(results)

			var winners []result
			alreadyExistsCount := 0
			for r := range results {
				switch {
				case r.err == nil:
					winners = append(winners, r)
				case errors.Is(r.err, ErrAlreadyExists):
					alreadyExistsCount++
				default:
					t.Fatalf("unexpected Create error: %v", r.err)
				}
			}

			if len(winners) != 1 || alreadyExistsCount != contenders-1 {
				t.Fatalf("winners=%d alreadyExists=%d, want 1 and %d", len(winners), alreadyExistsCount, contenders-1)
			}
			_ = winners[0].v.Close()

			// The persisted vault must belong to the sole winner.
			reopened, err := Open(ctx, store, winners[0].pass)
			if err != nil {
				t.Fatalf("winner password failed to open persisted vault: %v", err)
			}
			_ = reopened.Close()
		})
	}
}

// Audit FINDING-02: Create rejects parameters above DefaultArgon2Limits so a newly created
// vault can always be opened by default Open; WithMaxArgon2Params(DefaultMaxArgon2Params())
// preserves the default 2 GiB-passes MaxWork bound unless overridden.
func TestArgon2CreateUpperBoundsAndMaxWorkPreservation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()

	overDefaultCases := map[string]Argon2Params{
		"time_over_default":    {Time: crypto.DefaultMaxArgonTime + 1, MemoryKiB: 16 * 1024, Threads: 1},
		"memory_over_default":  {Time: 1, MemoryKiB: crypto.DefaultMaxArgonMemoryKiB + 1024, Threads: 1},
		"threads_over_default": {Time: 1, MemoryKiB: 16 * 1024, Threads: crypto.DefaultMaxArgonThreads + 1},
		"work_over_default":    {Time: 8, MemoryKiB: crypto.DefaultMaxArgonMemoryKiB, Threads: 1}, // 4 GiB-passes > 2 GiB-passes
	}
	for name, p := range overDefaultCases {
		if _, err := Create(ctx, store, []byte("pw"), WithArgon2Params(p)); !errors.Is(err, ErrInvalidArgon2Params) {
			t.Fatalf("Create(%s: %+v) err = %v, want ErrInvalidArgon2Params", name, p, err)
		}
	}

	// Passing DefaultMaxArgon2Params() (or tweaking Threads on it) to WithMaxArgon2Params
	// must NOT weaken MaxWork from 2 GiB-passes to 8 GiB-passes.
	workHeavyHeader := Argon2Params{Time: 8, MemoryKiB: 512 * 1024, Threads: 1} // 4 GiB-passes
	if err := store.Save(ctx, craftEnvelope(workHeavyHeader)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	maxCfg := DefaultMaxArgon2Params()
	maxCfg.Threads = 2
	start := time.Now()
	if _, err := Open(ctx, store, []byte("pw"), WithMaxArgon2Params(maxCfg)); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("Open with DefaultMaxArgon2Params should enforce 2 GiB-passes MaxWork, got err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Open took %v; MaxWork check did not run before KDF", elapsed)
	}

	// WithMaxArgon2Work can tighten or explicitly override the work product cap.
	smallHeader := Argon2Params{Time: 4, MemoryKiB: 64, Threads: 1} // work = 256 KiB-passes
	if err := store.Save(ctx, craftEnvelope(smallHeader)); err != nil {
		t.Fatalf("Save smallHeader: %v", err)
	}
	if _, err := Open(ctx, store, []byte("pw"), WithMaxArgon2Work(128)); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("Open under tight WithMaxArgon2Work err = %v, want ErrInvalidArgon2Params", err)
	}
	if _, err := Open(ctx, store, []byte("pw"), WithMaxArgon2Work(256)); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Open at exact WithMaxArgon2Work err = %v, want ErrInvalidPassword", err)
	}
}

// Audit FINDING-04: Secret redacts its contents in fmt and log/slog output.
func TestSecretRedactionInFmtAndSlog(t *testing.T) {
	t.Parallel()

	sec := Secret{
		Password:     "ultra-secret-password-98765",
		Notes:        "recovery phrase alpha beta gamma",
		CustomFields: map[string]string{"totp": "JBSWY3DPEHPK3PXP"},
	}

	formatted := []string{
		fmt.Sprint(sec),
		fmt.Sprintf("%s", sec),
		fmt.Sprintf("%v", sec),
		fmt.Sprintf("%+v", sec),
		fmt.Sprintf("%#v", sec),
		fmt.Sprintf("%+v", &sec),
		fmt.Sprintf("%#v", &sec),
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	logger.Info("loaded secret", "secret", sec, "secret_ptr", &sec)
	formatted = append(formatted, logBuf.String())

	for _, out := range formatted {
		for _, sensitive := range []string{sec.Password, sec.Notes, "JBSWY3DPEHPK3PXP"} {
			if strings.Contains(out, sensitive) {
				t.Fatalf("sensitive value %q leaked in output %q", sensitive, out)
			}
		}
	}
}

// Audit FINDING-05: CloseWithSave persists dirty state before closing and keeps the
// vault open on save failure so in-memory changes are never silently lost.
func TestVaultCloseWithSave(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mem := NewMemoryStorage()
	fs := &failingStorage{inner: mem, err: errors.New("io failure")}
	pass := []byte("close-with-save-pass")

	v, err := Create(ctx, fs, pass, fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	id, err := v.Put(ctx, EntryMeta{Title: "Unsaved"}, Secret{Password: "must-survive"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !v.Dirty() {
		t.Fatal("vault must be dirty after Put without autosave")
	}

	// Failing save during CloseWithSave must leave the vault open and dirty.
	fs.failSave.Store(true)
	if err := v.CloseWithSave(ctx); !errors.Is(err, fs.err) {
		t.Fatalf("CloseWithSave on failing storage err = %v, want %v", err, fs.err)
	}
	if !v.Dirty() || v.Len() != 1 {
		t.Fatalf("vault state lost after failed CloseWithSave: Dirty=%v Len=%d", v.Dirty(), v.Len())
	}

	// Once storage recovers, CloseWithSave persists and closes cleanly.
	fs.failSave.Store(false)
	if err := v.CloseWithSave(ctx); err != nil {
		t.Fatalf("CloseWithSave: %v", err)
	}
	if err := v.CloseWithSave(ctx); err != nil {
		t.Fatalf("idempotent CloseWithSave: %v", err)
	}

	reopened, err := Open(ctx, mem, pass)
	if err != nil {
		t.Fatalf("Open after CloseWithSave: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	sec, err := reopened.GetSecret(id)
	if err != nil || sec.Password != "must-survive" {
		t.Fatalf("GetSecret after CloseWithSave = %q, err=%v", sec.Password, err)
	}
}

// Audit RISK-01: concurrent modification of the underlying storage by another Vault
// instance is detected on Save (and Put/Delete with WithAutoSave) instead of silently
// overwriting newer data.
func TestConcurrentVaultModificationDetected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backends := []struct {
		name  string
		store func(t *testing.T) Storage
	}{
		{
			name:  "MemoryStorage",
			store: func(t *testing.T) Storage { return NewMemoryStorage() },
		},
		{
			name: "FileStorage",
			store: func(t *testing.T) Storage {
				return NewFileStorage(filepath.Join(t.TempDir(), "occ.psdm"))
			},
		},
	}

	for _, tc := range backends {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store(t)
			pass := []byte("occ-master-pass")

			vInit, err := Create(ctx, store, pass, fastTestArgon2())
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			idSeed, err := vInit.Put(ctx, EntryMeta{Title: "Seed"}, Secret{Password: "v1"})
			if err != nil {
				t.Fatalf("Put seed: %v", err)
			}
			if err := vInit.Save(ctx); err != nil {
				t.Fatalf("Save seed: %v", err)
			}
			_ = vInit.Close()

			// Two separate sessions open the same vault concurrently.
			v1, err := Open(ctx, store, pass)
			if err != nil {
				t.Fatalf("Open v1: %v", err)
			}
			defer func() { _ = v1.Close() }()

			v2, err := Open(ctx, store, pass, WithAutoSave(true))
			if err != nil {
				t.Fatalf("Open v2: %v", err)
			}
			defer func() { _ = v2.Close() }()

			// Session 1 updates and saves first.
			if _, err := v1.Put(ctx, EntryMeta{ID: idSeed, Title: "Seed from v1"}, Secret{Password: "v1-updated"}); err != nil {
				t.Fatalf("v1.Put: %v", err)
			}
			if err := v1.Save(ctx); err != nil {
				t.Fatalf("v1.Save: %v", err)
			}

			// Session 2 now has a stale view; its auto-save Put must fail with ErrConcurrentModification
			// and roll back its in-memory mutation.
			if _, err := v2.Put(ctx, EntryMeta{Title: "Stale write"}, Secret{Password: "stale"}); !errors.Is(err, ErrConcurrentModification) {
				t.Fatalf("v2.Put on stale vault err = %v, want ErrConcurrentModification", err)
			}
			if v2.Len() != 1 || v2.Dirty() {
				t.Fatalf("v2 state after failed autosave: Len=%d Dirty=%v", v2.Len(), v2.Dirty())
			}

			// Verify v1's saved data is intact on disk/memory.
			v3, err := Open(ctx, store, pass)
			if err != nil {
				t.Fatalf("Open v3: %v", err)
			}
			defer func() { _ = v3.Close() }()
			sec, err := v3.GetSecret(idSeed)
			if err != nil || sec.Password != "v1-updated" {
				t.Fatalf("stored secret after conflict = %q, err=%v", sec.Password, err)
			}
		})
	}
}

// Audit RISK-03: SecretPayload plaintexts are padded to 256-byte blocks before encryption,
// hiding exact password lengths and rejecting invalid padding.
func TestSecretPaddingHidesLengthAndRoundTripsBoundaries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	v, err := Create(ctx, store, []byte("padding-pass"), fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = v.Close() }()

	idShort, err := v.Put(ctx, EntryMeta{Title: "Short"}, Secret{Password: "a"})
	if err != nil {
		t.Fatalf("Put short: %v", err)
	}
	idMedium, err := v.Put(ctx, EntryMeta{Title: "Medium"}, Secret{
		Password: strings.Repeat("p", 80),
		Notes:    strings.Repeat("n", 80),
	})
	if err != nil {
		t.Fatalf("Put medium: %v", err)
	}

	ctShort := len(v.entries[idShort].encryptedSecret)
	ctMedium := len(v.entries[idMedium].encryptedSecret)
	wantBlockCT := secretPadBlockSize + crypto.Overhead
	if ctShort != wantBlockCT || ctMedium != wantBlockCT {
		t.Fatalf("ciphertext sizes = (%d, %d), want both equal to %d", ctShort, ctMedium, wantBlockCT)
	}

	// Verify boundary sizes for padSecret / unpadSecret directly.
	for _, size := range []int{0, 1, 127, 254, 255, 256, 257, 511, 512, 513} {
		orig := bytes.Repeat([]byte{0x5A}, size)
		padded := padSecret(orig)
		if len(padded) == 0 || len(padded)%secretPadBlockSize != 0 {
			t.Fatalf("size=%d: len(padded)=%d is not a positive multiple of %d", size, len(padded), secretPadBlockSize)
		}
		got, err := unpadSecret(padded)
		if err != nil || !bytes.Equal(got, orig) {
			t.Fatalf("size=%d: unpadSecret err=%v len(got)=%d", size, err, len(got))
		}
	}

	// Invalid padding shapes must be rejected with ErrSecretCorrupted.
	for _, bad := range [][]byte{
		nil,
		{},
		make([]byte, secretPadBlockSize-1),
		make([]byte, secretPadBlockSize), // all zeros, missing 0x80 marker
		append(make([]byte, secretPadBlockSize-1), 0x01),
	} {
		if _, err := unpadSecret(bad); !errors.Is(err, ErrSecretCorrupted) {
			t.Fatalf("unpadSecret(%x) err = %v, want ErrSecretCorrupted", bad, err)
		}
	}
}

// Audit Section 5: Open rejects corrupted inner VaultData entries (missing ID, duplicate ID,
// zero version, invalid nonce length, truncated ciphertext, or malformed protobuf), and
// entryAAD remains collision-free when EntryMeta.ID contains colons.
func TestOpenRejectsMalformedInnerEntriesAndColonIDs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	pass := []byte("inner-validation-pass")

	v, err := Create(ctx, store, pass, fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Verify IDs containing colons cannot collide in entryAAD("item:1", 2) vs entryAAD("item", 12).
	if _, err := v.Put(ctx, EntryMeta{ID: "item:1", Title: "Colon1"}, Secret{Password: "pw-colon"}); err != nil {
		t.Fatalf("Put item:1 v1: %v", err)
	}
	if _, err := v.Put(ctx, EntryMeta{ID: "item:1", Title: "Colon1 v2"}, Secret{Password: "pw-colon-v2"}); err != nil {
		t.Fatalf("Put item:1 v2: %v", err)
	}
	if _, err := v.Put(ctx, EntryMeta{ID: "item", Title: "Plain"}, Secret{Password: "pw-plain"}); err != nil {
		t.Fatalf("Put item: %v", err)
	}
	// Advance "item" to version 12.
	for i := 2; i <= 12; i++ {
		if _, err := v.Put(ctx, EntryMeta{ID: "item", Title: "Plain"}, Secret{Password: fmt.Sprintf("pw-plain-v%d", i)}); err != nil {
			t.Fatalf("Put item v%d: %v", i, err)
		}
	}
	// Swapping their encrypted secrets in memory must fail AEAD authentication.
	v.entries["item:1"].secretNonce, v.entries["item"].secretNonce = v.entries["item"].secretNonce, v.entries["item:1"].secretNonce
	v.entries["item:1"].encryptedSecret, v.entries["item"].encryptedSecret = v.entries["item"].encryptedSecret, v.entries["item:1"].encryptedSecret
	if _, err := v.GetSecret("item:1"); !errors.Is(err, ErrSecretCorrupted) {
		t.Fatalf("swapped colon-ID GetSecret(item:1) err = %v, want ErrSecretCorrupted", err)
	}
	if _, err := v.GetSecret("item"); !errors.Is(err, ErrSecretCorrupted) {
		t.Fatalf("swapped colon-ID GetSecret(item) err = %v, want ErrSecretCorrupted", err)
	}

	indexKey := testIndexKey(t, store, pass)
	raw, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	hdrBytes := raw[:headerSize]
	_ = v.Close()

	validNonce := make([]byte, crypto.NonceSize)
	validSecret := make([]byte, crypto.Overhead+secretPadBlockSize)

	badVaults := map[string]*vaultpb.VaultData{
		"missing_id": {
			Version: 1,
			Entries: []*vaultpb.Entry{{Id: "", Version: 1, SecretNonce: validNonce, EncryptedSecret: validSecret}},
		},
		"zero_version": {
			Version: 1,
			Entries: []*vaultpb.Entry{{Id: "e1", Version: 0, SecretNonce: validNonce, EncryptedSecret: validSecret}},
		},
		"bad_nonce_size": {
			Version: 1,
			Entries: []*vaultpb.Entry{{Id: "e1", Version: 1, SecretNonce: []byte("short"), EncryptedSecret: validSecret}},
		},
		"truncated_secret": {
			Version: 1,
			Entries: []*vaultpb.Entry{{Id: "e1", Version: 1, SecretNonce: validNonce, EncryptedSecret: []byte("short")}},
		},
		"duplicate_id": {
			Version: 1,
			Entries: []*vaultpb.Entry{
				{Id: "dup", Version: 1, SecretNonce: validNonce, EncryptedSecret: validSecret},
				{Id: "dup", Version: 1, SecretNonce: validNonce, EncryptedSecret: validSecret},
			},
		},
	}

	for name, pb := range badVaults {
		t.Run(name, func(t *testing.T) {
			plain, err := proto.Marshal(pb)
			if err != nil {
				t.Fatalf("proto.Marshal: %v", err)
			}
			nonce, ct, err := crypto.Encrypt(indexKey, plain, hdrBytes)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			s := NewMemoryStorage()
			if err := s.Save(ctx, packEnvelope(hdrBytes, nonce, ct)); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if _, err := Open(ctx, s, pass); !errors.Is(err, ErrCorruptedVault) {
				t.Fatalf("Open(%s) err = %v, want ErrCorruptedVault", name, err)
			}
		})
	}

	// Invalid protobuf bytes inside a validly authenticated outer envelope.
	nonce, ct, err := crypto.Encrypt(indexKey, []byte{0xff, 0xff, 0xff, 0xff}, hdrBytes)
	if err != nil {
		t.Fatalf("Encrypt bad proto: %v", err)
	}
	badProtoStore := NewMemoryStorage()
	if err := badProtoStore.Save(ctx, packEnvelope(hdrBytes, nonce, ct)); err != nil {
		t.Fatalf("Save bad proto: %v", err)
	}
	if _, err := Open(ctx, badProtoStore, pass); !errors.Is(err, ErrCorruptedVault) {
		t.Fatalf("Open(bad_protobuf) err = %v, want ErrCorruptedVault", err)
	}
}

// FuzzUnpackEnvelope verifies that parsing arbitrary untrusted bytes never panics
// and always enforces header format and Argon2id resource limits.
func FuzzUnpackEnvelope(f *testing.F) {
	limits := crypto.DefaultArgon2Limits()
	f.Add([]byte{})
	f.Add([]byte("PSDM"))
	f.Add(header{Version: currentVersion, Params: DefaultArgon2Params()}.marshal())
	f.Add(craftEnvelope(DefaultArgon2Params()))
	f.Add(craftEnvelope(Argon2Params{Time: 100, MemoryKiB: 4 * 1024 * 1024, Threads: 255}))

	f.Fuzz(func(t *testing.T, data []byte) {
		hdr, hdrBytes, nonce, ct, err := unpackEnvelope(data, limits)
		if err != nil {
			return
		}
		if len(hdrBytes) != headerSize || len(nonce) != crypto.NonceSize || len(ct) < crypto.Overhead {
			t.Fatalf("unpackEnvelope returned invalid slice lengths: hdr=%d nonce=%d ct=%d", len(hdrBytes), len(nonce), len(ct))
		}
		if err := hdr.Params.validateLimits(limits); err != nil {
			t.Fatalf("unpackEnvelope accepted header violating limits: %v", err)
		}
	})
}

// FuzzPadUnpadSecret verifies that padSecret/unpadSecret round-trip arbitrary payloads
// and unpadSecret never panics on arbitrary corrupted slices.
func FuzzPadUnpadSecret(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x80})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xAB}, 255))
	f.Add(bytes.Repeat([]byte{0xCD}, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		padded := padSecret(data)
		got, err := unpadSecret(padded)
		if err != nil {
			t.Fatalf("unpadSecret(padSecret(data)) failed: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(data))
		}
		_, _ = unpadSecret(data)
	})
}
