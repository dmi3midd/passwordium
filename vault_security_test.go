package passwordium

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/dmi3midd/passwordium/internal/crypto"
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
