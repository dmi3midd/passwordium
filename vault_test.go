package passwordium

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dmi3midd/passwordium/internal/crypto"
	"github.com/dmi3midd/passwordium/internal/vaultpb"
	"google.golang.org/protobuf/proto"
)

var uuidV4Regex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// fastTestArgon2 uses the unexported weak-params hook so unit tests stay fast;
// public callers cannot go below the 16 MiB Create floor.
func fastTestArgon2() CreateExportOption {
	return withUnsafeArgon2Params(Argon2Params{
		Time:      1,
		MemoryKiB: 64,
		Threads:   1,
	})
}

// testIndexKey re-derives indexKey from the stored header so tests can craft
// validly authenticated outer envelopes (the Vault itself no longer retains raw keys).
func testIndexKey(t *testing.T, store Storage, pass []byte) []byte {
	t.Helper()
	raw, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("testIndexKey Load: %v", err)
	}
	hdr, err := parseHeader(raw, crypto.DefaultArgon2Limits())
	if err != nil {
		t.Fatalf("testIndexKey parseHeader: %v", err)
	}
	mk, err := crypto.DeriveMasterKey(pass, hdr.Salt[:], hdr.Params.toCrypto())
	if err != nil {
		t.Fatalf("testIndexKey DeriveMasterKey: %v", err)
	}
	defer crypto.ZeroBytes(mk)
	ik, err := crypto.DeriveSubKey(mk, hkdfContextIndex)
	if err != nil {
		t.Fatalf("testIndexKey DeriveSubKey: %v", err)
	}
	return ik
}

func TestVaultLifecycleMemoryAndFile(t *testing.T) {
	t.Parallel()

	backends := []struct {
		name  string
		store func(t *testing.T) Storage
	}{
		{
			name: "MemoryStorage",
			store: func(t *testing.T) Storage {
				return NewMemoryStorage()
			},
		},
		{
			name: "FileStorage",
			store: func(t *testing.T) Storage {
				return NewFileStorage(filepath.Join(t.TempDir(), "vault.psdm"))
			},
		},
	}

	for _, tc := range backends {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			store := tc.store(t)
			masterPass := []byte("correct-horse-battery-staple!")
			origPassCopy := bytes.Clone(masterPass)

			v, err := Create(ctx, store, masterPass, fastTestArgon2())
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if !bytes.Equal(masterPass, origPassCopy) {
				t.Fatal("Create mutated caller masterPassword slice")
			}
			if v.Dirty() {
				t.Fatal("newly created vault should not be dirty")
			}
			if v.Len() != 0 {
				t.Fatalf("Len() = %d, want 0", v.Len())
			}

			// Put #1: auto-generated UUIDv4.
			id1, err := v.Put(ctx, EntryMeta{
				Title:    "GitHub",
				Username: "octocat",
				URL:      "https://github.com",
				Tags:     []string{"Dev", "Code"},
			}, Secret{
				Password: "gh-secret-password-v1",
				Notes:    "Primary dev account",
				CustomFields: map[string]string{
					"recovery_code": "1234-5678",
				},
			})
			if err != nil {
				t.Fatalf("Put #1: %v", err)
			}
			if !uuidV4Regex.MatchString(id1) {
				t.Fatalf("generated ID %q is not valid UUIDv4", id1)
			}
			if !v.Dirty() {
				t.Fatal("vault should be dirty after Put")
			}

			// Put #2: explicit ID.
			id2, err := v.Put(ctx, EntryMeta{
				ID:       "aws-prod-root",
				Title:    "AWS Production",
				Username: "admin@example.com",
				URL:      "https://console.aws.amazon.com",
				Tags:     []string{"Cloud", "Work"},
			}, Secret{
				Password: "aws-root-password",
				Notes:    "MFA enabled",
			})
			if err != nil {
				t.Fatalf("Put #2: %v", err)
			}
			if id2 != "aws-prod-root" {
				t.Fatalf("id2 = %q, want aws-prod-root", id2)
			}

			// Put #3: another entry for search coverage.
			id3, err := v.Put(ctx, EntryMeta{
				Title:    "Personal Email",
				Username: "alice@mail.example",
				URL:      "https://mail.example",
				Tags:     []string{"Personal", "Dev"},
			}, Secret{
				Password: "email-password",
			})
			if err != nil {
				t.Fatalf("Put #3: %v", err)
			}

			if v.Len() != 3 {
				t.Fatalf("Len() = %d, want 3", v.Len())
			}

			// Update entry #1 (version increments from 1 -> 2, CreatedAt preserved).
			meta1V1, err := v.GetMeta(id1)
			if err != nil {
				t.Fatalf("GetMeta(id1 v1): %v", err)
			}
			if meta1V1.Version != 1 {
				t.Fatalf("v1 Version = %d, want 1", meta1V1.Version)
			}

			gotID, err := v.Put(ctx, EntryMeta{
				ID:       id1,
				Title:    "GitHub Enterprise",
				Username: "octocat-corp",
				URL:      "https://github.example.com",
				Tags:     []string{"Dev", "Work"},
			}, Secret{
				Password: "gh-secret-password-v2",
				Notes:    "Rotated password",
				CustomFields: map[string]string{
					"recovery_code": "9999-0000",
					"token":         "tok_abc",
				},
			})
			if err != nil {
				t.Fatalf("Put update #1: %v", err)
			}
			if gotID != id1 {
				t.Fatalf("updated ID = %q, want %q", gotID, id1)
			}

			meta1V2, err := v.GetMeta(id1)
			if err != nil {
				t.Fatalf("GetMeta(id1 v2): %v", err)
			}
			if meta1V2.Version != 2 {
				t.Fatalf("v2 Version = %d, want 2", meta1V2.Version)
			}
			if !meta1V2.CreatedAt.Equal(meta1V1.CreatedAt) {
				t.Fatalf("CreatedAt changed on update: %v -> %v", meta1V1.CreatedAt, meta1V2.CreatedAt)
			}
			if meta1V2.UpdatedAt.Before(meta1V1.CreatedAt) {
				t.Fatalf("UpdatedAt %v < CreatedAt %v", meta1V2.UpdatedAt, meta1V1.CreatedAt)
			}

			if err := v.Save(ctx); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if v.Dirty() {
				t.Fatal("vault should not be dirty immediately after Save")
			}
			if err := v.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// Reopen and verify all metadata, secrets, and searches.
			reopened, err := Open(ctx, store, masterPass)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = reopened.Close() }()

			if reopened.Len() != 3 {
				t.Fatalf("reopened.Len() = %d, want 3", reopened.Len())
			}
			if reopened.Dirty() {
				t.Fatal("reopened vault should not be dirty")
			}

			sec1, err := reopened.GetSecret(id1)
			if err != nil {
				t.Fatalf("GetSecret(id1): %v", err)
			}
			if sec1.Password != "gh-secret-password-v2" || sec1.Notes != "Rotated password" || sec1.CustomFields["token"] != "tok_abc" {
				t.Fatalf("unexpected GetSecret(id1) = %+v", sec1)
			}

			// Mutating returned slice/map from GetMeta/GetSecret must not mutate vault internals.
			gotMeta := reopened.Search(SearchQuery{Query: "github"})
			if len(gotMeta) != 1 || gotMeta[0].ID != id1 {
				t.Fatalf("Search(github) = %+v, want 1 match (%s)", gotMeta, id1)
			}
			gotMeta[0].Tags[0] = "MUTATED"
			sec1.CustomFields["token"] = "MUTATED"

			sec1Again, err := reopened.GetSecret(id1)
			if err != nil || sec1Again.CustomFields["token"] != "tok_abc" {
				t.Fatalf("GetSecret leaked mutable map: %+v, err=%v", sec1Again, err)
			}

			// Case-insensitive search by username, URL, and tags.
			if res := reopened.Search(SearchQuery{Query: "ALICE@MAIL"}); len(res) != 1 || res[0].ID != id3 {
				t.Fatalf("Search by username = %+v, want %s", res, id3)
			}
			if res := reopened.Search(SearchQuery{Query: "CONSOLE.AWS"}); len(res) != 1 || res[0].ID != id2 {
				t.Fatalf("Search by URL = %+v, want %s", res, id2)
			}
			if res := reopened.Search(SearchQuery{Tags: []string{"work"}}); len(res) != 2 {
				t.Fatalf("Search by tag=work count = %d, want 2", len(res))
			}
			if res := reopened.Search(SearchQuery{Tags: []string{"dev", "work"}}); len(res) != 1 || res[0].ID != id1 {
				t.Fatalf("Search by tags=[dev,work] = %+v, want %s", res, id1)
			}
			if res := reopened.Search(SearchQuery{}); len(res) != 3 {
				t.Fatalf("empty Search count = %d, want 3", len(res))
			}
			if res := reopened.Search(SearchQuery{Query: "no-such-match"}); len(res) != 0 {
				t.Fatalf("non-matching Search count = %d, want 0", len(res))
			}

			// Delete entry #2, save, close, reopen.
			if err := reopened.Delete(id2); err != nil {
				t.Fatalf("Delete(id2): %v", err)
			}
			if !reopened.Dirty() {
				t.Fatal("vault should be dirty after Delete")
			}
			if _, err := reopened.GetMeta(id2); !errors.Is(err, ErrEntryNotFound) {
				t.Fatalf("GetMeta after Delete err = %v, want ErrEntryNotFound", err)
			}
			if _, err := reopened.GetSecret(id2); !errors.Is(err, ErrEntryNotFound) {
				t.Fatalf("GetSecret after Delete err = %v, want ErrEntryNotFound", err)
			}
			if err := reopened.Delete(id2); !errors.Is(err, ErrEntryNotFound) {
				t.Fatalf("second Delete err = %v, want ErrEntryNotFound", err)
			}
			if err := reopened.Save(ctx); err != nil {
				t.Fatalf("Save after Delete: %v", err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatalf("Close after Delete: %v", err)
			}

			reopened2, err := Open(ctx, store, masterPass)
			if err != nil {
				t.Fatalf("Open #2: %v", err)
			}
			defer func() { _ = reopened2.Close() }()

			if reopened2.Len() != 2 {
				t.Fatalf("reopened2.Len() = %d, want 2", reopened2.Len())
			}
			if _, err := reopened2.GetMeta(id2); !errors.Is(err, ErrEntryNotFound) {
				t.Fatalf("deleted entry persisted after Save: %v", err)
			}
		})
	}
}

func TestDefaultArgon2ParamsLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	pass := []byte("default-argon2-64mib-pass")

	v, err := Create(ctx, store, pass)
	if err != nil {
		t.Fatalf("Create with default Argon2 params: %v", err)
	}
	id, err := v.Put(ctx, EntryMeta{Title: "DefaultKDF"}, Secret{Password: "s3cr3t"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(ctx); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v2, err := Open(ctx, store, pass)
	if err != nil {
		t.Fatalf("Open with default Argon2 params: %v", err)
	}
	defer func() { _ = v2.Close() }()

	sec, err := v2.GetSecret(id)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if sec.Password != "s3cr3t" {
		t.Fatalf("Password = %q, want s3cr3t", sec.Password)
	}
}

func TestVaultCreateAndOpenValidation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()

	if _, err := Create(ctx, nil, []byte("pass")); !errors.Is(err, ErrNilStorage) {
		t.Fatalf("Create nil storage err = %v, want ErrNilStorage", err)
	}
	if _, err := Open(ctx, nil, []byte("pass")); !errors.Is(err, ErrNilStorage) {
		t.Fatalf("Open nil storage err = %v, want ErrNilStorage", err)
	}
	if _, err := Create(ctx, store, nil); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Create empty password err = %v, want ErrEmptyPassword", err)
	}
	if _, err := Create(ctx, store, []byte("pass"), WithArgon2Params(Argon2Params{Time: 0, MemoryKiB: 64, Threads: 1})); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("Create invalid Argon2 err = %v, want ErrInvalidArgon2Params", err)
	}
	if _, err := Open(ctx, store, []byte("pass")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open empty store err = %v, want ErrNotFound", err)
	}
}

func TestVaultWrongPassword(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	correct := []byte("real-master-password")

	v, err := Create(ctx, store, correct, fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id, err := v.Put(ctx, EntryMeta{Title: "Secret"}, Secret{Password: "pw"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(ctx); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_ = v.Close()

	if _, err := Open(ctx, store, []byte("wrong-master-password")); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Open wrong password err = %v, want ErrInvalidPassword", err)
	}
	if _, err := Open(ctx, store, nil); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Open empty password err = %v, want ErrInvalidPassword", err)
	}

	v2, err := Open(ctx, store, correct)
	if err != nil {
		t.Fatalf("Open correct password: %v", err)
	}
	defer func() { _ = v2.Close() }()
	if sec, err := v2.GetSecret(id); err != nil || sec.Password != "pw" {
		t.Fatalf("GetSecret = %+v, err=%v", sec, err)
	}
}

func TestVaultHeaderTamperingAAD(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	pass := []byte("aad-test-password")

	v, err := Create(ctx, store, pass, fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := v.Put(ctx, EntryMeta{Title: "AAD"}, Secret{Password: "123"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(ctx); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Capture indexKey before closing so we can verify AAD binding independently of KDF.
	indexKeyCopy := testIndexKey(t, store, pass)
	_ = v.Close()

	origRaw, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load raw: %v", err)
	}

	// 1. Direct cryptographic AAD check across every single byte of the 50-byte header.
	_, hdrBytes, nonce, ciphertext, err := unpackEnvelope(origRaw, crypto.DefaultArgon2Limits())
	if err != nil {
		t.Fatalf("unpackEnvelope: %v", err)
	}
	if _, err := crypto.Decrypt(indexKeyCopy, nonce, ciphertext, hdrBytes); err != nil {
		t.Fatalf("unmodified header AAD decrypt failed: %v", err)
	}
	for i := range headerSize {
		tamperedAAD := bytes.Clone(hdrBytes)
		tamperedAAD[i] ^= 0x01
		if _, err := crypto.Decrypt(indexKeyCopy, nonce, ciphertext, tamperedAAD); !errors.Is(err, crypto.ErrDecryptionFailed) {
			t.Fatalf("tampering header byte %d did not break AAD verification: err=%v", i, err)
		}
	}

	// 2. End-to-end Open checks against tampered serialized envelopes.
	cases := []struct {
		name    string
		mutate  func(b []byte)
		wantErr error
	}{
		{
			name:    "magic_tampered",
			mutate:  func(b []byte) { b[0] ^= 0x01 },
			wantErr: ErrInvalidHeader,
		},
		{
			name:    "version_tampered",
			mutate:  func(b []byte) { b[5] = 2 },
			wantErr: ErrUnsupportedVersion,
		},
		{
			name:    "salt_tampered",
			mutate:  func(b []byte) { b[10] ^= 0x01 },
			wantErr: ErrInvalidPassword,
		},
		{
			name:    "argon_time_tampered",
			mutate:  func(b []byte) { b[41] = 2 },
			wantErr: ErrInvalidPassword,
		},
		{
			name:    "argon_memory_tampered",
			mutate:  func(b []byte) { b[45] = 128 },
			wantErr: ErrInvalidPassword,
		},
		{
			name:    "argon_threads_tampered",
			mutate:  func(b []byte) { b[49] = 2 },
			wantErr: ErrInvalidPassword,
		},
		{
			name:    "argon_threads_zero",
			mutate:  func(b []byte) { b[49] = 0 },
			wantErr: ErrInvalidArgon2Params,
		},
		{
			name:    "ciphertext_tampered",
			mutate:  func(b []byte) { b[len(b)-1] ^= 0x01 },
			wantErr: ErrInvalidPassword,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tampered := bytes.Clone(origRaw)
			tc.mutate(tampered)

			tamperedStore := NewMemoryStorage()
			if err := tamperedStore.Save(ctx, tampered); err != nil {
				t.Fatalf("tamperedStore.Save: %v", err)
			}
			if _, err := Open(ctx, tamperedStore, pass); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Open(%s) err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestVaultEntrySecretSwapAndVersionRollback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	pass := []byte("swap-test-password")

	v, err := Create(ctx, store, pass, fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	idA, err := v.Put(ctx, EntryMeta{Title: "Entry A"}, Secret{Password: "secret-A"})
	if err != nil {
		t.Fatalf("Put A: %v", err)
	}
	idB, err := v.Put(ctx, EntryMeta{Title: "Entry B"}, Secret{Password: "secret-B"})
	if err != nil {
		t.Fatalf("Put B: %v", err)
	}
	if err := v.Save(ctx); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Capture indexKey before closing to craft a valid outer envelope with swapped entry secrets.
	indexKeyCopy := testIndexKey(t, store, pass)

	// 1. In-memory version rollback check (v1 secret placed under v2 entry metadata).
	v1Nonce := bytes.Clone(v.entries[idA].secretNonce)
	v1Cipher := bytes.Clone(v.entries[idA].encryptedSecret)
	if _, err := v.Put(ctx, EntryMeta{ID: idA, Title: "Entry A v2"}, Secret{Password: "secret-A-v2"}); err != nil {
		t.Fatalf("Put A v2: %v", err)
	}
	// Roll back encrypted secret bytes while keeping version=2.
	v.entries[idA].secretNonce = v1Nonce
	v.entries[idA].encryptedSecret = v1Cipher
	if _, err := v.GetSecret(idA); !errors.Is(err, ErrSecretCorrupted) {
		t.Fatalf("version rollback GetSecret err = %v, want ErrSecretCorrupted", err)
	}

	_ = v.Close()

	// 2. Persisted VaultData secret swap between Entry A and Entry B:
	// Outer VaultData envelope remains validly authenticated under indexKey,
	// so Open succeeds, and GetSecret detects the entry AAD mismatch.
	raw, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, hdrBytes, nonce, ciphertext, err := unpackEnvelope(raw, crypto.DefaultArgon2Limits())
	if err != nil {
		t.Fatalf("unpackEnvelope: %v", err)
	}
	plainVault, err := crypto.Decrypt(indexKeyCopy, nonce, ciphertext, hdrBytes)
	if err != nil {
		t.Fatalf("Decrypt outer: %v", err)
	}

	var pb vaultpb.VaultData
	if err := proto.Unmarshal(plainVault, &pb); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if len(pb.Entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(pb.Entries))
	}

	// Swap encrypted secrets and nonces between the two entries.
	pb.Entries[0].SecretNonce, pb.Entries[1].SecretNonce = pb.Entries[1].SecretNonce, pb.Entries[0].SecretNonce
	pb.Entries[0].EncryptedSecret, pb.Entries[1].EncryptedSecret = pb.Entries[1].EncryptedSecret, pb.Entries[0].EncryptedSecret

	swappedPlain, err := proto.Marshal(&pb)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	newNonce, newCT, err := crypto.Encrypt(indexKeyCopy, swappedPlain, hdrBytes)
	if err != nil {
		t.Fatalf("Encrypt outer: %v", err)
	}
	if err := store.Save(ctx, packEnvelope(hdrBytes, newNonce, newCT)); err != nil {
		t.Fatalf("store.Save swapped: %v", err)
	}

	reopened, err := Open(ctx, store, pass)
	if err != nil {
		t.Fatalf("Open after entry secret swap failed unexpectedly: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if _, err := reopened.GetSecret(idA); !errors.Is(err, ErrSecretCorrupted) {
		t.Fatalf("GetSecret(idA) after swap err = %v, want ErrSecretCorrupted", err)
	}
	if _, err := reopened.GetSecret(idB); !errors.Is(err, ErrSecretCorrupted) {
		t.Fatalf("GetSecret(idB) after swap err = %v, want ErrSecretCorrupted", err)
	}
}

type failingStorage struct {
	inner    Storage
	failSave atomic.Bool
	err      error
}

func (f *failingStorage) Load(ctx context.Context) ([]byte, error) {
	return f.inner.Load(ctx)
}

func (f *failingStorage) Save(ctx context.Context, data []byte) error {
	if f.failSave.Load() {
		return f.err
	}
	return f.inner.Save(ctx, data)
}

func TestVaultAutoSaveAndRollback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mem := NewMemoryStorage()
	fs := &failingStorage{
		inner: mem,
		err:   errors.New("disk full"),
	}
	pass := []byte("autosave-password")

	v, err := Create(ctx, fs, pass, fastTestArgon2(), WithAutoSave(true))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = v.Close() }()

	id1, err := v.Put(ctx, EntryMeta{Title: "First"}, Secret{Password: "pw-v1"})
	if err != nil {
		t.Fatalf("Put auto-save: %v", err)
	}
	if v.Dirty() {
		t.Fatal("Dirty() should be false after auto-save Put")
	}

	// Verify persistence immediately via a second independent Open.
	reader, err := Open(ctx, mem, pass)
	if err != nil {
		t.Fatalf("Open reader: %v", err)
	}
	if sec, err := reader.GetSecret(id1); err != nil || sec.Password != "pw-v1" {
		t.Fatalf("reader GetSecret = %+v, err=%v", sec, err)
	}
	_ = reader.Close()

	// Inject Save failure and verify Put (insert), Put (update), and Delete all roll back cleanly.
	fs.failSave.Store(true)

	if _, err := v.Put(ctx, EntryMeta{Title: "ShouldRollback"}, Secret{Password: "nope"}); !errors.Is(err, fs.err) {
		t.Fatalf("failing Put insert err = %v, want %v", err, fs.err)
	}
	if v.Len() != 1 || v.Dirty() {
		t.Fatalf("insert rollback failed: Len=%d Dirty=%v", v.Len(), v.Dirty())
	}

	if _, err := v.Put(ctx, EntryMeta{ID: id1, Title: "First Updated"}, Secret{Password: "pw-v2"}); !errors.Is(err, fs.err) {
		t.Fatalf("failing Put update err = %v, want %v", err, fs.err)
	}
	meta, err := v.GetMeta(id1)
	if err != nil || meta.Title != "First" || meta.Version != 1 {
		t.Fatalf("update metadata rollback failed: %+v err=%v", meta, err)
	}
	sec, err := v.GetSecret(id1)
	if err != nil || sec.Password != "pw-v1" {
		t.Fatalf("update secret rollback failed: %+v err=%v", sec, err)
	}

	if err := v.Delete(id1); !errors.Is(err, fs.err) {
		t.Fatalf("failing Delete err = %v, want %v", err, fs.err)
	}
	if v.Len() != 1 || v.Dirty() {
		t.Fatalf("delete rollback failed: Len=%d Dirty=%v", v.Len(), v.Dirty())
	}

	// Re-enable Save and verify auto-save Delete succeeds.
	fs.failSave.Store(false)
	if err := v.Delete(id1); err != nil {
		t.Fatalf("Delete auto-save: %v", err)
	}
	if v.Len() != 0 || v.Dirty() {
		t.Fatalf("after auto-save Delete: Len=%d Dirty=%v", v.Len(), v.Dirty())
	}
}

func TestVaultCloseZeroesKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStorage()
	v, err := Create(ctx, store, []byte("close-zero-pass"), fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id, err := v.Put(ctx, EntryMeta{Title: "Item"}, Secret{Password: "top-secret"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Hold references to underlying slices before Close() to verify clear().
	ic := v.indexCipher
	sc := v.secretCipher
	rec := v.entries[id]
	sn := rec.secretNonce
	es := rec.encryptedSecret

	allZero := func(b []byte) bool {
		for _, x := range b {
			if x != 0 {
				return false
			}
		}
		return true
	}

	if ic == nil || sc == nil {
		t.Fatal("session ciphers unexpectedly nil before Close")
	}
	if allZero(sn) || allZero(es) {
		t.Fatal("encrypted secret unexpectedly all-zero before Close")
	}

	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	for name, b := range map[string][]byte{
		"secretNonce":     sn,
		"encryptedSecret": es,
	} {
		if !allZero(b) {
			t.Fatalf("%s was not zeroed on Close", name)
		}
	}

	if v.indexCipher != nil || v.secretCipher != nil || v.entries != nil {
		t.Fatal("Vault fields were not cleared on Close")
	}
	// Retained references to the old ciphers must be unusable after Close.
	if _, _, err := ic.Encrypt([]byte("x"), nil); !errors.Is(err, crypto.ErrCipherClosed) {
		t.Fatalf("indexCipher after Close err = %v, want ErrCipherClosed", err)
	}
	if _, _, err := sc.Encrypt([]byte("x"), nil); !errors.Is(err, crypto.ErrCipherClosed) {
		t.Fatalf("secretCipher after Close err = %v, want ErrCipherClosed", err)
	}
	if _, err := v.Put(ctx, EntryMeta{Title: "X"}, Secret{}); !errors.Is(err, ErrVaultClosed) {
		t.Fatalf("Put after Close err = %v, want ErrVaultClosed", err)
	}
	if _, err := v.GetMeta(id); !errors.Is(err, ErrVaultClosed) {
		t.Fatalf("GetMeta after Close err = %v, want ErrVaultClosed", err)
	}
	if _, err := v.GetSecret(id); !errors.Is(err, ErrVaultClosed) {
		t.Fatalf("GetSecret after Close err = %v, want ErrVaultClosed", err)
	}
	if err := v.Delete(id); !errors.Is(err, ErrVaultClosed) {
		t.Fatalf("Delete after Close err = %v, want ErrVaultClosed", err)
	}
	if err := v.Save(ctx); !errors.Is(err, ErrVaultClosed) {
		t.Fatalf("Save after Close err = %v, want ErrVaultClosed", err)
	}
	if got := v.Search(SearchQuery{}); got != nil {
		t.Fatalf("Search after Close = %+v, want nil", got)
	}
	if v.Dirty() || v.Len() != 0 {
		t.Fatalf("Dirty=%v Len=%d after Close, want false/0", v.Dirty(), v.Len())
	}
}

func TestVaultConcurrentAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewFileStorage(filepath.Join(t.TempDir(), "concurrent.psdm"))
	pass := []byte("concurrent-vault-password")

	v, err := Create(ctx, store, pass, fastTestArgon2())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const seedCount = 8
	seedIDs := make([]string, seedCount)
	for i := range seedCount {
		id, err := v.Put(ctx, EntryMeta{
			Title:    fmt.Sprintf("Seed-%02d", i),
			Username: fmt.Sprintf("user%d", i),
			URL:      fmt.Sprintf("https://service%d.example", i),
			Tags:     []string{"seed", fmt.Sprintf("group-%d", i%3)},
		}, Secret{
			Password: fmt.Sprintf("seed-pw-%d", i),
		})
		if err != nil {
			t.Fatalf("seed Put %d: %v", i, err)
		}
		seedIDs[i] = id
	}

	const workers = 12
	const opsPerWorker = 40

	var wg sync.WaitGroup
	errCh := make(chan error, workers*opsPerWorker)

	for w := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			var ownID string
			for step := range opsPerWorker {
				switch step % 6 {
				case 0:
					id, err := v.Put(ctx, EntryMeta{
						ID:       ownID,
						Title:    fmt.Sprintf("Worker-%d-Step-%d", worker, step),
						Username: fmt.Sprintf("w%d", worker),
						Tags:     []string{"worker"},
					}, Secret{
						Password: fmt.Sprintf("pw-%d-%d", worker, step),
					})
					if err != nil {
						errCh <- fmt.Errorf("worker %d Put: %w", worker, err)
						return
					}
					ownID = id
				case 1:
					target := seedIDs[(worker+step)%len(seedIDs)]
					if _, err := v.GetMeta(target); err != nil && !errors.Is(err, ErrEntryNotFound) {
						errCh <- fmt.Errorf("worker %d GetMeta: %w", worker, err)
						return
					}
				case 2:
					target := seedIDs[(worker+step)%len(seedIDs)]
					if _, err := v.GetSecret(target); err != nil && !errors.Is(err, ErrEntryNotFound) {
						errCh <- fmt.Errorf("worker %d GetSecret: %w", worker, err)
						return
					}
				case 3:
					_ = v.Search(SearchQuery{Query: "worker", Tags: []string{"worker"}})
					_ = v.Dirty()
					_ = v.Len()
				case 4:
					if ownID != "" && step%12 == 4 {
						if err := v.Delete(ownID); err != nil && !errors.Is(err, ErrEntryNotFound) {
							errCh <- fmt.Errorf("worker %d Delete: %w", worker, err)
							return
						}
						ownID = ""
					}
				case 5:
					if step%10 == 5 {
						if err := v.Save(ctx); err != nil {
							errCh <- fmt.Errorf("worker %d Save: %w", worker, err)
							return
						}
					}
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	if err := v.Save(ctx); err != nil {
		t.Fatalf("final Save: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(ctx, store, pass)
	if err != nil {
		t.Fatalf("Open after concurrent writes: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	all := reopened.Search(SearchQuery{})
	if len(all) < seedCount {
		t.Fatalf("expected at least %d entries after concurrent test, got %d", seedCount, len(all))
	}
	for _, meta := range all {
		if _, err := reopened.GetSecret(meta.ID); err != nil {
			t.Fatalf("GetSecret(%s) after concurrent Save/Open failed: %v", meta.ID, err)
		}
	}
}
