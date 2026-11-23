// Package passwordium provides a single-file, minimized-RAM-exposure encrypted
// credential vault for storing passwords, secrets, and searchable entry metadata.
//
// A vault envelope consists of a 50-byte plaintext binary header (4-byte "PSDM" magic,
// uint16 format version, 32-byte Argon2id salt, and uint32 Time/MemoryKiB/Threads costs),
// a 24-byte outer XChaCha20-Poly1305 nonce, and an authenticated ciphertext containing
// the protobuf-encoded VaultData index with the 50-byte header bound as associated data (AAD).
//
// Key derivation follows a two-level hierarchy: Argon2id derives a 32-byte masterKey
// from the caller's master password and header salt, and HKDF-SHA256 expands masterKey
// into two domain-separated 32-byte subkeys (indexKey for the outer VaultData container
// and secretKey for individual entry Secret payloads). Raw key buffers are wiped via
// clear() immediately after initializing the session AEAD instances, and each entry's
// SecretPayload (padded to 256-byte ISO/IEC 7816-4 blocks and bound to "<entry_id>:<entry_version>"
// as AAD) remains encrypted in memory until Vault.GetSecret is called.
package passwordium

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dmi3midd/passwordium/internal/crypto"
	"github.com/dmi3midd/passwordium/internal/vaultpb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

//go:generate protoc --go_out=. --go_opt=module=github.com/dmi3midd/passwordium proto/vault.proto

const (
	hkdfContextIndex  = "passwordium:v1:index"
	hkdfContextSecret = "passwordium:v1:secret"

	// secretPadBlockSize is the block size (in bytes) to which serialized SecretPayload
	// plaintexts are padded (ISO/IEC 7816-4: 0x80 followed by 0x00 bytes) before
	// encryption, hiding exact password and note lengths within 256-byte buckets.
	secretPadBlockSize = 256
)

// Vault is a thread-safe encrypted credential store backed by a Storage implementation.
//
// After Create or Open returns, searchable entry metadata (EntryMeta) is indexed in
// memory for fast lookups via Vault.GetMeta and Vault.Search, while each entry's
// SecretPayload remains individually encrypted under secretKey in memory until
// Vault.GetSecret is called.
//
// The 32-byte master key and raw HKDF subkeys are wiped immediately after key derivation;
// only the initialized XChaCha20-Poly1305 AEAD instances for indexKey and secretKey
// are retained for the session and released when Vault.Close or Vault.CloseWithSave completes.
//
// All methods on Vault are safe for concurrent use by multiple goroutines. Unless
// WithAutoSave(true) is configured, in-memory mutations (Vault.Put, Vault.Delete,
// Vault.DeleteContext, and Vault.Import) mark the Vault as dirty without writing to
// Storage until Vault.Save or Vault.CloseWithSave is called.
type Vault struct {
	mu           sync.RWMutex
	store        Storage
	hdr          header
	indexCipher  *crypto.Cipher
	secretCipher *crypto.Cipher
	entries      map[string]*entryRecord
	version      uint64
	updatedAt    int64
	lastDigest   [32]byte
	hasDigest    bool
	dirty        bool
	autoSave     bool
	closed       bool
}

// entryRecord is a pure-Go in-memory representation of a vault entry, avoiding
// protobuf internal state (e.g., sizeCache) in concurrent read paths.
type entryRecord struct {
	id              string
	version         uint64
	title           string
	username        string
	url             string
	tags            []string
	createdAt       int64
	updatedAt       int64
	secretNonce     []byte
	encryptedSecret []byte
}

func (r *entryRecord) toMeta() EntryMeta {
	return EntryMeta{
		ID:        r.id,
		Version:   r.version,
		Title:     r.title,
		Username:  r.username,
		URL:       r.url,
		Tags:      slices.Clone(r.tags),
		CreatedAt: time.Unix(r.createdAt, 0).UTC(),
		UpdatedAt: time.Unix(r.updatedAt, 0).UTC(),
	}
}

func (r *entryRecord) toProto() *vaultpb.Entry {
	return &vaultpb.Entry{
		Id:              r.id,
		Version:         r.version,
		Title:           r.title,
		Username:        r.username,
		Url:             r.url,
		Tags:            slices.Clone(r.tags),
		CreatedAt:       r.createdAt,
		UpdatedAt:       r.updatedAt,
		SecretNonce:     bytes.Clone(r.secretNonce),
		EncryptedSecret: bytes.Clone(r.encryptedSecret),
	}
}

func (r *entryRecord) zeroSecret() {
	crypto.ZeroBytes(r.secretNonce)
	crypto.ZeroBytes(r.encryptedSecret)
}

func entryAAD(id string, version uint64) []byte {
	return []byte(fmt.Sprintf("%s:%d", id, version))
}

// padSecret pads src using ISO/IEC 7816-4 padding (0x80 followed by 0x00 bytes)
// to the next multiple of secretPadBlockSize bytes.
func padSecret(src []byte) []byte {
	rem := (len(src) + 1) % secretPadBlockSize
	padZeros := 0
	if rem != 0 {
		padZeros = secretPadBlockSize - rem
	}
	out := make([]byte, len(src)+1+padZeros)
	copy(out, src)
	out[len(src)] = 0x80
	return out
}

// unpadSecret removes ISO/IEC 7816-4 padding from padded, returning a subslice
// of padded without additional allocations.
func unpadSecret(padded []byte) ([]byte, error) {
	if len(padded) == 0 || len(padded)%secretPadBlockSize != 0 {
		return nil, ErrSecretCorrupted
	}
	for i := len(padded) - 1; i >= 0; i-- {
		switch padded[i] {
		case 0x00:
			continue
		case 0x80:
			return padded[:i], nil
		default:
			return nil, ErrSecretCorrupted
		}
	}
	return nil, ErrSecretCorrupted
}

func consumeValidTag(b []byte) (protowire.Number, protowire.Type, int) {
	v, n := protowire.ConsumeVarint(b)
	if n < 0 || v > math.MaxUint32 {
		return 0, 0, -1
	}
	num, typ := protowire.DecodeTag(v)
	if num < protowire.MinValidNumber || num > protowire.MaxValidNumber {
		return 0, 0, -1
	}
	return num, typ, n
}

// validateSecretPayloadWire verifies that b is a syntactically valid protobuf
// encoding of vaultpb.SecretPayload without allocating Go strings or maps on the heap.
func validateSecretPayloadWire(b []byte) error {
	for len(b) > 0 {
		num, typ, n := consumeValidTag(b)
		if n < 0 {
			return ErrSecretCorrupted
		}
		b = b[n:]

		switch num {
		case 1, 2: // password, notes (string)
			if typ != protowire.BytesType {
				return ErrSecretCorrupted
			}
			v, m := protowire.ConsumeBytes(b)
			if m < 0 || !utf8.Valid(v) {
				return ErrSecretCorrupted
			}
			b = b[m:]
		case 3: // custom_fields (map<string, string> entry message)
			if typ != protowire.BytesType {
				return ErrSecretCorrupted
			}
			entryBytes, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return ErrSecretCorrupted
			}
			if err := validateMapEntryWire(entryBytes); err != nil {
				return err
			}
			b = b[m:]
		default:
			return ErrSecretCorrupted
		}
	}
	return nil
}

func validateMapEntryWire(b []byte) error {
	for len(b) > 0 {
		num, typ, n := consumeValidTag(b)
		if n < 0 {
			return ErrSecretCorrupted
		}
		b = b[n:]

		switch num {
		case 1, 2: // key, value (string)
			if typ != protowire.BytesType {
				return ErrSecretCorrupted
			}
			v, m := protowire.ConsumeBytes(b)
			if m < 0 || !utf8.Valid(v) {
				return ErrSecretCorrupted
			}
			b = b[m:]
		default:
			return ErrSecretCorrupted
		}
	}
	return nil
}

func validateEntryMetaUTF8(meta EntryMeta) error {
	if !utf8.ValidString(meta.ID) ||
		!utf8.ValidString(meta.Title) ||
		!utf8.ValidString(meta.Username) ||
		!utf8.ValidString(meta.URL) {
		return errors.New("passwordium: entry metadata contains invalid UTF-8")
	}
	for _, tag := range meta.Tags {
		if !utf8.ValidString(tag) {
			return errors.New("passwordium: entry tag contains invalid UTF-8")
		}
	}
	return nil
}

// deriveVaultCiphers runs Argon2id + HKDF-SHA256, initializes one AEAD per subkey,
// and wipes masterKey, indexKey, and secretKey before returning on every path.
func deriveVaultCiphers(masterPassword, salt []byte, params Argon2Params) (indexCipher, secretCipher *crypto.Cipher, err error) {
	masterKey, err := crypto.DeriveMasterKey(masterPassword, salt, params.toCrypto())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidArgon2Params, err)
	}
	defer crypto.ZeroBytes(masterKey)

	indexKey, err := crypto.DeriveSubKey(masterKey, hkdfContextIndex)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.ZeroBytes(indexKey)

	secretKey, err := crypto.DeriveSubKey(masterKey, hkdfContextSecret)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.ZeroBytes(secretKey)

	indexCipher, err = crypto.NewCipher(indexKey)
	if err != nil {
		return nil, nil, err
	}
	secretCipher, err = crypto.NewCipher(secretKey)
	if err != nil {
		indexCipher.Close()
		return nil, nil, err
	}
	return indexCipher, secretCipher, nil
}

// Create initializes a brand-new encrypted Vault backed by store, derives session
// AEAD keys from masterPassword and a freshly generated 32-byte random salt using
// Argon2id and HKDF-SHA256, and immediately persists the initial empty vault (at
// container version 1) to store.
//
// By default, Create uses DefaultArgon2Params (Time=3, Memory=64 MiB, Threads=2),
// disables automatic saving on subsequent mutations, and refuses to overwrite an
// existing vault in store.
//
// Create does not mutate masterPassword; callers should zero masterPassword (for
// example, via clear(masterPassword)) once it is no longer needed.
//
// Create returns:
//   - ctx.Err() if ctx is canceled before or during initialization,
//   - ErrNilStorage if store is nil,
//   - ErrEmptyPassword if len(masterPassword) == 0,
//   - ErrInvalidArgon2Params if WithArgon2Params specifies a memory cost below 16 MiB
//     (16,384 KiB) or parameters exceeding DefaultMaxArgon2Params,
//   - ErrAlreadyExists if a vault already exists in store and WithOverwrite(true) is not set,
//   - ErrInvalidStorageFile or ErrVaultTooLarge if store is a FileStorage and path or
//     size constraints are violated, or
//   - a wrapped cryptographic or storage I/O error.
func Create(ctx context.Context, store Storage, masterPassword []byte, opts ...CreateOption) (*Vault, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrNilStorage
	}
	if len(masterPassword) == 0 {
		return nil, ErrEmptyPassword
	}

	cfg := defaultCreateConfig()
	for _, opt := range opts {
		if opt != nil {
			opt.applyCreate(&cfg)
		}
	}
	if err := cfg.argon2Params.validateForCreate(cfg.allowWeakArgon2); err != nil {
		return nil, err
	}

	if !cfg.overwrite {
		if err := checkStorageNotExists(ctx, store); err != nil {
			return nil, err
		}
	}

	salt, err := crypto.RandomBytes(crypto.SaltSize)
	if err != nil {
		return nil, err
	}

	var hdr header
	hdr.Version = currentVersion
	copy(hdr.Salt[:], salt)
	hdr.Params = cfg.argon2Params

	indexCipher, secretCipher, err := deriveVaultCiphers(masterPassword, hdr.Salt[:], hdr.Params)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		indexCipher.Close()
		secretCipher.Close()
		return nil, err
	}

	v := &Vault{
		store:        store,
		hdr:          hdr,
		indexCipher:  indexCipher,
		secretCipher: secretCipher,
		entries:      make(map[string]*entryRecord),
		updatedAt:    time.Now().UTC().Unix(),
		autoSave:     cfg.autoSave,
	}

	if err := v.saveInitialLocked(ctx, cfg.overwrite); err != nil {
		_ = v.Close()
		return nil, err
	}
	return v, nil
}

func checkStorageNotExists(ctx context.Context, store Storage) error {
	if ec, ok := store.(existenceChecker); ok {
		exists, err := ec.Exists(ctx)
		if err != nil {
			return err
		}
		if exists {
			return ErrAlreadyExists
		}
		return nil
	}
	_, err := store.Load(ctx)
	switch {
	case err == nil:
		return ErrAlreadyExists
	case !errors.Is(err, ErrNotFound):
		return err
	default:
		return nil
	}
}

// Open loads an existing encrypted vault envelope from store, validates the 50-byte
// plaintext header and enforces pre-KDF resource caps on its Argon2id parameters
// (DefaultMaxArgon2Params by default, or custom bounds configured via WithMaxArgon2Params
// and WithMaxArgon2Work), derives session keys from masterPassword, and authenticates
// and decrypts the outer VaultData index using the 50-byte header as associated data (AAD).
//
// After Open succeeds, entry metadata is indexed in memory and the SHA-256 digest of
// the loaded envelope is recorded for optimistic concurrency checks on subsequent saves,
// while individual entry Secret payloads remain encrypted in memory until Vault.GetSecret
// is invoked.
//
// Open does not mutate masterPassword; callers should zero masterPassword (for example,
// via clear(masterPassword)) once it is no longer needed.
//
// Open returns:
//   - ctx.Err() if ctx is canceled before or during key derivation,
//   - ErrNilStorage if store is nil,
//   - ErrNotFound if no vault exists in store,
//   - ErrInvalidStorageFile or ErrVaultTooLarge if store is a FileStorage and the file
//     is non-regular or exceeds the configured maximum file size,
//   - ErrInvalidHeader if the envelope has fewer than 50 bytes or lacks the "PSDM" magic,
//   - ErrUnsupportedVersion if the header format version is not 1,
//   - ErrInvalidArgon2Params if the header's Argon2id parameters or the caller's
//     WithMaxArgon2Params bounds are invalid or exceed configured resource limits,
//   - ErrCorruptedVault if the envelope is shorter than 90 bytes, the outer decrypted
//     VaultData protobuf is malformed, the container version is 0 or math.MaxUint64,
//     or any entry has an empty/duplicate ID, version 0 or math.MaxUint64, an invalid
//     24-byte secret nonce, or an unaligned encrypted secret size, or
//   - ErrInvalidPassword if outer XChaCha20-Poly1305 AEAD verification fails (wrong
//     master password or tampered header/ciphertext).
func Open(ctx context.Context, store Storage, masterPassword []byte, opts ...OpenOption) (*Vault, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrNilStorage
	}

	var cfg openConfig
	for _, opt := range opts {
		if opt != nil {
			opt.applyOpen(&cfg)
		}
	}

	limits := crypto.DefaultArgon2Limits()
	if cfg.hasMaxArgon2 {
		max := cfg.maxArgon2Params
		if err := max.toCrypto().Validate(); err != nil {
			return nil, fmt.Errorf("%w: invalid max limits: %v", ErrInvalidArgon2Params, err)
		}
		maxWork := uint64(max.Time) * uint64(max.MemoryKiB)
		if max.Time <= crypto.DefaultMaxArgonTime && max.MemoryKiB <= crypto.DefaultMaxArgonMemoryKiB && maxWork > crypto.DefaultMaxArgonWork {
			maxWork = crypto.DefaultMaxArgonWork
		}
		limits = crypto.Argon2Limits{
			MaxTime:      max.Time,
			MaxMemoryKiB: max.MemoryKiB,
			MaxThreads:   max.Threads,
			MaxWork:      maxWork,
		}
	}
	if cfg.hasMaxWork {
		limits.MaxWork = cfg.maxArgon2Work
	}

	raw, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}

	hdr, headerBytes, nonce, ciphertext, err := unpackEnvelope(raw, limits)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	indexCipher, secretCipher, err := deriveVaultCiphers(masterPassword, hdr.Salt[:], hdr.Params)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		indexCipher.Close()
		secretCipher.Close()
		return nil, err
	}
	closeCiphers := func() {
		indexCipher.Close()
		secretCipher.Close()
	}

	plaintext, err := indexCipher.Decrypt(nonce, ciphertext, headerBytes)
	if err != nil {
		closeCiphers()
		return nil, ErrInvalidPassword
	}
	defer crypto.ZeroBytes(plaintext)

	var pb vaultpb.VaultData
	if err := proto.Unmarshal(plaintext, &pb); err != nil {
		closeCiphers()
		return nil, fmt.Errorf("%w: %w", ErrCorruptedVault, err)
	}
	if pb.Version == 0 || pb.Version == math.MaxUint64 {
		closeCiphers()
		return nil, fmt.Errorf("%w: invalid vault version %d", ErrCorruptedVault, pb.Version)
	}

	entries := make(map[string]*entryRecord, len(pb.Entries))
	for _, e := range pb.Entries {
		if e == nil || e.Id == "" {
			closeCiphers()
			return nil, fmt.Errorf("%w: entry missing id", ErrCorruptedVault)
		}
		if e.Version == 0 || e.Version == math.MaxUint64 {
			closeCiphers()
			return nil, fmt.Errorf("%w: entry %q has invalid version %d", ErrCorruptedVault, e.Id, e.Version)
		}
		if len(e.SecretNonce) != crypto.NonceSize {
			closeCiphers()
			return nil, fmt.Errorf("%w: entry %q has invalid secret nonce size %d", ErrCorruptedVault, e.Id, len(e.SecretNonce))
		}
		if len(e.EncryptedSecret) < secretPadBlockSize+crypto.Overhead || (len(e.EncryptedSecret)-crypto.Overhead)%secretPadBlockSize != 0 {
			closeCiphers()
			return nil, fmt.Errorf("%w: entry %q has invalid encrypted secret size %d", ErrCorruptedVault, e.Id, len(e.EncryptedSecret))
		}
		if _, dup := entries[e.Id]; dup {
			closeCiphers()
			return nil, fmt.Errorf("%w: duplicate entry id", ErrCorruptedVault)
		}
		entries[e.Id] = &entryRecord{
			id:              e.Id,
			version:         e.Version,
			title:           e.Title,
			username:        e.Username,
			url:             e.Url,
			tags:            slices.Clone(e.Tags),
			createdAt:       e.CreatedAt,
			updatedAt:       e.UpdatedAt,
			secretNonce:     e.SecretNonce,
			encryptedSecret: e.EncryptedSecret,
		}
		e.SecretNonce = nil
		e.EncryptedSecret = nil
	}

	return &Vault{
		store:        store,
		hdr:          hdr,
		indexCipher:  indexCipher,
		secretCipher: secretCipher,
		entries:      entries,
		version:      pb.Version,
		updatedAt:    pb.UpdatedAt,
		lastDigest:   sha256.Sum256(raw),
		hasDigest:    true,
		autoSave:     cfg.autoSave,
	}, nil
}

// Put creates a new entry in v (generating a random RFC 4122 UUIDv4 when meta.ID is
// empty) or updates an existing entry in v when meta.ID matches an existing record,
// returning the entry's effective ID.
//
// Put validates that all string fields in meta and secret contain valid UTF-8, serializes
// secret into a protobuf SecretPayload, pads the plaintext to a multiple of 256 bytes
// using ISO/IEC 7816-4 padding, encrypts it under secretKey with a fresh 24-byte random
// nonce and "<id>:<version>" as associated data, and zeroes all temporary plaintext and
// padded byte buffers before returning.
//
// When creating a new entry, Version is initialized to 1 and both CreatedAt and UpdatedAt
// are set to the current UTC Unix timestamp (in seconds). When updating an existing entry,
// Version is incremented by 1, CreatedAt is preserved, UpdatedAt is set to at least the
// current UTC Unix timestamp (never regressing below CreatedAt or the previous UpdatedAt),
// and the previous entry record's encrypted secret buffer is wiped once the update succeeds.
//
// Unless WithAutoSave(true) is enabled on v, Put only updates v's in-memory index and
// marks v as dirty; when WithAutoSave(true) is enabled, Put immediately persists the
// vault to Storage and atomically rolls back the in-memory change if saving fails.
//
// Put returns ctx.Err() if ctx is canceled, ErrVaultClosed if v is closed, an error if
// any field in meta or secret contains invalid UTF-8, ErrCorruptedVault if incrementing
// the entry version would overflow uint64, or a storage error if WithAutoSave persistence fails.
func (v *Vault) Put(ctx context.Context, meta EntryMeta, secret Secret) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := validateEntryMetaUTF8(meta); err != nil {
		return "", err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return "", ErrVaultClosed
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	id := meta.ID
	if id == "" {
		var err error
		id, err = generateUUIDv4()
		if err != nil {
			return "", err
		}
	}

	now := time.Now().UTC().Unix()
	existing, exists := v.entries[id]

	version := uint64(1)
	createdAt := now
	updatedAt := now
	if exists {
		if existing.version >= math.MaxUint64-1 {
			return "", fmt.Errorf("%w: entry %q version overflow", ErrCorruptedVault, id)
		}
		version = existing.version + 1
		createdAt = existing.createdAt
		if existing.updatedAt > updatedAt {
			updatedAt = existing.updatedAt
		}
		if createdAt > updatedAt {
			updatedAt = createdAt
		}
	}

	// proto.Marshal does not retain or mutate CustomFields, so no defensive copy is needed.
	plainSecret, err := proto.Marshal(&vaultpb.SecretPayload{
		Password:     secret.Password,
		Notes:        secret.Notes,
		CustomFields: secret.CustomFields,
	})
	if err != nil {
		return "", fmt.Errorf("passwordium: marshal secret: %w", err)
	}
	defer crypto.ZeroBytes(plainSecret)

	paddedSecret := padSecret(plainSecret)
	defer crypto.ZeroBytes(paddedSecret)

	secretNonce, encryptedSecret, err := v.secretCipher.Encrypt(paddedSecret, entryAAD(id, version))
	if err != nil {
		return "", fmt.Errorf("passwordium: encrypt secret: %w", err)
	}

	rec := &entryRecord{
		id:              id,
		version:         version,
		title:           meta.Title,
		username:        meta.Username,
		url:             meta.URL,
		tags:            slices.Clone(meta.Tags),
		createdAt:       createdAt,
		updatedAt:       updatedAt,
		secretNonce:     secretNonce,
		encryptedSecret: encryptedSecret,
	}

	prevDirty := v.dirty
	v.entries[id] = rec
	v.dirty = true

	if v.autoSave {
		if err := v.saveLocked(ctx); err != nil {
			if exists {
				v.entries[id] = existing
			} else {
				delete(v.entries, id)
			}
			v.dirty = prevDirty
			rec.zeroSecret()
			return "", err
		}
	}

	if exists {
		existing.zeroSecret()
	}

	return id, nil
}

// GetMeta returns a copy of the EntryMeta for the entry identified by id from v's
// in-memory index without decrypting the entry's Secret payload.
//
// The returned EntryMeta contains a freshly cloned Tags slice, so mutating it does
// not affect v. GetMeta returns ErrVaultClosed if v has been closed, or ErrEntryNotFound
// if no entry with id exists in v.
func (v *Vault) GetMeta(id string) (EntryMeta, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return EntryMeta{}, ErrVaultClosed
	}

	rec, ok := v.entries[id]
	if !ok {
		return EntryMeta{}, ErrEntryNotFound
	}
	return rec.toMeta(), nil
}

// GetSecret authenticates, decrypts, unpads, and unmarshals the Secret payload for
// the entry identified by id.
//
// GetSecret verifies the entry's XChaCha20-Poly1305 authentication tag against
// "<id>:<version>" as associated data (detecting any cross-entry swap or version
// rollback), removes ISO/IEC 7816-4 padding, unmarshals the SecretPayload protobuf,
// and wipes the temporary decrypted byte buffer before returning. The returned
// CustomFields map is freshly allocated and owned by the caller.
//
// GetSecret returns ErrVaultClosed if v has been closed, ErrEntryNotFound if id does
// not exist in v, or ErrSecretCorrupted if AEAD verification, unpadding, or protobuf
// decoding fails.
func (v *Vault) GetSecret(id string) (Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return Secret{}, ErrVaultClosed
	}

	rec, ok := v.entries[id]
	if !ok {
		return Secret{}, ErrEntryNotFound
	}

	plain, err := v.secretCipher.Decrypt(rec.secretNonce, rec.encryptedSecret, entryAAD(rec.id, rec.version))
	if err != nil {
		return Secret{}, fmt.Errorf("%w: %w", ErrSecretCorrupted, err)
	}
	defer crypto.ZeroBytes(plain)

	unpadded, err := unpadSecret(plain)
	if err != nil {
		return Secret{}, err
	}

	var pb vaultpb.SecretPayload
	if err := proto.Unmarshal(unpadded, &pb); err != nil {
		return Secret{}, fmt.Errorf("%w: %w", ErrSecretCorrupted, err)
	}

	// pb is local and its map was freshly allocated by proto.Unmarshal; no copy needed.
	return Secret{
		Password:     pb.Password,
		Notes:        pb.Notes,
		CustomFields: pb.CustomFields,
	}, nil
}

// Delete removes the entry identified by id from v and zeroes its in-memory encrypted
// secret buffer.
//
// Delete is a shorthand for v.DeleteContext(context.Background(), id). Prefer
// Vault.DeleteContext when WithAutoSave(true) is enabled and the underlying Storage
// may block or require deadline propagation.
//
// Delete returns ErrVaultClosed if v is closed, ErrEntryNotFound if id does not exist
// in v, or a storage error if WithAutoSave(true) persistence fails (in which case the
// deletion is rolled back in memory).
func (v *Vault) Delete(id string) error {
	return v.DeleteContext(context.Background(), id)
}

// DeleteContext removes the entry identified by id from v, honoring ctx cancellation
// and deadlines, and zeroes the removed entry's in-memory encrypted secret buffer.
//
// When WithAutoSave(true) is enabled on v, DeleteContext immediately persists the
// updated vault to Storage using ctx; if saving fails, the entry and v's previous
// dirty state are atomically restored in memory and the entry's secret buffer is
// preserved. When WithAutoSave is disabled, DeleteContext marks v as dirty without
// performing storage I/O.
//
// DeleteContext returns ctx.Err() if ctx is canceled, ErrVaultClosed if v is closed,
// ErrEntryNotFound if id does not exist in v, or any error returned by Storage during
// auto-save.
func (v *Vault) DeleteContext(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return ErrVaultClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	rec, ok := v.entries[id]
	if !ok {
		return ErrEntryNotFound
	}

	prevDirty := v.dirty
	delete(v.entries, id)
	v.dirty = true

	if v.autoSave {
		if err := v.saveLocked(ctx); err != nil {
			v.entries[id] = rec
			v.dirty = prevDirty
			return err
		}
	}

	rec.zeroSecret()
	return nil
}

// Search filters v's in-memory EntryMeta index against query without decrypting any
// entry secrets and returns a deterministically sorted slice of matching EntryMeta copies.
//
// An entry matches query if:
//  1. query.Query is empty, or query.Query appears as a case-insensitive substring of
//     the entry's Title, Username, or URL; and
//  2. query.Tags is empty, or the entry contains every tag in query.Tags (matched
//     case-insensitively for exact tag equality).
//
// Matching entries are sorted in ascending order by case-folded Title, then exact
// Title, and finally ID. Each returned EntryMeta has a defensive copy of its Tags slice.
// If v is closed, Search returns nil.
func (v *Vault) Search(query SearchQuery) []EntryMeta {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return nil
	}

	q := strings.ToLower(query.Query)
	results := make([]EntryMeta, 0, len(v.entries))

	for _, rec := range v.entries {
		if q != "" {
			if !strings.Contains(strings.ToLower(rec.title), q) &&
				!strings.Contains(strings.ToLower(rec.username), q) &&
				!strings.Contains(strings.ToLower(rec.url), q) {
				continue
			}
		}
		if len(query.Tags) > 0 && !hasAllTags(rec.tags, query.Tags) {
			continue
		}
		results = append(results, rec.toMeta())
	}

	slices.SortFunc(results, func(a, b EntryMeta) int {
		if c := cmp.Compare(strings.ToLower(a.Title), strings.ToLower(b.Title)); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Title, b.Title); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})

	return results
}

func hasAllTags(entryTags, required []string) bool {
	for _, want := range required {
		found := false
		for _, have := range entryTags {
			if strings.EqualFold(have, want) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Save increments v's container version, serializes all entries into a VaultData
// protobuf (wiping the temporary plaintext buffer afterwards), encrypts the container
// under indexKey with a fresh 24-byte random nonce and the 50-byte plaintext header
// as associated data, and persists the resulting envelope to v's backing Storage.
//
// When the backing Storage implements conditional saving (such as FileStorage and
// MemoryStorage), Save verifies that the currently stored bytes still match the
// SHA-256 digest from when v was opened or last saved, preventing silent lost updates
// across concurrent sessions. Upon a successful write, Save updates v's container
// Version, UpdatedAt timestamp, and stored digest, and clears the Dirty flag. If
// saving fails, v's in-memory state, Version, and Dirty flag remain unchanged.
//
// Save returns ctx.Err() if ctx is canceled, ErrVaultClosed if v is closed,
// ErrCorruptedVault if incrementing the container version would overflow uint64,
// ErrConcurrentModification if the underlying Storage was modified out-of-band,
// ErrVaultTooLarge or ErrInvalidStorageFile for FileStorage constraint violations,
// or a wrapped I/O error.
func (v *Vault) Save(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return ErrVaultClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	return v.saveLocked(ctx)
}

// Export writes a complete, self-contained encrypted snapshot of v's current in-memory
// state (including any unsaved modifications) to dst without modifying v's dirty state,
// container version, or backing Storage.
//
// By default:
//   - Export refuses to overwrite an existing vault in dst (returning ErrAlreadyExists)
//     unless WithOverwrite(true) is provided.
//   - Export seals the snapshot using v's existing header parameters and key hierarchy
//     (with a fresh 24-byte outer nonce), without decrypting individual entry secrets.
//
// When WithExportPassword(newPassword) is supplied (optionally combined with
// WithArgon2Params), Export generates a fresh 32-byte random salt, derives a new key
// hierarchy outside v's lock, and re-encrypts every entry's padded SecretPayload in
// place (verifying AEAD tags, padding, and protobuf UTF-8 wire validity while wiping
// each temporary byte buffer immediately without allocating Go strings).
//
// Export returns:
//   - ctx.Err() if ctx is canceled,
//   - ErrNilStorage if dst is nil,
//   - ErrVaultClosed if v is closed,
//   - ErrSameStorage if dst refers to the same Storage instance or file as v's store,
//   - ErrEmptyPassword if WithExportPassword is given an empty slice or WithArgon2Params
//     is provided without WithExportPassword,
//   - ErrInvalidArgon2Params if custom Argon2id parameters violate creation bounds,
//   - ErrAlreadyExists if dst already contains a vault and WithOverwrite(true) is not set,
//   - ErrSecretCorrupted if re-keying encounters a corrupted entry secret in v, or
//   - a storage I/O error from dst.
func (v *Vault) Export(ctx context.Context, dst Storage, opts ...ExportOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dst == nil {
		return ErrNilStorage
	}

	var cfg exportConfig
	for _, opt := range opts {
		if opt != nil {
			opt.applyExport(&cfg)
		}
	}

	if cfg.hasPassword && len(cfg.password) == 0 {
		return ErrEmptyPassword
	}
	if cfg.hasArgon2Params && !cfg.hasPassword {
		return fmt.Errorf("%w: WithExportPassword is required when overriding Argon2 parameters on Export", ErrEmptyPassword)
	}
	if cfg.hasArgon2Params {
		if err := cfg.argon2Params.validateForCreate(cfg.allowWeakArgon2); err != nil {
			return err
		}
	}

	v.mu.RLock()
	closed := v.closed
	ownStore := v.store
	exportHdr := v.hdr
	v.mu.RUnlock()

	if closed {
		return ErrVaultClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if sameStorage(ownStore, dst) {
		return ErrSameStorage
	}

	if !cfg.overwrite {
		if err := checkStorageNotExists(ctx, dst); err != nil {
			return err
		}
	}

	var derivedIndexCipher *crypto.Cipher
	var exportSecretCipher *crypto.Cipher

	if cfg.hasPassword {
		salt, err := crypto.RandomBytes(crypto.SaltSize)
		if err != nil {
			return err
		}
		copy(exportHdr.Salt[:], salt)
		if cfg.hasArgon2Params {
			exportHdr.Params = cfg.argon2Params
		}
		ic, sc, err := deriveVaultCiphers(cfg.password, exportHdr.Salt[:], exportHdr.Params)
		if err != nil {
			return err
		}
		defer ic.Close()
		defer sc.Close()
		if err := ctx.Err(); err != nil {
			return err
		}
		derivedIndexCipher = ic
		exportSecretCipher = sc
	}

	envelope, err := func() ([]byte, error) {
		v.mu.RLock()
		defer v.mu.RUnlock()

		if v.closed {
			return nil, ErrVaultClosed
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if sameStorage(v.store, dst) {
			return nil, ErrSameStorage
		}

		exportIndexCipher := v.indexCipher
		if derivedIndexCipher != nil {
			exportIndexCipher = derivedIndexCipher
		}

		ids := slices.Sorted(maps.Keys(v.entries))
		pbEntries := make([]*vaultpb.Entry, 0, len(ids))
		defer func() {
			for _, pe := range pbEntries {
				crypto.ZeroBytes(pe.SecretNonce)
				crypto.ZeroBytes(pe.EncryptedSecret)
			}
		}()

		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			rec := v.entries[id]
			pe := rec.toProto()

			if exportSecretCipher != nil {
				aad := entryAAD(rec.id, rec.version)
				paddedPlain, err := v.secretCipher.Decrypt(rec.secretNonce, rec.encryptedSecret, aad)
				if err != nil {
					return nil, fmt.Errorf("%w: %w", ErrSecretCorrupted, err)
				}
				unpadded, err := unpadSecret(paddedPlain)
				if err != nil {
					crypto.ZeroBytes(paddedPlain)
					return nil, err
				}
				if err := validateSecretPayloadWire(unpadded); err != nil {
					crypto.ZeroBytes(paddedPlain)
					return nil, err
				}
				newNonce, newCT, err := exportSecretCipher.Encrypt(paddedPlain, aad)
				crypto.ZeroBytes(paddedPlain)
				if err != nil {
					return nil, fmt.Errorf("passwordium: re-encrypt exported secret: %w", err)
				}
				crypto.ZeroBytes(pe.SecretNonce)
				crypto.ZeroBytes(pe.EncryptedSecret)
				pe.SecretNonce = newNonce
				pe.EncryptedSecret = newCT
			}
			pbEntries = append(pbEntries, pe)
		}

		exportVersion := v.version
		if exportVersion == 0 {
			exportVersion = 1
		}
		now := time.Now().UTC().Unix()

		plaintext, err := proto.Marshal(&vaultpb.VaultData{
			Version:   exportVersion,
			UpdatedAt: now,
			Entries:   pbEntries,
		})
		if err != nil {
			return nil, fmt.Errorf("passwordium: marshal exported vault: %w", err)
		}
		defer crypto.ZeroBytes(plaintext)

		headerBytes := exportHdr.marshal()
		nonce, ciphertext, err := exportIndexCipher.Encrypt(plaintext, headerBytes)
		if err != nil {
			return nil, fmt.Errorf("passwordium: encrypt exported vault: %w", err)
		}
		return packEnvelope(headerBytes, nonce, ciphertext), nil
	}()
	if err != nil {
		return err
	}

	if !cfg.overwrite {
		if es, ok := dst.(exclusiveSaver); ok {
			return es.SaveNew(ctx, envelope)
		}
		if err := checkStorageNotExists(ctx, dst); err != nil {
			return err
		}
	}
	return dst.Save(ctx, envelope)
}

// Import opens and authenticates an external encrypted vault from src using srcPassword,
// verifies and re-encrypts every entry's padded SecretPayload under v's secretKey without
// allocating Go strings for secret payloads, and merges the entries into v according to
// the configured ConflictPolicy (defaulting to ConflictKeepNewer).
//
// Import enforces pre-KDF Argon2id resource limits on src's header (configurable via
// WithMaxArgon2Params and WithMaxArgon2Work) and performs the source vault KDF outside
// v's write lock. Every source entry's secret is decrypted, unpadded, and validated at
// the protobuf wire level (including UTF-8 validation) before any entry in v is modified,
// ensuring corrupted source entries are never silently ignored even if they would be
// skipped by the conflict policy.
//
// Import is atomic: if any entry in src fails authentication, wire validation, or version
// overflow checks, or if WithAutoSave(true) persistence fails, v's in-memory entries and
// dirty state remain completely unchanged. When staged entries are added or updated, v is
// marked dirty (or saved immediately when WithAutoSave(true) is enabled); if all source
// entries are skipped, v's dirty state is left untouched.
//
// Import does not mutate srcPassword; callers should zero srcPassword (for example, via
// clear(srcPassword)) once Import returns.
//
// Import returns an ImportResult with Added, Updated, and Skipped counts, or an error:
//   - ctx.Err() if ctx is canceled,
//   - ErrNilStorage if src is nil,
//   - ErrInvalidConflictPolicy if WithConflictPolicy specifies an invalid policy,
//   - ErrVaultClosed if v is closed,
//   - ErrSameStorage if src refers to the same Storage instance or file as v's store,
//   - any header, limit, password, or format error returned by Open on src,
//   - ErrSecretCorrupted if any entry secret in src fails AEAD verification, unpadding,
//     or protobuf wire/UTF-8 validation,
//   - ErrCorruptedVault if merging a conflicting entry's version would overflow uint64, or
//   - any storage error if WithAutoSave(true) persistence fails.
func (v *Vault) Import(ctx context.Context, src Storage, srcPassword []byte, opts ...ImportOption) (ImportResult, error) {
	if err := ctx.Err(); err != nil {
		return ImportResult{}, err
	}
	if src == nil {
		return ImportResult{}, ErrNilStorage
	}

	cfg := defaultImportConfig()
	for _, opt := range opts {
		if opt != nil {
			opt.applyImport(&cfg)
		}
	}
	if !cfg.conflictPolicy.valid() {
		return ImportResult{}, fmt.Errorf("%w: %d", ErrInvalidConflictPolicy, cfg.conflictPolicy)
	}

	v.mu.RLock()
	closed := v.closed
	ownStore := v.store
	v.mu.RUnlock()
	if closed {
		return ImportResult{}, ErrVaultClosed
	}

	if sameStorage(ownStore, src) {
		return ImportResult{}, ErrSameStorage
	}

	srcVault, err := Open(ctx, src, srcPassword, cfg.openOpts...)
	if err != nil {
		return ImportResult{}, err
	}
	defer func() { _ = srcVault.Close() }()

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return ImportResult{}, ErrVaultClosed
	}
	if err := ctx.Err(); err != nil {
		return ImportResult{}, err
	}
	if sameStorage(v.store, src) {
		return ImportResult{}, ErrSameStorage
	}

	type stagedImport struct {
		id       string
		rec      *entryRecord
		isUpdate bool
		prev     *entryRecord
	}

	srcIDs := slices.Sorted(maps.Keys(srcVault.entries))
	staged := make([]stagedImport, 0, len(srcIDs))
	cleanupStaged := func() {
		for _, s := range staged {
			s.rec.zeroSecret()
		}
	}

	var res ImportResult
	for _, srcID := range srcIDs {
		if err := ctx.Err(); err != nil {
			cleanupStaged()
			return ImportResult{}, err
		}

		srcRec := srcVault.entries[srcID]
		// Always decrypt and verify every source entry secret before mutating v so
		// corrupted entries in src are never silently skipped.
		paddedPlain, err := srcVault.secretCipher.Decrypt(srcRec.secretNonce, srcRec.encryptedSecret, entryAAD(srcRec.id, srcRec.version))
		if err != nil {
			cleanupStaged()
			return ImportResult{}, fmt.Errorf("%w: %w", ErrSecretCorrupted, err)
		}
		unpadded, err := unpadSecret(paddedPlain)
		if err != nil {
			crypto.ZeroBytes(paddedPlain)
			cleanupStaged()
			return ImportResult{}, err
		}
		if err := validateSecretPayloadWire(unpadded); err != nil {
			crypto.ZeroBytes(paddedPlain)
			cleanupStaged()
			return ImportResult{}, err
		}

		targetID := srcRec.id
		targetVersion := srcRec.version
		targetCreatedAt := srcRec.createdAt
		targetUpdatedAt := srcRec.updatedAt
		isUpdate := false

		existing, exists := v.entries[targetID]
		if exists {
			switch cfg.conflictPolicy {
			case ConflictKeepExisting:
				crypto.ZeroBytes(paddedPlain)
				res.Skipped++
				continue
			case ConflictKeepNewer:
				if srcRec.updatedAt <= existing.updatedAt {
					crypto.ZeroBytes(paddedPlain)
					res.Skipped++
					continue
				}
				maxVer := max(existing.version, srcRec.version)
				if maxVer >= math.MaxUint64-1 {
					crypto.ZeroBytes(paddedPlain)
					cleanupStaged()
					return ImportResult{}, fmt.Errorf("%w: entry %q version overflow", ErrCorruptedVault, targetID)
				}
				isUpdate = true
				targetVersion = maxVer + 1
				targetCreatedAt = existing.createdAt
			case ConflictOverwrite:
				maxVer := max(existing.version, srcRec.version)
				if maxVer >= math.MaxUint64-1 {
					crypto.ZeroBytes(paddedPlain)
					cleanupStaged()
					return ImportResult{}, fmt.Errorf("%w: entry %q version overflow", ErrCorruptedVault, targetID)
				}
				isUpdate = true
				targetVersion = maxVer + 1
				targetCreatedAt = existing.createdAt
				targetUpdatedAt = max(srcRec.updatedAt, existing.updatedAt)
			case ConflictKeepBoth:
				newID, err := generateUUIDv4()
				if err != nil {
					crypto.ZeroBytes(paddedPlain)
					cleanupStaged()
					return ImportResult{}, err
				}
				targetID = newID
				targetVersion = 1
			}
		}

		newNonce, newCT, err := v.secretCipher.Encrypt(paddedPlain, entryAAD(targetID, targetVersion))
		crypto.ZeroBytes(paddedPlain)
		if err != nil {
			cleanupStaged()
			return ImportResult{}, fmt.Errorf("passwordium: encrypt imported secret: %w", err)
		}

		newRec := &entryRecord{
			id:              targetID,
			version:         targetVersion,
			title:           srcRec.title,
			username:        srcRec.username,
			url:             srcRec.url,
			tags:            slices.Clone(srcRec.tags),
			createdAt:       targetCreatedAt,
			updatedAt:       targetUpdatedAt,
			secretNonce:     newNonce,
			encryptedSecret: newCT,
		}
		staged = append(staged, stagedImport{
			id:       targetID,
			rec:      newRec,
			isUpdate: isUpdate,
			prev:     existing,
		})
		if isUpdate {
			res.Updated++
		} else {
			res.Added++
		}
	}

	if len(staged) == 0 {
		return res, nil
	}

	prevDirty := v.dirty
	for _, s := range staged {
		v.entries[s.id] = s.rec
	}
	v.dirty = true

	if v.autoSave {
		if err := v.saveLocked(ctx); err != nil {
			for _, s := range staged {
				if s.isUpdate {
					v.entries[s.id] = s.prev
				} else {
					delete(v.entries, s.id)
				}
			}
			v.dirty = prevDirty
			cleanupStaged()
			return ImportResult{}, err
		}
	}

	for _, s := range staged {
		if s.isUpdate && s.prev != nil {
			s.prev.zeroSecret()
		}
	}

	return res, nil
}

func (v *Vault) marshalEnvelopeLocked(nextVersion uint64, now int64) ([]byte, error) {
	ids := slices.Sorted(maps.Keys(v.entries))
	pbEntries := make([]*vaultpb.Entry, 0, len(ids))
	for _, id := range ids {
		pbEntries = append(pbEntries, v.entries[id].toProto())
	}

	plaintext, err := proto.Marshal(&vaultpb.VaultData{
		Version:   nextVersion,
		UpdatedAt: now,
		Entries:   pbEntries,
	})
	if err != nil {
		return nil, fmt.Errorf("passwordium: marshal vault: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	headerBytes := v.hdr.marshal()
	nonce, ciphertext, err := v.indexCipher.Encrypt(plaintext, headerBytes)
	if err != nil {
		return nil, fmt.Errorf("passwordium: encrypt vault: %w", err)
	}
	return packEnvelope(headerBytes, nonce, ciphertext), nil
}

func (v *Vault) saveInitialLocked(ctx context.Context, overwrite bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.version >= math.MaxUint64-1 {
		return fmt.Errorf("%w: vault version overflow", ErrCorruptedVault)
	}

	nextVersion := v.version + 1
	now := time.Now().UTC().Unix()

	envelope, err := v.marshalEnvelopeLocked(nextVersion, now)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(envelope)

	if !overwrite {
		if es, ok := v.store.(exclusiveSaver); ok {
			if err := es.SaveNew(ctx, envelope); err != nil {
				return err
			}
		} else {
			if err := checkStorageNotExists(ctx, v.store); err != nil {
				return err
			}
			if err := v.store.Save(ctx, envelope); err != nil {
				return err
			}
		}
	} else {
		if err := v.store.Save(ctx, envelope); err != nil {
			return err
		}
	}

	v.version = nextVersion
	v.updatedAt = now
	v.lastDigest = digest
	v.hasDigest = true
	v.dirty = false
	return nil
}

func (v *Vault) saveLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.version >= math.MaxUint64-1 {
		return fmt.Errorf("%w: vault version overflow", ErrCorruptedVault)
	}

	nextVersion := v.version + 1
	now := time.Now().UTC().Unix()

	envelope, err := v.marshalEnvelopeLocked(nextVersion, now)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(envelope)

	if v.hasDigest {
		if cs, ok := v.store.(conditionalSaver); ok {
			if err := cs.SaveIfMatch(ctx, envelope, v.lastDigest); err != nil {
				return err
			}
		} else {
			if err := v.store.Save(ctx, envelope); err != nil {
				return err
			}
		}
	} else {
		if err := v.store.Save(ctx, envelope); err != nil {
			return err
		}
	}

	v.version = nextVersion
	v.updatedAt = now
	v.lastDigest = digest
	v.hasDigest = true
	v.dirty = false
	return nil
}

// Close releases v's session AEAD instances (indexCipher and secretCipher), zeroes all
// in-memory encrypted entry secrets and nonces via clear(), empties the entry index map,
// clears the stored concurrency digest, and marks v as closed so subsequent operations
// fail with ErrVaultClosed.
//
// Close does not perform any Storage I/O; any unsaved in-memory modifications
// (when Vault.Dirty reports true) are discarded. Call Vault.Save before Close, use
// Vault.CloseWithSave, or configure WithAutoSave(true) to persist changes.
// Calling Close multiple times is safe and idempotent, and always returns nil.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.closeLocked()
	return nil
}

// CloseWithSave atomically persists any unsaved in-memory modifications (when Vault.Dirty
// is true) to v's backing Storage before closing and wiping v as described in Vault.Close.
//
// If v is not dirty, CloseWithSave closes and wipes v without writing to Storage.
// If v is already closed, CloseWithSave is a no-op and returns nil (unless ctx is
// already canceled, in which case ctx.Err() is returned).
//
// If saving to Storage fails (for example, due to I/O failure, context cancellation,
// ErrVaultTooLarge, or ErrConcurrentModification), CloseWithSave aborts the close and
// leaves v open with its in-memory entries and dirty state intact so the caller can
// retry, export a backup snapshot via Vault.Export, or inspect the unsaved state.
func (v *Vault) CloseWithSave(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return nil
	}
	if v.dirty {
		if err := v.saveLocked(ctx); err != nil {
			return err
		}
	}
	v.closeLocked()
	return nil
}

func (v *Vault) closeLocked() {
	if v.closed {
		return
	}

	v.indexCipher.Close()
	v.secretCipher.Close()
	v.indexCipher = nil
	v.secretCipher = nil

	for _, rec := range v.entries {
		rec.zeroSecret()
	}
	clear(v.entries)
	v.entries = nil
	crypto.ZeroBytes(v.lastDigest[:])
	v.hasDigest = false
	v.dirty = false
	v.closed = true
}

// Dirty reports whether v currently has in-memory entry modifications (from Vault.Put,
// Vault.Delete, Vault.DeleteContext, or Vault.Import) that have not yet been persisted
// to Storage.
//
// Dirty returns false for a newly created or freshly opened Vault, immediately after
// a successful Vault.Save or auto-saved mutation, and after v has been closed.
func (v *Vault) Dirty() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return !v.closed && v.dirty
}

// Len returns the number of entries currently stored in v's in-memory index, or 0 if
// v has been closed.
func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return 0
	}
	return len(v.entries)
}

// Version returns the monotonically increasing container version of v as last persisted
// to or loaded from Storage (starting at 1 when created by Create and incrementing by 1
// on each successful Save), or 0 if v has been closed.
//
// In-memory mutations that have not yet been saved do not increment Version until
// Vault.Save, Vault.CloseWithSave, or an auto-saved mutation succeeds. Callers can
// record Version in external trusted metadata to detect whole-file rollback attacks
// on the underlying Storage backend.
func (v *Vault) Version() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return 0
	}
	return v.version
}

// UpdatedAt returns the UTC timestamp (at 1-second Unix resolution) of v's last
// persisted state (updated on Create and on each successful Save), or the zero
// time.Time value if v has been closed.
func (v *Vault) UpdatedAt() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed || v.updatedAt == 0 {
		return time.Time{}
	}
	return time.Unix(v.updatedAt, 0).UTC()
}
