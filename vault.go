package passwordium

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dmi3midd/passwordium/internal/crypto"
	"github.com/dmi3midd/passwordium/internal/vaultpb"
	"google.golang.org/protobuf/proto"
)

//go:generate protoc --go_out=. --go_opt=module=github.com/dmi3midd/passwordium proto/vault.proto

const (
	hkdfContextIndex  = "passwordium:v1:index"
	hkdfContextSecret = "passwordium:v1:secret"
)

// Vault is a thread-safe encrypted credential store backed by a Storage implementation.
// Entry metadata is kept indexed in memory after Open for fast search, while each
// entry's SecretPayload remains encrypted in memory until GetSecret is called.
type Vault struct {
	mu        sync.RWMutex
	store     Storage
	hdr       header
	masterKey []byte
	indexKey  []byte
	secretKey []byte
	entries   map[string]*entryRecord
	version   uint64
	updatedAt int64
	dirty     bool
	autoSave  bool
	closed    bool
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

func deriveVaultKeys(masterPassword, salt []byte, params Argon2Params) (masterKey, indexKey, secretKey []byte, err error) {
	masterKey = crypto.DeriveMasterKey(masterPassword, salt, params.toCrypto())
	indexKey, err = crypto.DeriveSubKey(masterKey, hkdfContextIndex)
	if err != nil {
		crypto.ZeroBytes(masterKey)
		return nil, nil, nil, err
	}
	secretKey, err = crypto.DeriveSubKey(masterKey, hkdfContextSecret)
	if err != nil {
		crypto.ZeroBytes(indexKey)
		crypto.ZeroBytes(masterKey)
		return nil, nil, nil, err
	}
	return masterKey, indexKey, secretKey, nil
}

// Create initializes a brand-new encrypted vault with a fresh random salt,
// derives keys from masterPassword using Argon2id + HKDF-SHA256, and immediately
// saves the empty vault to store.
func Create(ctx context.Context, store Storage, masterPassword []byte, opts ...Option) (*Vault, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrNilStorage
	}
	if len(masterPassword) == 0 {
		return nil, ErrEmptyPassword
	}

	cfg := defaultVaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if err := cfg.argon2Params.validate(); err != nil {
		return nil, err
	}

	salt, err := crypto.RandomBytes(crypto.SaltSize)
	if err != nil {
		return nil, err
	}

	var hdr header
	hdr.Version = currentVersion
	copy(hdr.Salt[:], salt)
	hdr.Params = cfg.argon2Params

	masterKey, indexKey, secretKey, err := deriveVaultKeys(masterPassword, hdr.Salt[:], hdr.Params)
	if err != nil {
		return nil, err
	}

	v := &Vault{
		store:     store,
		hdr:       hdr,
		masterKey: masterKey,
		indexKey:  indexKey,
		secretKey: secretKey,
		entries:   make(map[string]*entryRecord),
		updatedAt: time.Now().UTC().Unix(),
		autoSave:  cfg.autoSave,
	}

	if err := v.Save(ctx); err != nil {
		_ = v.Close()
		return nil, err
	}
	return v, nil
}

// Open loads an existing vault from store, verifies the binary header and AAD,
// derives keys from masterPassword, and decrypts the VaultData container index.
// Individual entry secrets remain encrypted in memory until GetSecret is called.
func Open(ctx context.Context, store Storage, masterPassword []byte, opts ...Option) (*Vault, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrNilStorage
	}

	cfg := defaultVaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	raw, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}

	hdr, headerBytes, nonce, ciphertext, err := unpackEnvelope(raw)
	if err != nil {
		return nil, err
	}

	masterKey, indexKey, secretKey, err := deriveVaultKeys(masterPassword, hdr.Salt[:], hdr.Params)
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.Decrypt(indexKey, nonce, ciphertext, headerBytes)
	if err != nil {
		crypto.ZeroBytes(secretKey)
		crypto.ZeroBytes(indexKey)
		crypto.ZeroBytes(masterKey)
		return nil, ErrInvalidPassword
	}
	defer crypto.ZeroBytes(plaintext)

	var pb vaultpb.VaultData
	if err := proto.Unmarshal(plaintext, &pb); err != nil {
		crypto.ZeroBytes(secretKey)
		crypto.ZeroBytes(indexKey)
		crypto.ZeroBytes(masterKey)
		return nil, fmt.Errorf("%w: %w", ErrCorruptedVault, err)
	}

	entries := make(map[string]*entryRecord, len(pb.Entries))
	for _, e := range pb.Entries {
		if e == nil || e.Id == "" {
			crypto.ZeroBytes(secretKey)
			crypto.ZeroBytes(indexKey)
			crypto.ZeroBytes(masterKey)
			return nil, fmt.Errorf("%w: entry missing id", ErrCorruptedVault)
		}
		if _, dup := entries[e.Id]; dup {
			crypto.ZeroBytes(secretKey)
			crypto.ZeroBytes(indexKey)
			crypto.ZeroBytes(masterKey)
			return nil, fmt.Errorf("%w: duplicate entry id %q", ErrCorruptedVault, e.Id)
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
			secretNonce:     bytes.Clone(e.SecretNonce),
			encryptedSecret: bytes.Clone(e.EncryptedSecret),
		}
	}

	return &Vault{
		store:     store,
		hdr:       hdr,
		masterKey: masterKey,
		indexKey:  indexKey,
		secretKey: secretKey,
		entries:   entries,
		version:   pb.Version,
		updatedAt: pb.UpdatedAt,
		autoSave:  cfg.autoSave,
	}, nil
}

// Put creates a new entry (generating a UUIDv4 when meta.ID is empty) or updates
// an existing entry (incrementing its version). Secret is encrypted immediately
// with secretKey using "<entry_id>:<entry_version>" as associated data.
func (v *Vault) Put(ctx context.Context, meta EntryMeta, secret Secret) (string, error) {
	if err := ctx.Err(); err != nil {
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
	if exists {
		version = existing.version + 1
		createdAt = existing.createdAt
	}

	pbSecret := &vaultpb.SecretPayload{
		Password:     secret.Password,
		Notes:        secret.Notes,
		CustomFields: maps.Clone(secret.CustomFields),
	}
	plainSecret, err := proto.Marshal(pbSecret)
	if err != nil {
		return "", fmt.Errorf("passwordium: marshal secret: %w", err)
	}
	defer crypto.ZeroBytes(plainSecret)

	secretNonce, encryptedSecret, err := crypto.Encrypt(v.secretKey, plainSecret, entryAAD(id, version))
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
		updatedAt:       now,
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

// GetMeta returns the metadata for entry id without decrypting its secret.
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

// GetSecret decrypts and returns the Secret for entry id.
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

	plain, err := crypto.Decrypt(v.secretKey, rec.secretNonce, rec.encryptedSecret, entryAAD(rec.id, rec.version))
	if err != nil {
		return Secret{}, fmt.Errorf("%w: %w", ErrSecretCorrupted, err)
	}
	defer crypto.ZeroBytes(plain)

	var pb vaultpb.SecretPayload
	if err := proto.Unmarshal(plain, &pb); err != nil {
		return Secret{}, fmt.Errorf("%w: %w", ErrSecretCorrupted, err)
	}

	return Secret{
		Password:     pb.Password,
		Notes:        pb.Notes,
		CustomFields: maps.Clone(pb.CustomFields),
	}, nil
}

// Delete removes entry id from the vault.
func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return ErrVaultClosed
	}

	rec, ok := v.entries[id]
	if !ok {
		return ErrEntryNotFound
	}

	prevDirty := v.dirty
	delete(v.entries, id)
	v.dirty = true

	if v.autoSave {
		if err := v.saveLocked(context.Background()); err != nil {
			v.entries[id] = rec
			v.dirty = prevDirty
			return err
		}
	}

	rec.zeroSecret()
	return nil
}

// Search performs a case-insensitive in-memory search over entry metadata
// matching query.Query as a substring of Title, Username, or URL, and requiring
// all tags listed in query.Tags. Results are returned sorted deterministically.
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

// Save serializes the vault index, encrypts it with indexKey using a fresh nonce
// and the 50-byte plaintext header as AAD, and persists the envelope via Storage.
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

func (v *Vault) saveLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	nextVersion := v.version + 1
	now := time.Now().UTC().Unix()

	ids := slices.Sorted(maps.Keys(v.entries))
	pbEntries := make([]*vaultpb.Entry, 0, len(ids))
	for _, id := range ids {
		pbEntries = append(pbEntries, v.entries[id].toProto())
	}

	pbVault := &vaultpb.VaultData{
		Version:   nextVersion,
		UpdatedAt: now,
		Entries:   pbEntries,
	}

	plaintext, err := proto.Marshal(pbVault)
	if err != nil {
		return fmt.Errorf("passwordium: marshal vault: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	headerBytes := v.hdr.marshal()
	nonce, ciphertext, err := crypto.Encrypt(v.indexKey, plaintext, headerBytes)
	if err != nil {
		return fmt.Errorf("passwordium: encrypt vault: %w", err)
	}

	envelope := packEnvelope(headerBytes, nonce, ciphertext)
	if err := v.store.Save(ctx, envelope); err != nil {
		return err
	}

	v.version = nextVersion
	v.updatedAt = now
	v.dirty = false
	return nil
}

// Close zeroes all derived cryptographic keys and encrypted secrets in memory,
// clears the in-memory entry map, and prevents further operations on the Vault.
// Calling Close multiple times is safe and idempotent.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return nil
	}

	crypto.ZeroBytes(v.masterKey)
	crypto.ZeroBytes(v.indexKey)
	crypto.ZeroBytes(v.secretKey)
	v.masterKey = nil
	v.indexKey = nil
	v.secretKey = nil

	for _, rec := range v.entries {
		rec.zeroSecret()
	}
	clear(v.entries)
	v.entries = nil
	v.dirty = false
	v.closed = true
	return nil
}

// Dirty reports whether the vault has unsaved in-memory modifications.
func (v *Vault) Dirty() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return !v.closed && v.dirty
}

// Len returns the number of entries currently stored in the vault.
func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return 0
	}
	return len(v.entries)
}
