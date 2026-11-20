package passwordium

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

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
// Entry metadata is kept indexed in memory after Open for fast search, while each
// entry's SecretPayload remains encrypted in memory until GetSecret is called.
//
// The master key and raw subkeys are wiped immediately after key derivation; only
// the initialized AEAD instances for indexKey and secretKey are retained for the session.
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

// validateSecretPayloadWire verifies that b is a syntactically valid protobuf
// encoding of vaultpb.SecretPayload without allocating Go strings or maps on the heap.
func validateSecretPayloadWire(b []byte) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return ErrSecretCorrupted
		}
		b = b[n:]

		switch num {
		case 1, 2: // password, notes (string)
			if typ != protowire.BytesType {
				return ErrSecretCorrupted
			}
			_, m := protowire.ConsumeBytes(b)
			if m < 0 {
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
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return ErrSecretCorrupted
			}
			b = b[m:]
		}
	}
	return nil
}

func validateMapEntryWire(b []byte) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return ErrSecretCorrupted
		}
		b = b[n:]

		switch num {
		case 1, 2: // key, value (string)
			if typ != protowire.BytesType {
				return ErrSecretCorrupted
			}
			_, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return ErrSecretCorrupted
			}
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return ErrSecretCorrupted
			}
			b = b[m:]
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

// Create initializes a brand-new encrypted vault with a fresh random salt,
// derives keys from masterPassword using Argon2id + HKDF-SHA256, and immediately
// saves the empty vault to store. Create refuses to replace an existing vault
// (returning ErrAlreadyExists) unless WithOverwrite(true) is supplied, and rejects
// Argon2id memory costs below 16 MiB or parameters exceeding DefaultMaxArgon2Params.
//
// Create does not mutate masterPassword; callers should zero masterPassword
// (for example, via clear(masterPassword)) once it is no longer needed.
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

// Open loads an existing vault from store, enforces resource limits on the
// plaintext header's Argon2id parameters (DefaultMaxArgon2Params, or the bounds
// given via WithMaxArgon2Params / WithMaxArgon2Work) before running any key derivation,
// derives keys from masterPassword, and decrypts the VaultData container index with
// the header as AAD. Individual entry secrets remain encrypted in memory until
// GetSecret is called.
//
// Open does not mutate masterPassword; callers should zero masterPassword
// (for example, via clear(masterPassword)) once it is no longer needed.
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

	entries := make(map[string]*entryRecord, len(pb.Entries))
	for _, e := range pb.Entries {
		if e == nil || e.Id == "" {
			closeCiphers()
			return nil, fmt.Errorf("%w: entry missing id", ErrCorruptedVault)
		}
		if e.Version == 0 {
			closeCiphers()
			return nil, fmt.Errorf("%w: entry %q has invalid version 0", ErrCorruptedVault, e.Id)
		}
		if len(e.SecretNonce) != crypto.NonceSize {
			closeCiphers()
			return nil, fmt.Errorf("%w: entry %q has invalid secret nonce size %d", ErrCorruptedVault, e.Id, len(e.SecretNonce))
		}
		if len(e.EncryptedSecret) < crypto.Overhead {
			closeCiphers()
			return nil, fmt.Errorf("%w: entry %q has truncated encrypted secret", ErrCorruptedVault, e.Id)
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

// GetSecret decrypts and returns the Secret for entry id. The returned
// CustomFields map is freshly allocated and owned by the caller.
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

// Delete removes entry id from the vault. It is equivalent to
// DeleteContext(context.Background(), id); prefer DeleteContext when
// WithAutoSave is enabled and Storage may block.
func (v *Vault) Delete(id string) error {
	return v.DeleteContext(context.Background(), id)
}

// DeleteContext removes entry id from the vault. When WithAutoSave is enabled,
// ctx is propagated to Storage.Save so deadlines and cancellation are honored;
// on save failure the deletion is rolled back.
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

// Export writes a complete encrypted snapshot of the vault's current in-memory state
// to dst without modifying the active Vault's dirty state, version, or backing Storage.
//
// By default:
//   - Export refuses to overwrite an existing vault in dst (returning ErrAlreadyExists)
//     unless WithOverwrite(true) is provided.
//   - Export seals the snapshot using the active vault's header parameters and key
//     hierarchy (with a fresh 24-byte outer nonce), without decrypting entry secrets.
//
// When WithExportPassword(newPassword) is supplied (optionally combined with
// WithArgon2Params), Export generates a fresh 32-byte random salt, derives a new
// key hierarchy, and re-encrypts every entry's padded secret payload in place
// (wiping each temporary byte buffer immediately without allocating Go strings).
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
	defer v.mu.RUnlock()

	if v.closed {
		return ErrVaultClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if same, err := sameStorage(v.store, dst); err != nil {
		return err
	} else if same {
		return ErrSameStorage
	}

	if !cfg.overwrite {
		if err := checkStorageNotExists(ctx, dst); err != nil {
			return err
		}
	}

	exportHdr := v.hdr
	exportIndexCipher := v.indexCipher
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
		exportIndexCipher = ic
		exportSecretCipher = sc
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
			return err
		}
		rec := v.entries[id]
		pe := rec.toProto()

		if exportSecretCipher != nil {
			aad := entryAAD(rec.id, rec.version)
			paddedPlain, err := v.secretCipher.Decrypt(rec.secretNonce, rec.encryptedSecret, aad)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrSecretCorrupted, err)
			}
			unpadded, err := unpadSecret(paddedPlain)
			if err != nil {
				crypto.ZeroBytes(paddedPlain)
				return err
			}
			if err := validateSecretPayloadWire(unpadded); err != nil {
				crypto.ZeroBytes(paddedPlain)
				return err
			}
			newNonce, newCT, err := exportSecretCipher.Encrypt(paddedPlain, aad)
			crypto.ZeroBytes(paddedPlain)
			if err != nil {
				return fmt.Errorf("passwordium: re-encrypt exported secret: %w", err)
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
		return fmt.Errorf("passwordium: marshal exported vault: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	headerBytes := exportHdr.marshal()
	nonce, ciphertext, err := exportIndexCipher.Encrypt(plaintext, headerBytes)
	if err != nil {
		return fmt.Errorf("passwordium: encrypt exported vault: %w", err)
	}
	envelope := packEnvelope(headerBytes, nonce, ciphertext)

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
// verifies and re-encrypts its entry secrets under the active vault's secretKey without
// allocating Go strings for secret payloads, and merges the entries into v according to
// ConflictPolicy (defaulting to ConflictKeepNewer).
//
// Import is atomic: if any entry in src fails authentication or validation, or if
// WithAutoSave persistence fails, v remains unchanged.
//
// Import does not mutate srcPassword; callers should zero srcPassword
// (for example, via clear(srcPassword)) once it is no longer needed.
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

	if same, err := sameStorage(ownStore, src); err != nil {
		return ImportResult{}, err
	} else if same {
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
	if same, err := sameStorage(v.store, src); err != nil {
		return ImportResult{}, err
	} else if same {
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
				isUpdate = true
				targetVersion = max(existing.version, srcRec.version) + 1
				targetCreatedAt = existing.createdAt
			case ConflictOverwrite:
				isUpdate = true
				targetVersion = max(existing.version, srcRec.version) + 1
				targetCreatedAt = existing.createdAt
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
			updatedAt:       srcRec.updatedAt,
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

	nextVersion := v.version + 1
	now := time.Now().UTC().Unix()

	envelope, err := v.marshalEnvelopeLocked(nextVersion, now)
	if err != nil {
		return err
	}

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
	v.lastDigest = sha256.Sum256(envelope)
	v.hasDigest = true
	v.dirty = false
	return nil
}

func (v *Vault) saveLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	nextVersion := v.version + 1
	now := time.Now().UTC().Unix()

	envelope, err := v.marshalEnvelopeLocked(nextVersion, now)
	if err != nil {
		return err
	}

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
	v.lastDigest = sha256.Sum256(envelope)
	v.hasDigest = true
	v.dirty = false
	return nil
}

// Close releases the session AEAD instances, zeroes all encrypted entry secrets
// in memory, clears the in-memory entry map, and prevents further operations on
// the Vault. Any unsaved in-memory modifications (Dirty() == true) are discarded
// without writing to Storage; call Save before Close, use CloseWithSave, or enable
// WithAutoSave to persist changes. Calling Close multiple times is safe and idempotent.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.closeLocked()
	return nil
}

// CloseWithSave persists any unsaved in-memory modifications (when Dirty() is true)
// to Storage before closing and wiping the Vault. If saving fails, the Vault remains
// open and retains its in-memory state so the caller can retry or recover.
// Calling CloseWithSave on an already-closed Vault is a no-op and returns nil.
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
