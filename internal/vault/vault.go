package vault

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dmi3midd/passwordium/internal/crypto"
	"github.com/dmi3midd/passwordium/internal/vault/pb"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	CurrentVaultVersion   uint32 = 1
	SaltSize                     = 32
	FileEncryptionContext        = "vault-file-encryption-v1"
	EntryEncryptionCtx           = "vault-entry-encryption-v1"
)

var (
	ErrInvalidMasterPassword = errors.New("невірний майстер-пароль або пошкоджений файл сховища (помилка автентифікації Poly1305)")
	ErrEntryNotFound         = errors.New("запис не знайдено")
	ErrCorruptedVaultFile    = errors.New("файл сховища пошкоджений або має невірний формат")
)

// Vault manages the in-memory state of the password store.
// Only derived subkeys (fileKey, entryKey) and entry metadata + encrypted fields
// are kept in memory; plaintext passwords and notes are decrypted on demand.
type Vault struct {
	mu       sync.RWMutex
	path     string
	version  uint32
	salt     []byte
	fileKey  []byte
	entryKey []byte
	payload  *pb.VaultPayload
}

// Exists checks whether the vault file already exists on disk.
func Exists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Size() > 0
}

// Create initializes a brand-new encrypted vault on disk using the provided master password.
func Create(path string, masterPassword []byte) (*Vault, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	fileKey, entryKey, err := deriveSubKeys(masterPassword, salt)
	if err != nil {
		return nil, err
	}

	v := &Vault{
		path:     path,
		version:  CurrentVaultVersion,
		salt:     salt,
		fileKey:  fileKey,
		entryKey: entryKey,
		payload: &pb.VaultPayload{
			Entries: []*pb.VaultEntry{},
		},
	}

	if err := v.Save(); err != nil {
		v.Close()
		return nil, err
	}

	return v, nil
}

// Open reads an existing vault file from disk, derives keys from the master password and salt,
// and verifies + decrypts the outer VaultPayload.
func Open(path string, masterPassword []byte) (*Vault, error) {
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault file: %w", err)
	}

	var encFile pb.EncryptedVaultFile
	if err := proto.Unmarshal(rawBytes, &encFile); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedVaultFile, err)
	}

	if len(encFile.Salt) != 16 && len(encFile.Salt) != 32 {
		return nil, fmt.Errorf("%w: невірний розмір солі (%d байтів)", ErrCorruptedVaultFile, len(encFile.Salt))
	}
	if len(encFile.FileNonce) != 24 {
		return nil, fmt.Errorf("%w: невірний розмір file_nonce (%d байтів)", ErrCorruptedVaultFile, len(encFile.FileNonce))
	}

	fileKey, entryKey, err := deriveSubKeys(masterPassword, encFile.Salt)
	if err != nil {
		return nil, err
	}

	aad := buildFileAAD(encFile.Version, encFile.Salt)
	decryptedBytes, err := crypto.Decrypt(fileKey, encFile.FileNonce, encFile.EncryptedPayload, aad)
	if err != nil {
		ZeroBytes(fileKey)
		ZeroBytes(entryKey)
		return nil, ErrInvalidMasterPassword
	}
	defer ZeroBytes(decryptedBytes)

	var payload pb.VaultPayload
	if err := proto.Unmarshal(decryptedBytes, &payload); err != nil {
		ZeroBytes(fileKey)
		ZeroBytes(entryKey)
		return nil, fmt.Errorf("%w: %v", ErrCorruptedVaultFile, err)
	}

	return &Vault{
		path:     path,
		version:  encFile.Version,
		salt:     encFile.Salt,
		fileKey:  fileKey,
		entryKey: entryKey,
		payload:  &payload,
	}, nil
}

// deriveSubKeys derives masterKey with Argon2id, derives fileKey and entryKey with HKDF,
// and immediately zeroes masterKey from memory.
func deriveSubKeys(masterPassword, salt []byte) (fileKey, entryKey []byte, err error) {
	masterKey := crypto.DeriveMasterKey(masterPassword, salt)
	defer ZeroBytes(masterKey)

	fileKey, err = crypto.DeriveSubKey(masterKey, FileEncryptionContext)
	if err != nil {
		return nil, nil, fmt.Errorf("derive file subkey: %w", err)
	}

	entryKey, err = crypto.DeriveSubKey(masterKey, EntryEncryptionCtx)
	if err != nil {
		ZeroBytes(fileKey)
		return nil, nil, fmt.Errorf("derive entry subkey: %w", err)
	}

	return fileKey, entryKey, nil
}

// buildFileAAD constructs the Associated Data (version + salt) for outer file encryption.
func buildFileAAD(version uint32, salt []byte) []byte {
	aad := make([]byte, 4+len(salt))
	binary.BigEndian.PutUint32(aad[:4], version)
	copy(aad[4:], salt)
	return aad
}

// Save atomically persists the encrypted vault to disk via a temporary file (0600) + os.Rename.
func (v *Vault) Save() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.saveLocked()
}

func (v *Vault) saveLocked() error {
	payloadBytes, err := proto.Marshal(v.payload)
	if err != nil {
		return fmt.Errorf("marshal vault payload: %w", err)
	}
	defer ZeroBytes(payloadBytes)

	aad := buildFileAAD(v.version, v.salt)
	fileNonce, encryptedPayload, err := crypto.Encrypt(v.fileKey, payloadBytes, aad)
	if err != nil {
		return fmt.Errorf("encrypt vault payload: %w", err)
	}

	encFile := &pb.EncryptedVaultFile{
		Version:          v.version,
		Salt:             v.salt,
		FileNonce:        fileNonce,
		EncryptedPayload: encryptedPayload,
	}

	outBytes, err := proto.Marshal(encFile)
	if err != nil {
		return fmt.Errorf("marshal encrypted vault file: %w", err)
	}

	dir := filepath.Dir(v.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create vault directory: %w", err)
		}
	}

	tmpPath := v.path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp vault file: %w", err)
	}

	if _, err := f.Write(outBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp vault file: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync temp vault file: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp vault file: %w", err)
	}

	if err := os.Rename(tmpPath, v.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename vault file: %w", err)
	}

	return nil
}

// Close wipes sensitive subkeys from memory.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	ZeroBytes(v.fileKey)
	ZeroBytes(v.entryKey)
}

// Entries returns a shallow slice copy of the vault entries.
// Sensitive fields inside each entry remain encrypted.
func (v *Vault) Entries() []*pb.VaultEntry {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.payload == nil {
		return nil
	}
	res := make([]*pb.VaultEntry, len(v.payload.Entries))
	copy(res, v.payload.Entries)
	return res
}

// GetEntry finds an entry by its UUID.
func (v *Vault) GetEntry(id string) (*pb.VaultEntry, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, e := range v.payload.Entries {
		if e.Id == id {
			return e, true
		}
	}
	return nil, false
}

// AddEntry creates a new entry, encrypts its password and notes with entryKey (AAD = entry.Id),
// appends it to the vault, and atomically saves the vault file.
func (v *Vault) AddEntry(title, username, password, url, notes string) (*pb.VaultEntry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	id := uuid.NewString()
	aad := []byte(id)

	pwBytes := []byte(password)
	defer ZeroBytes(pwBytes)
	pwNonce, encPw, err := crypto.Encrypt(v.entryKey, pwBytes, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt entry password: %w", err)
	}

	notesBytes := []byte(notes)
	defer ZeroBytes(notesBytes)
	notesNonce, encNotes, err := crypto.Encrypt(v.entryKey, notesBytes, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt entry notes: %w", err)
	}

	now := time.Now().Unix()
	entry := &pb.VaultEntry{
		Id:                id,
		Title:             title,
		Username:          username,
		Url:               url,
		PasswordNonce:     pwNonce,
		EncryptedPassword: encPw,
		NotesNonce:        notesNonce,
		EncryptedNotes:    encNotes,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	v.payload.Entries = append(v.payload.Entries, entry)
	if err := v.saveLocked(); err != nil {
		v.payload.Entries = v.payload.Entries[:len(v.payload.Entries)-1]
		return nil, err
	}

	return entry, nil
}

// UpdateEntry updates an existing entry by ID, re-encrypting its password and notes with fresh nonces,
// and atomically saves the vault file.
func (v *Vault) UpdateEntry(id, title, username, password, url, notes string) (*pb.VaultEntry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	idx := -1
	for i, e := range v.payload.Entries {
		if e.Id == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, ErrEntryNotFound
	}

	aad := []byte(id)

	pwBytes := []byte(password)
	defer ZeroBytes(pwBytes)
	pwNonce, encPw, err := crypto.Encrypt(v.entryKey, pwBytes, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt entry password: %w", err)
	}

	notesBytes := []byte(notes)
	defer ZeroBytes(notesBytes)
	notesNonce, encNotes, err := crypto.Encrypt(v.entryKey, notesBytes, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt entry notes: %w", err)
	}

	orig := v.payload.Entries[idx]
	updated := &pb.VaultEntry{
		Id:                id,
		Title:             title,
		Username:          username,
		Url:               url,
		PasswordNonce:     pwNonce,
		EncryptedPassword: encPw,
		NotesNonce:        notesNonce,
		EncryptedNotes:    encNotes,
		CreatedAt:         orig.CreatedAt,
		UpdatedAt:         time.Now().Unix(),
	}

	v.payload.Entries[idx] = updated
	if err := v.saveLocked(); err != nil {
		v.payload.Entries[idx] = orig
		return nil, err
	}

	return updated, nil
}

// DeleteEntry removes an entry by ID and atomically saves the vault file.
func (v *Vault) DeleteEntry(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	idx := -1
	for i, e := range v.payload.Entries {
		if e.Id == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ErrEntryNotFound
	}

	removed := v.payload.Entries[idx]
	v.payload.Entries = append(v.payload.Entries[:idx], v.payload.Entries[idx+1:]...)
	if err := v.saveLocked(); err != nil {
		// Restore on failure
		entries := make([]*pb.VaultEntry, 0, len(v.payload.Entries)+1)
		entries = append(entries, v.payload.Entries[:idx]...)
		entries = append(entries, removed)
		entries = append(entries, v.payload.Entries[idx:]...)
		v.payload.Entries = entries
		return err
	}

	return nil
}

// DecryptPassword decrypts a single entry's password on demand using entryKey and AAD = entry.Id.
func (v *Vault) DecryptPassword(entry *pb.VaultEntry) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if entry == nil {
		return "", ErrEntryNotFound
	}
	plain, err := crypto.Decrypt(v.entryKey, entry.PasswordNonce, entry.EncryptedPassword, []byte(entry.Id))
	if err != nil {
		return "", fmt.Errorf("decrypt entry password: %w", err)
	}
	defer ZeroBytes(plain)
	return string(plain), nil
}

// DecryptNotes decrypts a single entry's notes on demand using entryKey and AAD = entry.Id.
func (v *Vault) DecryptNotes(entry *pb.VaultEntry) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if entry == nil {
		return "", ErrEntryNotFound
	}
	if len(entry.EncryptedNotes) == 0 && len(entry.NotesNonce) == 0 {
		return "", nil
	}
	plain, err := crypto.Decrypt(v.entryKey, entry.NotesNonce, entry.EncryptedNotes, []byte(entry.Id))
	if err != nil {
		return "", fmt.Errorf("decrypt entry notes: %w", err)
	}
	defer ZeroBytes(plain)
	return string(plain), nil
}

