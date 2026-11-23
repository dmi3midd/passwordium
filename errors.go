package passwordium

import "errors"

var (
	// ErrNotFound is returned by Storage.Load, Open, and Vault.Import when the target
	// vault does not exist in the underlying Storage backend.
	//
	// Custom Storage implementations must return ErrNotFound (or an error wrapping it)
	// from Load when no vault has been persisted yet so that Create and Vault.Export
	// can distinguish an uninitialized backend from an I/O failure.
	ErrNotFound = errors.New("passwordium: vault not found")

	// ErrAlreadyExists is returned by Create and Vault.Export when a vault already
	// exists in the destination Storage backend and WithOverwrite(true) was not supplied.
	//
	// When this error is returned, the existing vault in Storage is left unmodified.
	ErrAlreadyExists = errors.New("passwordium: vault already exists")

	// ErrEntryNotFound is returned by Vault.GetMeta, Vault.GetSecret, Vault.Delete,
	// and Vault.DeleteContext when the requested entry ID is not present in the
	// open Vault's in-memory index.
	ErrEntryNotFound = errors.New("passwordium: entry not found")

	// ErrVaultClosed is returned by any method on Vault (other than Close, CloseWithSave,
	// Search, Dirty, Len, Version, and UpdatedAt) when invoked after the Vault has been
	// closed and its session AEAD ciphers and encrypted entry buffers have been wiped.
	ErrVaultClosed = errors.New("passwordium: vault is closed")

	// ErrInvalidPassword is returned by Open and Vault.Import when the key derived from
	// the supplied master password fails XChaCha20-Poly1305 AEAD authentication of the
	// outer VaultData ciphertext or its 50-byte plaintext header AAD.
	//
	// Because the entire 50-byte header is authenticated as associated data, tampering
	// with the salt, Argon2id parameters, or outer ciphertext after header validation
	// also results in ErrInvalidPassword.
	ErrInvalidPassword = errors.New("passwordium: invalid master password")

	// ErrEmptyPassword is returned by Create when masterPassword is nil or empty,
	// and by Vault.Export when WithExportPassword is supplied with an empty byte slice
	// or when WithArgon2Params is supplied without WithExportPassword.
	ErrEmptyPassword = errors.New("passwordium: master password must not be empty")

	// ErrNilStorage is returned by Create, Open, Vault.Export, and Vault.Import when
	// the provided Storage interface value is nil.
	ErrNilStorage = errors.New("passwordium: storage must not be nil")

	// ErrInvalidHeader is returned by Open and Vault.Import when the serialized vault
	// byte slice is shorter than the fixed 50-byte plaintext header or does not begin
	// with the 4-byte ASCII magic prefix "PSDM".
	ErrInvalidHeader = errors.New("passwordium: invalid vault header")

	// ErrUnsupportedVersion is returned by Open and Vault.Import when the 16-bit big-endian
	// format version in the plaintext header is not supported by this version of passwordium
	// (currently only format version 1 is supported).
	ErrUnsupportedVersion = errors.New("passwordium: unsupported vault version")

	// ErrInvalidArgon2Params is returned by Create, Open, Vault.Export, and Vault.Import
	// when Argon2id parameters violate hard protocol bounds, fall below the 16 MiB
	// creation memory floor, or exceed the maximum resource limits configured for Open
	// or Vault.Import (DefaultMaxArgon2Params, WithMaxArgon2Params, or WithMaxArgon2Work).
	//
	// On Open and Vault.Import, this error is returned during header parsing before any
	// Argon2id key derivation is executed.
	ErrInvalidArgon2Params = errors.New("passwordium: invalid argon2 parameters")

	// ErrCorruptedVault is returned by Open, Vault.Put, Vault.Save, and Vault.Import when
	// the outer envelope is shorter than the minimum 90-byte envelope size, when the
	// decrypted VaultData protobuf payload cannot be unmarshaled, when container or entry
	// invariants are violated (missing or duplicate entry ID, invalid version 0 or
	// math.MaxUint64, invalid 24-byte secret nonce, or unaligned encrypted secret size),
	// or when incrementing a container or entry version would overflow uint64.
	ErrCorruptedVault = errors.New("passwordium: corrupted vault data")

	// ErrSecretCorrupted is returned by Vault.GetSecret, Vault.Export (when re-keying),
	// and Vault.Import when an individual entry's encrypted SecretPayload fails
	// XChaCha20-Poly1305 AEAD verification (including entry "<id>:<version>" AAD mismatch),
	// has invalid ISO/IEC 7816-4 padding, or contains malformed or non-UTF-8 protobuf wire data.
	ErrSecretCorrupted = errors.New("passwordium: entry secret is corrupted")

	// ErrVaultTooLarge is returned by FileStorage.Load, FileStorage.Save, FileStorage.SaveNew,
	// and FileStorage.SaveIfMatch (as well as Vault operations backed by FileStorage) when
	// the serialized vault file size on disk or the buffer being saved exceeds the configured
	// maximum size (DefaultMaxFileSize or WithMaxFileSize).
	ErrVaultTooLarge = errors.New("passwordium: vault exceeds maximum allowed size")

	// ErrInvalidStorageFile is returned by FileStorage methods when the target filesystem
	// path resolves to a non-regular file (such as a symbolic link, directory, FIFO/named pipe,
	// socket, or device node) or when the file inode changes between os.Lstat and os.Open.
	ErrInvalidStorageFile = errors.New("passwordium: storage path is not a regular file")

	// ErrConcurrentModification is returned by Vault.Save, Vault.CloseWithSave, and
	// mutating Vault operations with WithAutoSave(true) (as well as FileStorage.SaveIfMatch
	// and MemoryStorage.SaveIfMatch) when the underlying vault bytes in Storage were
	// modified or removed by another Vault instance or external writer since the Vault
	// was opened or last saved.
	ErrConcurrentModification = errors.New("passwordium: vault was modified concurrently in storage")

	// ErrSameStorage is returned by Vault.Export and Vault.Import when the destination
	// or source Storage refers to the same underlying storage instance or filesystem file
	// (including hard links and equivalent relative/absolute paths) as the active Vault.
	ErrSameStorage = errors.New("passwordium: source and destination storage must not be the same")

	// ErrInvalidConflictPolicy is returned by Vault.Import when WithConflictPolicy is
	// configured with a ConflictPolicy value outside the defined enumeration constants.
	ErrInvalidConflictPolicy = errors.New("passwordium: invalid import conflict policy")
)
