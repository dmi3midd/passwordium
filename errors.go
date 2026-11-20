package passwordium

import "errors"

var (
	// ErrNotFound is returned by Storage.Load when the vault does not exist yet.
	ErrNotFound = errors.New("passwordium: vault not found")

	// ErrAlreadyExists is returned by Create when a vault already exists in Storage and WithOverwrite is not enabled.
	ErrAlreadyExists = errors.New("passwordium: vault already exists")

	// ErrEntryNotFound is returned when an entry ID does not exist in the vault.
	ErrEntryNotFound = errors.New("passwordium: entry not found")

	// ErrVaultClosed is returned when an operation is attempted on a closed Vault.
	ErrVaultClosed = errors.New("passwordium: vault is closed")

	// ErrInvalidPassword is returned when the supplied master password fails to authenticate the vault.
	ErrInvalidPassword = errors.New("passwordium: invalid master password")

	// ErrEmptyPassword is returned when Create is called with an empty master password.
	ErrEmptyPassword = errors.New("passwordium: master password must not be empty")

	// ErrNilStorage is returned when a nil Storage backend is provided.
	ErrNilStorage = errors.New("passwordium: storage must not be nil")

	// ErrInvalidHeader is returned when the binary vault header is missing, truncated, or has invalid magic.
	ErrInvalidHeader = errors.New("passwordium: invalid vault header")

	// ErrUnsupportedVersion is returned when the vault header specifies an unsupported format version.
	ErrUnsupportedVersion = errors.New("passwordium: unsupported vault version")

	// ErrInvalidArgon2Params is returned when Argon2id parameters are outside supported or configured bounds.
	ErrInvalidArgon2Params = errors.New("passwordium: invalid argon2 parameters")

	// ErrCorruptedVault is returned when the vault envelope or serialized VaultData is malformed.
	ErrCorruptedVault = errors.New("passwordium: corrupted vault data")

	// ErrSecretCorrupted is returned when an entry's SecretPayload fails AEAD verification or decoding.
	ErrSecretCorrupted = errors.New("passwordium: entry secret is corrupted")

	// ErrVaultTooLarge is returned when a vault file exceeds the configured maximum size.
	ErrVaultTooLarge = errors.New("passwordium: vault exceeds maximum allowed size")

	// ErrInvalidStorageFile is returned when FileStorage points to a non-regular file (symlink, FIFO, device, or directory).
	ErrInvalidStorageFile = errors.New("passwordium: storage path is not a regular file")

	// ErrConcurrentModification is returned by Save when the underlying vault in Storage was modified since it was opened or last saved.
	ErrConcurrentModification = errors.New("passwordium: vault was modified concurrently in storage")
)
