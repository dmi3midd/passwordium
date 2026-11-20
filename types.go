package passwordium

import (
	"fmt"
	"time"

	"github.com/dmi3midd/passwordium/internal/crypto"
)

// Argon2Params configures the Argon2id key derivation function for a vault.
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // Memory cost in KiB (for example, 64 * 1024 for 64 MiB).
	Threads uint32
}

// DefaultArgon2Params returns the recommended default Argon2id parameters
// (Time=3, Memory=64 MiB, Threads=2).
func DefaultArgon2Params() Argon2Params {
	p := crypto.DefaultArgon2Params()
	return Argon2Params{
		Time:    p.Time,
		Memory:  p.Memory,
		Threads: p.Threads,
	}
}

func (p Argon2Params) toCrypto() crypto.Argon2Params {
	return crypto.Argon2Params{
		Time:    p.Time,
		Memory:  p.Memory,
		Threads: p.Threads,
	}
}

// validate verifies that Argon2Params are within safe cryptographic and resource bounds.
func (p Argon2Params) validate() error {
	if err := p.toCrypto().Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgon2Params, err)
	}
	return nil
}

// EntryMeta holds the searchable, non-secret metadata of a vault entry.
// It stays indexed in memory while the vault is open.
type EntryMeta struct {
	ID        string
	Version   uint64
	Title     string
	Username  string
	URL       string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Secret holds the sensitive payload of a vault entry.
// It remains encrypted at rest in memory and is decrypted only when GetSecret is called.
type Secret struct {
	Password     string
	Notes        string
	CustomFields map[string]string
}

// SearchQuery filters vault entries in memory.
// Query matches Title, Username, or URL case-insensitively (substring match).
// Tags requires the entry to contain all specified tags (case-insensitive exact tag match).
type SearchQuery struct {
	Query string
	Tags  []string
}
