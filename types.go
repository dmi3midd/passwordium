package passwordium

import (
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/dmi3midd/passwordium/internal/crypto"
)

// Argon2Params configures the Argon2id key derivation function for a vault.
type Argon2Params struct {
	Time      uint32
	MemoryKiB uint32 // Memory cost in KiB (for example, 64 * 1024 for 64 MiB). See Argon2ParamsMiB.
	Threads   uint32
}

// DefaultArgon2Params returns the recommended default Argon2id parameters
// (Time=3, Memory=64 MiB, Threads=2).
func DefaultArgon2Params() Argon2Params {
	p := crypto.DefaultArgon2Params()
	return Argon2Params{
		Time:      p.Time,
		MemoryKiB: p.MemoryKiB,
		Threads:   p.Threads,
	}
}

// DefaultMaxArgon2Params returns the default upper bounds Open applies to Argon2id
// parameters read from an untrusted header (Time=16, Memory=512 MiB, Threads=16).
// Additionally, Open rejects headers whose Time*MemoryKiB exceeds 2 GiB-passes by default.
func DefaultMaxArgon2Params() Argon2Params {
	return Argon2Params{
		Time:      crypto.DefaultMaxArgonTime,
		MemoryKiB: crypto.DefaultMaxArgonMemoryKiB,
		Threads:   crypto.DefaultMaxArgonThreads,
	}
}

// Argon2ParamsMiB constructs Argon2Params from a memory cost expressed in MiB,
// avoiding KiB/MiB unit confusion. Values that would overflow saturate to
// math.MaxUint32 KiB and are subsequently rejected by validation.
func Argon2ParamsMiB(time, memoryMiB, threads uint32) Argon2Params {
	memoryKiB := uint32(math.MaxUint32)
	if memoryMiB <= math.MaxUint32/1024 {
		memoryKiB = memoryMiB * 1024
	}
	return Argon2Params{
		Time:      time,
		MemoryKiB: memoryKiB,
		Threads:   threads,
	}
}

func (p Argon2Params) toCrypto() crypto.Argon2Params {
	return crypto.Argon2Params{
		Time:      p.Time,
		MemoryKiB: p.MemoryKiB,
		Threads:   p.Threads,
	}
}

// validateForCreate enforces the 16 MiB memory floor unless allowWeak is set by internal test hooks.
func (p Argon2Params) validateForCreate(allowWeak bool) error {
	minMem := crypto.MinCreateArgonMemoryKiB
	if allowWeak {
		minMem = crypto.MinArgonMemoryKiB
	}
	if err := p.toCrypto().ValidateForCreate(minMem); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgon2Params, err)
	}
	return nil
}

func (p Argon2Params) validateLimits(limits crypto.Argon2Limits) error {
	if err := p.toCrypto().ValidateLimits(limits); err != nil {
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
//
// Because Go strings are immutable, decrypted Password, Notes, and CustomFields values
// remain in garbage-collected heap memory after GetSecret or Put returns.
// String, GoString, and LogValue redact the payload to prevent accidental leakage into logs.
type Secret struct {
	Password     string
	Notes        string
	CustomFields map[string]string
}

const redactedSecretString = "passwordium.Secret{REDACTED}"

// String returns a redacted placeholder so formatting a Secret with fmt (%s, %v, %+v)
// never leaks credentials.
func (Secret) String() string {
	return redactedSecretString
}

// GoString returns a redacted placeholder so formatting a Secret with fmt (%#v)
// never leaks credentials.
func (Secret) GoString() string {
	return redactedSecretString
}

// LogValue implements slog.LogValuer so structured loggers redact Secret values automatically.
func (Secret) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

// SearchQuery filters vault entries in memory.
// Query matches Title, Username, or URL case-insensitively (substring match).
// Tags requires the entry to contain all specified tags (case-insensitive exact tag match).
type SearchQuery struct {
	Query string
	Tags  []string
}
