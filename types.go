package passwordium

import (
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/dmi3midd/passwordium/internal/crypto"
)

// Argon2Params configures the Argon2id key derivation function for a vault.
//
// Parameters are stored in big-endian form in the 50-byte plaintext vault header
// and authenticated as associated data (AAD) of the outer XChaCha20-Poly1305 envelope.
//
// When used with Create or Vault.Export (via WithArgon2Params), parameters must satisfy:
//   - Time in [1, 16]
//   - MemoryKiB in [16384, 524288] (16 MiB to 512 MiB)
//   - Threads in [1, 16]
//   - uint64(Time) * uint64(MemoryKiB) <= 2097152 (2 GiB-passes)
//
// When used with Open or Vault.Import (via WithMaxArgon2Params), parameters define the
// maximum untrusted header costs that will be accepted before key derivation runs, up to
// the hard protocol limits (Time <= 100, MemoryKiB <= 4 GiB, Threads <= 255).
type Argon2Params struct {
	// Time is the number of Argon2id passes (iterations) over memory. Must be >= 1.
	Time uint32
	// MemoryKiB is the Argon2id memory cost in kibibytes (KiB), e.g., 64 * 1024 for 64 MiB.
	// Prefer Argon2ParamsMiB to construct parameters from mebibytes and avoid KiB/MiB unit confusion.
	MemoryKiB uint32 // Memory cost in KiB (for example, 64 * 1024 for 64 MiB). See Argon2ParamsMiB.
	// Threads is the degree of parallelism (lanes) used by Argon2id. Must be in [1, 255].
	Threads uint32
}

// DefaultArgon2Params returns the recommended RFC 9106-aligned default Argon2id parameters
// used by Create when WithArgon2Params is not provided: Time=3 iterations, MemoryKiB=65536
// (64 MiB), and Threads=2 lanes.
func DefaultArgon2Params() Argon2Params {
	p := crypto.DefaultArgon2Params()
	return Argon2Params{
		Time:      p.Time,
		MemoryKiB: p.MemoryKiB,
		Threads:   p.Threads,
	}
}

// DefaultMaxArgon2Params returns the default upper bounds that Open and Vault.Import
// enforce on Argon2id parameters parsed from an untrusted vault header: Time=16,
// MemoryKiB=524288 (512 MiB), and Threads=16.
//
// In addition to these per-parameter bounds, Open and Vault.Import reject headers whose
// combined work product uint64(Time) * uint64(MemoryKiB) exceeds 2 GiB-passes (2,097,152 KiB-passes)
// unless overridden via WithMaxArgon2Params or WithMaxArgon2Work.
func DefaultMaxArgon2Params() Argon2Params {
	return Argon2Params{
		Time:      crypto.DefaultMaxArgonTime,
		MemoryKiB: crypto.DefaultMaxArgonMemoryKiB,
		Threads:   crypto.DefaultMaxArgonThreads,
	}
}

// Argon2ParamsMiB constructs an Argon2Params value from an iteration count time, a memory
// cost memoryMiB expressed in mebibytes (1 MiB = 1024 KiB), and a parallelism degree threads.
//
// Using Argon2ParamsMiB prevents accidental unit confusion where a caller passes 64 intending
// 64 MiB but actually specifies 64 KiB. If memoryMiB * 1024 would overflow uint32
// (memoryMiB > math.MaxUint32 / 1024), MemoryKiB saturates to math.MaxUint32 and will be
// rejected with ErrInvalidArgon2Params during parameter validation.
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
//
// While a Vault is open, EntryMeta fields are kept indexed in memory so Vault.Search
// and Vault.GetMeta can inspect entries without decrypting any Secret payloads. When
// persisted to Storage, all EntryMeta records are encrypted inside the outer VaultData
// container under indexKey.
//
// All string fields (ID, Title, Username, URL, and elements of Tags) must be valid UTF-8.
// Returned EntryMeta values always contain a defensive copy of Tags, so mutating a
// returned EntryMeta never affects the Vault's internal state.
type EntryMeta struct {
	// ID uniquely identifies the entry within the vault. When passed to Vault.Put,
	// an empty ID causes Put to generate a random RFC 4122 UUIDv4 string automatically;
	// a non-empty ID creates or updates the entry with that exact identifier.
	ID string
	// Version is the monotonically increasing modification counter of the entry,
	// starting at 1 on creation and incrementing by 1 on each update or overwrite import.
	// Version is bound into the entry secret's AEAD associated data ("<ID>:<Version>")
	// to prevent in-memory or persisted secret rollback. Ignored as input to Vault.Put.
	Version uint64
	// Title is a human-readable display name for the entry (e.g., "GitHub"), matched
	// case-insensitively by Vault.Search and used as the primary sort key in search results.
	Title string
	// Username is the account login, handle, or email associated with the entry,
	// matched case-insensitively as a substring by Vault.Search.
	Username string
	// URL is the service URI or domain associated with the entry, matched
	// case-insensitively as a substring by Vault.Search.
	URL string
	// Tags is an optional list of labels attached to the entry. Vault.Search matches
	// required tags case-insensitively using exact tag equality.
	Tags []string
	// CreatedAt is the UTC timestamp (at 1-second Unix resolution) when the entry was
	// originally created. Preserved across updates; ignored as input to Vault.Put.
	CreatedAt time.Time
	// UpdatedAt is the UTC timestamp (at 1-second Unix resolution) when the entry was
	// last created or modified. Used by ConflictKeepNewer during Vault.Import; ignored
	// as input to Vault.Put.
	UpdatedAt time.Time
}

// Secret holds the sensitive credential payload of a vault entry.
//
// Unlike EntryMeta, a Secret remains individually encrypted in memory under secretKey
// (padded with ISO/IEC 7816-4 to 256-byte blocks and bound to "<entry_id>:<entry_version>"
// as associated data) and is decrypted on demand only when Vault.GetSecret is called.
//
// Because Go strings are immutable, decrypted Password, Notes, and CustomFields values
// remain in garbage-collected heap memory after Vault.GetSecret or Vault.Put returns.
// All string values and map keys/values must be valid UTF-8.
//
// Secret implements fmt.Stringer, fmt.GoStringer, and slog.LogValuer to redact its
// contents automatically and prevent accidental credential leakage into logs or error traces.
type Secret struct {
	// Password is the primary secret credential, passphrase, or token for the entry.
	Password string
	// Notes holds free-form sensitive text such as recovery codes, security questions, or instructions.
	Notes string
	// CustomFields stores arbitrary key-value secret attributes (for example, TOTP seeds,
	// API keys, or PINs). Vault.Put does not retain or mutate the caller's map, and
	// Vault.GetSecret returns a freshly allocated map owned by the caller.
	CustomFields map[string]string
}

const redactedSecretString = "passwordium.Secret{REDACTED}"

// String implements fmt.Stringer and returns the constant placeholder
// "passwordium.Secret{REDACTED}" so formatting a Secret value or pointer with
// fmt (%s, %v, %+v) never exposes Password, Notes, or CustomFields.
func (Secret) String() string {
	return redactedSecretString
}

// GoString implements fmt.GoStringer and returns the constant placeholder
// "passwordium.Secret{REDACTED}" so formatting a Secret value or pointer with
// fmt (%#v) never exposes credentials in debug output.
func (Secret) GoString() string {
	return redactedSecretString
}

// LogValue implements slog.LogValuer and returns a redacted slog.Value ("[REDACTED]")
// so structured logging via log/slog never serializes secret fields.
func (Secret) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

// SearchQuery specifies filter criteria for Vault.Search over in-memory EntryMeta records.
//
// An empty SearchQuery (zero value) matches all entries in the vault. When both Query
// and Tags are non-empty, an entry must satisfy both filters (logical AND).
type SearchQuery struct {
	// Query filters entries whose Title, Username, or URL contains Query as a
	// case-insensitive substring. An empty string matches any Title, Username, and URL.
	Query string
	// Tags requires matching entries to possess every tag listed in Tags, compared
	// case-insensitively for full-string equality (logical AND across all specified tags).
	Tags []string
}

// ConflictPolicy controls how Vault.Import resolves entries from the source vault
// whose EntryMeta.ID already exists in the destination Vault.
type ConflictPolicy int

const (
	// ConflictKeepNewer (the default policy) replaces an existing destination entry
	// only when the imported entry has a strictly greater UpdatedAt Unix timestamp
	// (in seconds), and skips the imported entry otherwise. When an entry is replaced,
	// its original CreatedAt timestamp is preserved and its Version is set to
	// max(existing.Version, imported.Version) + 1.
	//
	// Note that UpdatedAt timestamps have 1-second granularity and originate from the
	// source vault's authenticated metadata; when importing from a clock-skewed or
	// untrusted source vault, consider ConflictKeepExisting or ConflictKeepBoth.
	ConflictKeepNewer ConflictPolicy = iota

	// ConflictKeepExisting always preserves the existing entry in the destination Vault
	// and skips any imported entry with a colliding ID (incrementing ImportResult.Skipped).
	ConflictKeepExisting

	// ConflictOverwrite always replaces the existing entry in the destination Vault with
	// the imported entry's metadata and secret (incrementing ImportResult.Updated).
	// The existing entry's CreatedAt timestamp is preserved, UpdatedAt is set to
	// max(existing.UpdatedAt, imported.UpdatedAt) so timestamps never regress, and
	// Version is set to max(existing.Version, imported.Version) + 1.
	ConflictOverwrite

	// ConflictKeepBoth preserves the existing entry in the destination Vault untouched
	// and imports the colliding source entry as a brand-new entry under a freshly
	// generated RFC 4122 UUIDv4 ID with Version reset to 1 (incrementing ImportResult.Added).
	ConflictKeepBoth
)

func (p ConflictPolicy) valid() bool {
	switch p {
	case ConflictKeepNewer, ConflictKeepExisting, ConflictOverwrite, ConflictKeepBoth:
		return true
	default:
		return false
	}
}

// ImportResult summarizes the entry counts produced by a completed Vault.Import call.
//
// For any successful Import call, Added + Updated + Skipped equals the total number
// of entries present in the source vault.
type ImportResult struct {
	// Added is the number of entries inserted under a new ID in the destination vault
	// (including colliding entries re-assigned a new UUIDv4 under ConflictKeepBoth).
	Added int
	// Updated is the number of existing entries in the destination vault that were
	// replaced in place under ConflictKeepNewer or ConflictOverwrite.
	Updated int
	// Skipped is the number of colliding entries from the source vault that were left
	// unimported under ConflictKeepExisting or ConflictKeepNewer.
	Skipped int
}
