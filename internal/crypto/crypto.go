// Package crypto implements the cryptographic primitives used by passwordium:
// Argon2id key derivation, HKDF-SHA256 subkey expansion, XChaCha20-Poly1305 AEAD,
// CSPRNG helpers, and memory zeroing.
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the required byte length (32 bytes / 256 bits) of Argon2id master keys,
	// HKDF-SHA256 subkeys, and XChaCha20-Poly1305 symmetric AEAD keys.
	KeySize = chacha20poly1305.KeySize // 32 bytes

	// SaltSize is the fixed byte length (32 bytes / 256 bits) of the random Argon2id salt
	// stored in the plaintext vault header.
	SaltSize = 32

	// NonceSize is the byte length (24 bytes / 192 bits) of an XChaCha20-Poly1305 random nonce.
	NonceSize = chacha20poly1305.NonceSizeX // 24 bytes

	// Overhead is the byte length (16 bytes / 128 bits) of the Poly1305 authentication tag
	// appended to XChaCha20-Poly1305 ciphertexts.
	Overhead = chacha20poly1305.Overhead // 16 bytes

	// DefaultArgonTime is the default Argon2id time cost (3 iterations) returned by DefaultArgon2Params.
	DefaultArgonTime uint32 = 3

	// DefaultArgonMemoryKiB is the default Argon2id memory cost in kibibytes (65,536 KiB / 64 MiB)
	// returned by DefaultArgon2Params.
	DefaultArgonMemoryKiB uint32 = 64 * 1024

	// DefaultArgonThreads is the default Argon2id parallelism degree (2 lanes) returned by DefaultArgon2Params.
	DefaultArgonThreads uint32 = 2

	// MinArgonMemoryKiB is the low-level protocol minimum Argon2id memory cost in kibibytes (8 KiB)
	// enforced by Argon2Params.Validate.
	MinArgonMemoryKiB uint32 = 8

	// MinCreateArgonMemoryKiB is the minimum Argon2id memory cost in kibibytes (16,384 KiB / 16 MiB)
	// enforced when creating or re-keying a vault to prevent weak KDF configurations and KiB/MiB unit confusion.
	MinCreateArgonMemoryKiB uint32 = 16 * 1024

	// DefaultMaxArgonTime is the default maximum Argon2id iteration count (16) accepted from
	// an untrusted header when opening or importing a vault.
	DefaultMaxArgonTime uint32 = 16

	// DefaultMaxArgonMemoryKiB is the default maximum Argon2id memory cost in kibibytes
	// (524,288 KiB / 512 MiB) accepted from an untrusted header when opening or importing a vault.
	DefaultMaxArgonMemoryKiB uint32 = 512 * 1024

	// DefaultMaxArgonThreads is the default maximum Argon2id parallelism degree (16 lanes)
	// accepted from an untrusted header when opening or importing a vault.
	DefaultMaxArgonThreads uint32 = 16

	// DefaultMaxArgonWork is the default maximum combined Argon2id work factor
	// uint64(Time) * uint64(MemoryKiB) (2,097,152 KiB-passes, equivalent to 2 GiB-passes)
	// accepted from an untrusted header before key derivation runs.
	DefaultMaxArgonWork uint64 = 2 * 1024 * 1024

	// HardMaxArgonTime is the absolute protocol upper bound on Argon2id iterations (100)
	// enforced by Argon2Params.Validate.
	HardMaxArgonTime uint32 = 100

	// HardMaxArgonMemoryKiB is the absolute protocol upper bound on Argon2id memory cost
	// in kibibytes (4,194,304 KiB / 4 GiB) enforced by Argon2Params.Validate.
	HardMaxArgonMemoryKiB uint32 = 4 * 1024 * 1024

	// HardMaxArgonThreads is the absolute protocol upper bound on Argon2id parallelism (255 lanes),
	// matching the maximum uint8 value accepted by golang.org/x/crypto/argon2.IDKey.
	HardMaxArgonThreads uint32 = 255
)

var (
	// ErrDecryptionFailed is returned by Cipher.Decrypt and Decrypt when the ciphertext is
	// shorter than Overhead (16 bytes) or when XChaCha20-Poly1305 authentication tag verification
	// fails due to an incorrect key, modified nonce, corrupted ciphertext, or mismatched AAD.
	ErrDecryptionFailed = errors.New("crypto: decryption failed")

	// ErrInvalidKeySize is returned by DeriveSubKey, NewCipher, Encrypt, and Decrypt when
	// the provided symmetric key slice does not have length KeySize (32 bytes).
	ErrInvalidKeySize = errors.New("crypto: invalid key size")

	// ErrInvalidNonceSize is returned by Cipher.Decrypt and Decrypt when the provided nonce
	// slice does not have length NonceSize (24 bytes).
	ErrInvalidNonceSize = errors.New("crypto: invalid nonce size")

	// ErrInvalidArgon2Params is returned by Argon2Params.Validate, Argon2Params.ValidateLimits,
	// Argon2Params.ValidateForCreate, and DeriveMasterKey when any Argon2id parameter is outside
	// its allowed bounds.
	ErrInvalidArgon2Params = errors.New("crypto: invalid argon2 parameters")

	// ErrEmptyContextInfo is returned by DeriveSubKey when the HKDF contextInfo string is empty.
	ErrEmptyContextInfo = errors.New("crypto: empty hkdf context info")

	// ErrCipherClosed is returned by Cipher.Encrypt and Cipher.Decrypt when called on a nil
	// Cipher pointer or after Cipher.Close has released the underlying AEAD instance.
	ErrCipherClosed = errors.New("crypto: cipher is closed")
)

// Argon2Params configures the time, memory, and parallelism costs for Argon2id key derivation.
type Argon2Params struct {
	// Time is the number of passes (iterations) over memory. Must be in [1, HardMaxArgonTime].
	Time uint32
	// MemoryKiB is the memory cost in kibibytes (KiB). Must be in [MinArgonMemoryKiB, HardMaxArgonMemoryKiB].
	MemoryKiB uint32
	// Threads is the degree of parallelism (lanes). Must be in [1, HardMaxArgonThreads].
	Threads uint32
}

// Argon2Limits defines the upper resource bounds enforced on Argon2Params parsed from
// an untrusted vault header prior to executing Argon2id key derivation.
type Argon2Limits struct {
	// MaxTime is the maximum allowed iteration count.
	MaxTime uint32
	// MaxMemoryKiB is the maximum allowed memory cost in kibibytes (KiB).
	MaxMemoryKiB uint32
	// MaxThreads is the maximum allowed parallelism degree (lanes).
	MaxThreads uint32
	// MaxWork is the maximum allowed product uint64(Time) * uint64(MemoryKiB) in KiB-passes;
	// a value of 0 disables the combined work-product check while keeping per-field caps active.
	MaxWork uint64 // Maximum allowed uint64(Time) * uint64(MemoryKiB); 0 disables the product check.
}

// DefaultArgon2Params returns the default RFC 9106-aligned Argon2id parameters:
// Time=DefaultArgonTime (3), MemoryKiB=DefaultArgonMemoryKiB (64 MiB), and
// Threads=DefaultArgonThreads (2).
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:      DefaultArgonTime,
		MemoryKiB: DefaultArgonMemoryKiB,
		Threads:   DefaultArgonThreads,
	}
}

// DefaultArgon2Limits returns the default pre-KDF resource limits enforced when opening
// or importing untrusted vault headers: MaxTime=16, MaxMemoryKiB=512 MiB, MaxThreads=16,
// and MaxWork=2 GiB-passes.
func DefaultArgon2Limits() Argon2Limits {
	return Argon2Limits{
		MaxTime:      DefaultMaxArgonTime,
		MaxMemoryKiB: DefaultMaxArgonMemoryKiB,
		MaxThreads:   DefaultMaxArgonThreads,
		MaxWork:      DefaultMaxArgonWork,
	}
}

// Validate checks whether p satisfies the hard protocol bounds: Time in [1, HardMaxArgonTime],
// MemoryKiB in [MinArgonMemoryKiB, HardMaxArgonMemoryKiB], and Threads in [1, HardMaxArgonThreads].
//
// Validate returns ErrInvalidArgon2Params (wrapped with a descriptive message) if any field
// is out of range. Passing Validate guarantees that argon2.IDKey will not panic and that
// converting Threads to uint8 will not truncate high bits.
func (p Argon2Params) Validate() error {
	if p.Time < 1 || p.Time > HardMaxArgonTime {
		return fmt.Errorf("%w: time=%d must be in [1, %d]", ErrInvalidArgon2Params, p.Time, HardMaxArgonTime)
	}
	if p.MemoryKiB < MinArgonMemoryKiB || p.MemoryKiB > HardMaxArgonMemoryKiB {
		return fmt.Errorf("%w: memory=%d KiB must be in [%d, %d]", ErrInvalidArgon2Params, p.MemoryKiB, MinArgonMemoryKiB, HardMaxArgonMemoryKiB)
	}
	if p.Threads < 1 || p.Threads > HardMaxArgonThreads {
		return fmt.Errorf("%w: threads=%d must be in [1, %d]", ErrInvalidArgon2Params, p.Threads, HardMaxArgonThreads)
	}
	return nil
}

// ValidateLimits verifies that p satisfies both hard protocol bounds (via Argon2Params.Validate)
// and the caller-supplied resource caps in limits (MaxTime, MaxMemoryKiB, MaxThreads, and,
// when limits.MaxWork > 0, uint64(p.Time)*uint64(p.MemoryKiB) <= limits.MaxWork).
//
// It returns an error wrapping ErrInvalidArgon2Params if any bound is violated.
func (p Argon2Params) ValidateLimits(limits Argon2Limits) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Time > limits.MaxTime {
		return fmt.Errorf("%w: time=%d exceeds max %d", ErrInvalidArgon2Params, p.Time, limits.MaxTime)
	}
	if p.MemoryKiB > limits.MaxMemoryKiB {
		return fmt.Errorf("%w: memory=%d KiB exceeds max %d KiB", ErrInvalidArgon2Params, p.MemoryKiB, limits.MaxMemoryKiB)
	}
	if p.Threads > limits.MaxThreads {
		return fmt.Errorf("%w: threads=%d exceeds max %d", ErrInvalidArgon2Params, p.Threads, limits.MaxThreads)
	}
	if limits.MaxWork > 0 {
		work := uint64(p.Time) * uint64(p.MemoryKiB)
		if work > limits.MaxWork {
			return fmt.Errorf("%w: work factor time*memory=%d exceeds max %d", ErrInvalidArgon2Params, work, limits.MaxWork)
		}
	}
	return nil
}

// ValidateForCreate verifies that p is valid, satisfies DefaultArgon2Limits (ensuring any
// vault created with p can be opened under default Open resource limits), and has
// p.MemoryKiB >= minMemoryKiB (typically MinCreateArgonMemoryKiB, 16 MiB).
//
// It returns an error wrapping ErrInvalidArgon2Params if any condition is not met.
func (p Argon2Params) ValidateForCreate(minMemoryKiB uint32) error {
	if err := p.ValidateLimits(DefaultArgon2Limits()); err != nil {
		return err
	}
	if p.MemoryKiB < minMemoryKiB {
		return fmt.Errorf("%w: memory=%d KiB is below minimum %d KiB", ErrInvalidArgon2Params, p.MemoryKiB, minMemoryKiB)
	}
	return nil
}

// DeriveMasterKey validates params via Argon2Params.Validate and derives a 32-byte
// (KeySize) master key from password and salt using Argon2id.
//
// DeriveMasterKey does not mutate password or salt. Callers are responsible for zeroing
// the returned key slice with ZeroBytes once subkeys have been derived. It returns an
// error wrapping ErrInvalidArgon2Params if params are outside hard protocol bounds.
func DeriveMasterKey(password, salt []byte, params Argon2Params) ([]byte, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	return argon2.IDKey(password, salt, params.Time, params.MemoryKiB, uint8(params.Threads), KeySize), nil // #nosec G115 -- params.Validate enforces Threads <= 255
}

// DeriveSubKey derives a domain-separated 32-byte (KeySize) subkey from masterKey
// using HKDF-SHA256 with nil HKDF salt and contextInfo as the HKDF info string.
//
// DeriveSubKey does not mutate masterKey. Callers should wipe the returned subkey with
// ZeroBytes immediately after initializing a Cipher. DeriveSubKey returns ErrInvalidKeySize
// if len(masterKey) != KeySize, or ErrEmptyContextInfo if contextInfo is empty.
func DeriveSubKey(masterKey []byte, contextInfo string) ([]byte, error) {
	if len(masterKey) != KeySize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidKeySize, len(masterKey), KeySize)
	}
	if contextInfo == "" {
		return nil, ErrEmptyContextInfo
	}

	kdf := hkdf.New(sha256.New, masterKey, nil, []byte(contextInfo))
	subKey := make([]byte, KeySize)
	if _, err := io.ReadFull(kdf, subKey); err != nil {
		ZeroBytes(subKey)
		return nil, fmt.Errorf("crypto: hkdf expand: %w", err)
	}
	return subKey, nil
}

// Cipher wraps an initialized XChaCha20-Poly1305 cipher.AEAD instance with a read-write
// mutex so a symmetric subkey is expanded into the AEAD state once per vault session and
// can be safely closed across concurrent goroutines.
type Cipher struct {
	mu   sync.RWMutex
	aead cipher.AEAD
}

// NewCipher constructs a thread-safe XChaCha20-Poly1305 Cipher from a 32-byte (KeySize) key.
//
// Because chacha20poly1305.NewX copies the key into its internal state during construction,
// the caller may zero the input key slice immediately after NewCipher returns. NewCipher
// returns ErrInvalidKeySize if len(key) != KeySize.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidKeySize, len(key), KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aead: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt encrypts plaintext and authenticates associatedData using the Cipher's
// XChaCha20-Poly1305 AEAD instance with a freshly generated 24-byte (NonceSize) random
// nonce from crypto/rand, returning the generated nonce and the resulting ciphertext
// (which includes the 16-byte Poly1305 authentication tag).
//
// Encrypt is safe for concurrent use. It returns ErrCipherClosed if c is nil or has been
// closed via Cipher.Close, or an error if the CSPRNG fails to generate a nonce.
func (c *Cipher) Encrypt(plaintext, associatedData []byte) (nonce, ciphertext []byte, err error) {
	if c == nil {
		return nil, nil, ErrCipherClosed
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.aead == nil {
		return nil, nil, ErrCipherClosed
	}

	nonce, err = RandomBytes(NonceSize)
	if err != nil {
		return nil, nil, err
	}

	ciphertext = c.aead.Seal(nil, nonce, plaintext, associatedData) // #nosec G407 -- nonce is freshly generated via crypto/rand in RandomBytes
	return nonce, ciphertext, nil
}

// Decrypt verifies the Poly1305 authentication tag over ciphertext and associatedData
// using the 24-byte nonce and decrypts the payload using the Cipher's XChaCha20-Poly1305
// AEAD instance.
//
// Decrypt is safe for concurrent use. It returns ErrCipherClosed if c is nil or has been
// closed, ErrInvalidNonceSize if len(nonce) != NonceSize (24 bytes), or ErrDecryptionFailed
// if len(ciphertext) < Overhead (16 bytes) or AEAD authentication fails.
func (c *Cipher) Decrypt(nonce, ciphertext, associatedData []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrCipherClosed
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.aead == nil {
		return nil, ErrCipherClosed
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidNonceSize, len(nonce), NonceSize)
	}
	if len(ciphertext) < Overhead {
		return nil, ErrDecryptionFailed
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// Close releases the Cipher's reference to the underlying cipher.AEAD instance so that
// any subsequent Encrypt or Decrypt calls fail with ErrCipherClosed.
//
// Because Go's standard cipher.AEAD interface provides no method to zero its internal
// key copy, dropping the reference makes the AEAD state unreachable and eligible for
// garbage collection. Close is safe for concurrent use, idempotent, and a no-op on a nil receiver.
func (c *Cipher) Close() {
	if c != nil {
		c.mu.Lock()
		c.aead = nil
		c.mu.Unlock()
	}
}

// Encrypt is a one-shot helper that initializes a temporary XChaCha20-Poly1305 Cipher
// from the 32-byte key, encrypts plaintext with associatedData and a freshly generated
// 24-byte random nonce, and closes the temporary Cipher before returning.
//
// It returns ErrInvalidKeySize if len(key) != KeySize (32 bytes), or an error if random
// nonce generation fails.
func Encrypt(key, plaintext, associatedData []byte) (nonce, ciphertext []byte, err error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	return c.Encrypt(plaintext, associatedData)
}

// Decrypt is a one-shot helper that initializes a temporary XChaCha20-Poly1305 Cipher
// from the 32-byte key, verifies and decrypts ciphertext with the 24-byte nonce and
// associatedData, and closes the temporary Cipher before returning.
//
// It returns ErrInvalidKeySize if len(key) != KeySize (32 bytes), ErrInvalidNonceSize if
// len(nonce) != NonceSize (24 bytes), or ErrDecryptionFailed if ciphertext is shorter than
// Overhead (16 bytes) or fails AEAD authentication.
func Decrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Decrypt(nonce, ciphertext, associatedData)
}

// ZeroBytes overwrites every element of b with zero bytes using Go's built-in clear.
// Passing a nil or empty slice is a safe no-op.
func ZeroBytes(b []byte) {
	clear(b)
}

// RandomBytes allocates and returns a new byte slice of length n filled with
// cryptographically secure random bytes read from crypto/rand.Reader.
//
// If n < 0, RandomBytes returns an error. If reading from crypto/rand.Reader fails,
// any partially filled buffer is zeroed with ZeroBytes before returning the wrapped error.
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("crypto: negative random byte count %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		ZeroBytes(b)
		return nil, fmt.Errorf("crypto: read random bytes: %w", err)
	}
	return b, nil
}
