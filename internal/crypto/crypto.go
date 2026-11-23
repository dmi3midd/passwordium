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
	// KeySize is the byte length of master keys, HKDF subkeys, and XChaCha20-Poly1305 keys.
	KeySize = chacha20poly1305.KeySize // 32 bytes

	// SaltSize is the byte length of the Argon2id salt stored in the header.
	SaltSize = 32

	// NonceSize is the byte length of an XChaCha20-Poly1305 nonce.
	NonceSize = chacha20poly1305.NonceSizeX // 24 bytes

	// Overhead is the Poly1305 authentication tag length appended to ciphertexts.
	Overhead = chacha20poly1305.Overhead // 16 bytes

	// DefaultArgonTime is the default Argon2id iteration count.
	DefaultArgonTime uint32 = 3

	// DefaultArgonMemoryKiB is the default Argon2id memory cost in KiB (64 MiB).
	DefaultArgonMemoryKiB uint32 = 64 * 1024

	// DefaultArgonThreads is the default Argon2id parallelism degree.
	DefaultArgonThreads uint32 = 2

	// MinArgonMemoryKiB is the low-level protocol minimum Argon2id memory cost in KiB.
	MinArgonMemoryKiB uint32 = 8

	// MinCreateArgonMemoryKiB is the safe minimum Argon2id memory cost (16 MiB) enforced on vault creation.
	MinCreateArgonMemoryKiB uint32 = 16 * 1024

	// DefaultMaxArgonTime is the default upper bound on Argon2id iterations accepted when opening a vault.
	DefaultMaxArgonTime uint32 = 16

	// DefaultMaxArgonMemoryKiB is the default upper bound on Argon2id memory cost (512 MiB) accepted when opening a vault.
	DefaultMaxArgonMemoryKiB uint32 = 512 * 1024

	// DefaultMaxArgonThreads is the default upper bound on Argon2id parallelism accepted when opening a vault.
	DefaultMaxArgonThreads uint32 = 16

	// DefaultMaxArgonWork is the default upper bound on Time*MemoryKiB (2 GiB-passes) accepted when opening a vault.
	DefaultMaxArgonWork uint64 = 2 * 1024 * 1024

	// HardMaxArgonTime is the absolute protocol cap on Argon2id iterations.
	HardMaxArgonTime uint32 = 100

	// HardMaxArgonMemoryKiB is the absolute protocol cap on Argon2id memory cost in KiB (4 GiB).
	HardMaxArgonMemoryKiB uint32 = 4 * 1024 * 1024

	// HardMaxArgonThreads is the maximum uint8 parallelism accepted by argon2.IDKey.
	HardMaxArgonThreads uint32 = 255
)

var (
	// ErrDecryptionFailed indicates AEAD authentication or decryption failure.
	ErrDecryptionFailed = errors.New("crypto: decryption failed")

	// ErrInvalidKeySize indicates a key whose byte length is not KeySize.
	ErrInvalidKeySize = errors.New("crypto: invalid key size")

	// ErrInvalidNonceSize indicates a nonce whose byte length is not NonceSize.
	ErrInvalidNonceSize = errors.New("crypto: invalid nonce size")

	// ErrInvalidArgon2Params indicates out-of-range Argon2id parameters.
	ErrInvalidArgon2Params = errors.New("crypto: invalid argon2 parameters")

	// ErrEmptyContextInfo indicates an empty HKDF context info string.
	ErrEmptyContextInfo = errors.New("crypto: empty hkdf context info")

	// ErrCipherClosed indicates an operation was attempted on a closed or nil Cipher.
	ErrCipherClosed = errors.New("crypto: cipher is closed")
)

// Argon2Params configures the Argon2id key derivation function.
type Argon2Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint32
}

// Argon2Limits defines upper bounds on Argon2id parameters read from untrusted headers.
type Argon2Limits struct {
	MaxTime      uint32
	MaxMemoryKiB uint32
	MaxThreads   uint32
	MaxWork      uint64 // Maximum allowed uint64(Time) * uint64(MemoryKiB); 0 disables the product check.
}

// DefaultArgon2Params returns the default RFC 9106-aligned Argon2id parameters.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:      DefaultArgonTime,
		MemoryKiB: DefaultArgonMemoryKiB,
		Threads:   DefaultArgonThreads,
	}
}

// DefaultArgon2Limits returns conservative default resource limits for opening untrusted vault headers.
func DefaultArgon2Limits() Argon2Limits {
	return Argon2Limits{
		MaxTime:      DefaultMaxArgonTime,
		MaxMemoryKiB: DefaultMaxArgonMemoryKiB,
		MaxThreads:   DefaultMaxArgonThreads,
		MaxWork:      DefaultMaxArgonWork,
	}
}

// Validate checks whether the Argon2id parameters are within hard protocol bounds.
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

// ValidateLimits verifies that p is within both hard protocol bounds and limits.
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

// ValidateForCreate verifies that p is valid, satisfies DefaultArgon2Limits (so a vault
// created with p can always be opened with default Open limits), and meets the minimum
// memory floor minMemoryKiB.
func (p Argon2Params) ValidateForCreate(minMemoryKiB uint32) error {
	if err := p.ValidateLimits(DefaultArgon2Limits()); err != nil {
		return err
	}
	if p.MemoryKiB < minMemoryKiB {
		return fmt.Errorf("%w: memory=%d KiB is below minimum %d KiB", ErrInvalidArgon2Params, p.MemoryKiB, minMemoryKiB)
	}
	return nil
}

// DeriveMasterKey validates params and derives a 32-byte master key from password and salt using Argon2id.
// Validation guarantees argon2.IDKey can never panic and Threads is never silently truncated to uint8.
func DeriveMasterKey(password, salt []byte, params Argon2Params) ([]byte, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	return argon2.IDKey(password, salt, params.Time, params.MemoryKiB, uint8(params.Threads), KeySize), nil // #nosec G115 -- params.Validate enforces Threads <= 255
}

// DeriveSubKey derives a domain-separated 32-byte subkey from masterKey using HKDF-SHA256.
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

// Cipher wraps an initialized XChaCha20-Poly1305 AEAD instance so the symmetric key
// is copied into the AEAD once per vault session rather than on every operation.
type Cipher struct {
	mu   sync.RWMutex
	aead cipher.AEAD
}

// NewCipher constructs a Cipher from a 32-byte key. The caller may zero key afterwards.
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

// Encrypt encrypts plaintext and authenticates associatedData with a freshly
// generated 24-byte random nonce.
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

// Decrypt authenticates associatedData and decrypts ciphertext.
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

// Close drops the reference to the underlying AEAD so subsequent operations fail
// with ErrCipherClosed. Go provides no API to wipe the AEAD's internal key copy;
// dropping the reference makes it unreachable for the garbage collector.
func (c *Cipher) Close() {
	if c != nil {
		c.mu.Lock()
		c.aead = nil
		c.mu.Unlock()
	}
}

// Encrypt encrypts plaintext and authenticates associatedData using XChaCha20-Poly1305
// with a freshly generated 24-byte random nonce.
func Encrypt(key, plaintext, associatedData []byte) (nonce, ciphertext []byte, err error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	return c.Encrypt(plaintext, associatedData)
}

// Decrypt authenticates associatedData and decrypts ciphertext using XChaCha20-Poly1305.
func Decrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Decrypt(nonce, ciphertext, associatedData)
}

// ZeroBytes overwrites the contents of b with zeros.
func ZeroBytes(b []byte) {
	clear(b)
}

// RandomBytes returns n cryptographically secure random bytes.
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
