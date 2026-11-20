// Package crypto implements the cryptographic primitives used by passwordium:
// Argon2id key derivation, HKDF-SHA256 subkey expansion, XChaCha20-Poly1305 AEAD,
// CSPRNG helpers, and memory zeroing.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

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

	// DefaultArgonMemory is the default Argon2id memory cost in KiB (64 MiB).
	DefaultArgonMemory uint32 = 64 * 1024

	// DefaultArgonThreads is the default Argon2id parallelism degree.
	DefaultArgonThreads uint32 = 2

	// MinArgonMemory is the minimum Argon2id memory cost in KiB.
	MinArgonMemory uint32 = 8

	// MaxArgonTime is the upper bound on Argon2id iterations to prevent DoS on untrusted headers.
	MaxArgonTime uint32 = 100

	// MaxArgonMemory is the upper bound on Argon2id memory cost in KiB (4 GiB).
	MaxArgonMemory uint32 = 4 * 1024 * 1024

	// MaxArgonThreads is the maximum uint8 parallelism accepted by argon2.IDKey.
	MaxArgonThreads uint32 = 255
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
)

// Argon2Params configures the Argon2id key derivation function.
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint32
}

// DefaultArgon2Params returns the default RFC 9106-aligned Argon2id parameters.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:    DefaultArgonTime,
		Memory:  DefaultArgonMemory,
		Threads: DefaultArgonThreads,
	}
}

// Validate checks whether the Argon2id parameters are within safe bounds.
func (p Argon2Params) Validate() error {
	if p.Time < 1 || p.Time > MaxArgonTime {
		return fmt.Errorf("%w: time=%d must be in [1, %d]", ErrInvalidArgon2Params, p.Time, MaxArgonTime)
	}
	if p.Memory < MinArgonMemory || p.Memory > MaxArgonMemory {
		return fmt.Errorf("%w: memory=%d KiB must be in [%d, %d]", ErrInvalidArgon2Params, p.Memory, MinArgonMemory, MaxArgonMemory)
	}
	if p.Threads < 1 || p.Threads > MaxArgonThreads {
		return fmt.Errorf("%w: threads=%d must be in [1, %d]", ErrInvalidArgon2Params, p.Threads, MaxArgonThreads)
	}
	return nil
}

// DeriveMasterKey derives a 32-byte master key from password and salt using Argon2id.
// Callers must validate params before calling DeriveMasterKey.
func DeriveMasterKey(password, salt []byte, params Argon2Params) []byte {
	return argon2.IDKey(password, salt, params.Time, params.Memory, uint8(params.Threads), KeySize)
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

// Encrypt encrypts plaintext and authenticates associatedData using XChaCha20-Poly1305
// with a freshly generated 24-byte random nonce.
func Encrypt(key, plaintext, associatedData []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidKeySize, len(key), KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: init aead: %w", err)
	}

	nonce, err = RandomBytes(NonceSize)
	if err != nil {
		return nil, nil, err
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, associatedData)
	return nonce, ciphertext, nil
}

// Decrypt authenticates associatedData and decrypts ciphertext using XChaCha20-Poly1305.
func Decrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidKeySize, len(key), KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidNonceSize, len(nonce), NonceSize)
	}
	if len(ciphertext) < Overhead {
		return nil, ErrDecryptionFailed
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aead: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
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
