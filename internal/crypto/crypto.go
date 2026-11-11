package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func DeriveMasterKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, 3, 24*1024, 2, 32)
}

func DeriveSubKey(masterKey []byte, contextInfo string) ([]byte, error) {
	reader := hkdf.New(sha256.New, masterKey, nil, []byte(contextInfo))
	subKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, subKey); err != nil {
		return nil, err
	}
	return subKey, nil
}

func Encrypt(key, plaintext, associatedData []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, associatedData)
	return nonce, ciphertext, nil
}

func Decrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, associatedData)
}
