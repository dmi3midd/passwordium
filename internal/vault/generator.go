package vault

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars   = "0123456789"
	specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	allChars     = lowerChars + upperChars + digitChars + specialChars

	DefaultGeneratedPasswordLen = 20
)

// GeneratePassword creates a cryptographically secure random password of the given length
// guaranteed to include at least one lowercase, uppercase, digit, and special character.
func GeneratePassword(length int) (string, error) {
	if length < 12 {
		length = DefaultGeneratedPasswordLen
	}

	buf := make([]byte, length)
	charsets := []string{lowerChars, upperChars, digitChars, specialChars}

	// Ensure at least one character from each class
	for i, cs := range charsets {
		ch, err := randomChar(cs)
		if err != nil {
			return "", fmt.Errorf("generate required char: %w", err)
		}
		buf[i] = ch
	}

	// Fill remaining positions from full alphabet
	for i := len(charsets); i < length; i++ {
		ch, err := randomChar(allChars)
		if err != nil {
			return "", fmt.Errorf("generate random char: %w", err)
		}
		buf[i] = ch
	}

	// Cryptographic Fisher-Yates shuffle
	for i := length - 1; i > 0; i-- {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("shuffle password: %w", err)
		}
		j := int(nBig.Int64())
		buf[i], buf[j] = buf[j], buf[i]
	}

	return string(buf), nil
}

func randomChar(charset string) (byte, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[nBig.Int64()], nil
}

// ZeroBytes overwrites a byte slice in memory with zeros.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

