package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestDeriveMasterKeyAndSubKey(t *testing.T) {
	t.Parallel()

	salt, err := RandomBytes(SaltSize)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	params := Argon2Params{Time: 1, Memory: 64, Threads: 1}

	k1 := DeriveMasterKey([]byte("correct-horse-battery-staple"), salt, params)
	k2 := DeriveMasterKey([]byte("correct-horse-battery-staple"), salt, params)
	kWrong := DeriveMasterKey([]byte("wrong-password"), salt, params)

	if len(k1) != KeySize {
		t.Fatalf("len(masterKey) = %d, want %d", len(k1), KeySize)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("DeriveMasterKey is not deterministic for equal inputs")
	}
	if bytes.Equal(k1, kWrong) {
		t.Fatal("different passwords produced identical master keys")
	}

	salt2 := bytes.Clone(salt)
	salt2[0] ^= 0xff
	kDiffSalt := DeriveMasterKey([]byte("correct-horse-battery-staple"), salt2, params)
	if bytes.Equal(k1, kDiffSalt) {
		t.Fatal("different salts produced identical master keys")
	}

	idx1, err := DeriveSubKey(k1, "passwordium:v1:index")
	if err != nil {
		t.Fatalf("DeriveSubKey(index): %v", err)
	}
	idx2, err := DeriveSubKey(k1, "passwordium:v1:index")
	if err != nil {
		t.Fatalf("DeriveSubKey(index) repeat: %v", err)
	}
	sec, err := DeriveSubKey(k1, "passwordium:v1:secret")
	if err != nil {
		t.Fatalf("DeriveSubKey(secret): %v", err)
	}

	if !bytes.Equal(idx1, idx2) {
		t.Fatal("DeriveSubKey is not deterministic")
	}
	if bytes.Equal(idx1, sec) {
		t.Fatal("HKDF domain separation failed: different contexts produced same subkey")
	}
	if bytes.Equal(idx1, k1) || bytes.Equal(sec, k1) {
		t.Fatal("subkey unexpectedly equals masterKey")
	}

	if _, err := DeriveSubKey([]byte("short"), "ctx"); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("short key err = %v, want ErrInvalidKeySize", err)
	}
	if _, err := DeriveSubKey(k1, ""); !errors.Is(err, ErrEmptyContextInfo) {
		t.Fatalf("empty context err = %v, want ErrEmptyContextInfo", err)
	}
}

func TestEncryptDecryptAndTampering(t *testing.T) {
	t.Parallel()

	key, err := RandomBytes(KeySize)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	plaintext := []byte("super-secret-payload")
	aad := []byte("entry-123:1")

	nonce1, ct1, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	nonce2, ct2, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}

	if len(nonce1) != NonceSize {
		t.Fatalf("len(nonce) = %d, want %d", len(nonce1), NonceSize)
	}
	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("Encrypt reused random nonce")
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("ciphertexts with distinct nonces should differ")
	}

	got, err := Decrypt(key, nonce1, ct1, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt = %q, want %q", got, plaintext)
	}

	// Empty plaintext must still authenticate and round-trip.
	emptyNonce, emptyCT, err := Encrypt(key, nil, aad)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	emptyPT, err := Decrypt(key, emptyNonce, emptyCT, aad)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(emptyPT) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(emptyPT))
	}

	// Tampered AAD.
	if _, err := Decrypt(key, nonce1, ct1, []byte("entry-123:2")); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered AAD err = %v, want ErrDecryptionFailed", err)
	}

	// Tampered ciphertext.
	badCT := bytes.Clone(ct1)
	badCT[0] ^= 0x01
	if _, err := Decrypt(key, nonce1, badCT, aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered ciphertext err = %v, want ErrDecryptionFailed", err)
	}

	// Tampered nonce.
	badNonce := bytes.Clone(nonce1)
	badNonce[len(badNonce)-1] ^= 0x80
	if _, err := Decrypt(key, badNonce, ct1, aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered nonce err = %v, want ErrDecryptionFailed", err)
	}

	// Wrong key.
	wrongKey := bytes.Clone(key)
	wrongKey[0] ^= 0x01
	if _, err := Decrypt(wrongKey, nonce1, ct1, aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("wrong key err = %v, want ErrDecryptionFailed", err)
	}

	// Invalid sizes must return sentinel errors rather than panic.
	if _, _, err := Encrypt([]byte("short"), plaintext, aad); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("Encrypt short key err = %v, want ErrInvalidKeySize", err)
	}
	if _, err := Decrypt([]byte("short"), nonce1, ct1, aad); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("Decrypt short key err = %v, want ErrInvalidKeySize", err)
	}
	if _, err := Decrypt(key, []byte("short"), ct1, aad); !errors.Is(err, ErrInvalidNonceSize) {
		t.Fatalf("Decrypt short nonce err = %v, want ErrInvalidNonceSize", err)
	}
	if _, err := Decrypt(key, nonce1, []byte("short"), aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt short ciphertext err = %v, want ErrDecryptionFailed", err)
	}
}

func TestZeroBytes(t *testing.T) {
	t.Parallel()

	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ZeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("buf[%d] = %d, want 0", i, b)
		}
	}
	ZeroBytes(nil) // should not panic
}

func TestArgon2ParamsValidate(t *testing.T) {
	t.Parallel()

	if err := DefaultArgon2Params().Validate(); err != nil {
		t.Fatalf("DefaultArgon2Params().Validate() = %v", err)
	}

	invalid := []Argon2Params{
		{Time: 0, Memory: 64, Threads: 1},
		{Time: MaxArgonTime + 1, Memory: 64, Threads: 1},
		{Time: 1, Memory: MinArgonMemory - 1, Threads: 1},
		{Time: 1, Memory: MaxArgonMemory + 1, Threads: 1},
		{Time: 1, Memory: 64, Threads: 0},
		{Time: 1, Memory: 64, Threads: MaxArgonThreads + 1},
	}
	for _, p := range invalid {
		if err := p.Validate(); !errors.Is(err, ErrInvalidArgon2Params) {
			t.Errorf("Validate(%+v) = %v, want ErrInvalidArgon2Params", p, err)
		}
	}
}
