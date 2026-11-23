package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func fastParams() Argon2Params {
	return Argon2Params{Time: 1, MemoryKiB: 64, Threads: 1}
}

func TestDeriveMasterKeyAndSubKey(t *testing.T) {
	t.Parallel()

	salt, err := RandomBytes(SaltSize)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	params := fastParams()

	mustDerive := func(pw, s []byte) []byte {
		t.Helper()
		k, err := DeriveMasterKey(pw, s, params)
		if err != nil {
			t.Fatalf("DeriveMasterKey: %v", err)
		}
		return k
	}

	k1 := mustDerive([]byte("correct-horse-battery-staple"), salt)
	k2 := mustDerive([]byte("correct-horse-battery-staple"), salt)
	kWrong := mustDerive([]byte("wrong-password"), salt)

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
	if bytes.Equal(k1, mustDerive([]byte("correct-horse-battery-staple"), salt2)) {
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

// FINDING-10: DeriveMasterKey must return an error instead of panicking or truncating Threads.
func TestDeriveMasterKeyRejectsInvalidParamsWithoutPanic(t *testing.T) {
	t.Parallel()

	salt := make([]byte, SaltSize)
	cases := []Argon2Params{
		{Time: 0, MemoryKiB: 64, Threads: 1},
		{Time: 1, MemoryKiB: 64, Threads: 0},
		{Time: 1, MemoryKiB: 64, Threads: 256}, // uint8(256) == 0 would panic in argon2.IDKey
		{Time: 1, MemoryKiB: 0, Threads: 1},
	}
	for _, p := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DeriveMasterKey(%+v) panicked: %v", p, r)
				}
			}()
			key, err := DeriveMasterKey([]byte("pw"), salt, p)
			if !errors.Is(err, ErrInvalidArgon2Params) {
				t.Fatalf("DeriveMasterKey(%+v) err = %v, want ErrInvalidArgon2Params", p, err)
			}
			if key != nil {
				t.Fatalf("DeriveMasterKey(%+v) returned non-nil key on error", p)
			}
		}()
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

	if _, err := Decrypt(key, nonce1, ct1, []byte("entry-123:2")); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered AAD err = %v, want ErrDecryptionFailed", err)
	}

	badCT := bytes.Clone(ct1)
	badCT[0] ^= 0x01
	if _, err := Decrypt(key, nonce1, badCT, aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered ciphertext err = %v, want ErrDecryptionFailed", err)
	}

	badNonce := bytes.Clone(nonce1)
	badNonce[len(badNonce)-1] ^= 0x80
	if _, err := Decrypt(key, badNonce, ct1, aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered nonce err = %v, want ErrDecryptionFailed", err)
	}

	wrongKey := bytes.Clone(key)
	wrongKey[0] ^= 0x01
	if _, err := Decrypt(wrongKey, nonce1, ct1, aad); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("wrong key err = %v, want ErrDecryptionFailed", err)
	}

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

// FINDING-05: a single reusable Cipher must interoperate with the standalone helpers
// and stop working after Close.
func TestCipherReuseAndClose(t *testing.T) {
	t.Parallel()

	key, err := RandomBytes(KeySize)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	// Zero the caller's key: the Cipher must keep working from its own internal copy.
	keyCopy := bytes.Clone(key)
	ZeroBytes(key)

	for i := range 5 {
		aad := []byte{byte(i)}
		nonce, ct, err := c.Encrypt([]byte("payload"), aad)
		if err != nil {
			t.Fatalf("Cipher.Encrypt #%d: %v", i, err)
		}
		pt, err := c.Decrypt(nonce, ct, aad)
		if err != nil || string(pt) != "payload" {
			t.Fatalf("Cipher.Decrypt #%d = %q, %v", i, pt, err)
		}
		pt2, err := Decrypt(keyCopy, nonce, ct, aad)
		if err != nil || string(pt2) != "payload" {
			t.Fatalf("standalone Decrypt of Cipher output #%d = %q, %v", i, pt2, err)
		}
	}

	if _, err := NewCipher([]byte("short")); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("NewCipher short key err = %v, want ErrInvalidKeySize", err)
	}
	if _, err := c.Decrypt([]byte("short"), make([]byte, Overhead), nil); !errors.Is(err, ErrInvalidNonceSize) {
		t.Fatalf("Cipher.Decrypt short nonce err = %v, want ErrInvalidNonceSize", err)
	}

	c.Close()
	c.Close() // idempotent
	if _, _, err := c.Encrypt([]byte("x"), nil); !errors.Is(err, ErrCipherClosed) {
		t.Fatalf("Encrypt after Close err = %v, want ErrCipherClosed", err)
	}
	if _, err := c.Decrypt(make([]byte, NonceSize), make([]byte, Overhead), nil); !errors.Is(err, ErrCipherClosed) {
		t.Fatalf("Decrypt after Close err = %v, want ErrCipherClosed", err)
	}

	var nilCipher *Cipher
	nilCipher.Close()
	if _, _, err := nilCipher.Encrypt(nil, nil); !errors.Is(err, ErrCipherClosed) {
		t.Fatalf("nil Cipher Encrypt err = %v, want ErrCipherClosed", err)
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
	ZeroBytes(nil)

	if _, err := RandomBytes(-1); err == nil {
		t.Fatal("RandomBytes(-1) must return an error")
	}
	empty, err := RandomBytes(0)
	if err != nil || len(empty) != 0 {
		t.Fatalf("RandomBytes(0) = (%v, %v), want empty slice and nil", empty, err)
	}
}

func TestArgon2ParamsValidate(t *testing.T) {
	t.Parallel()

	if err := DefaultArgon2Params().Validate(); err != nil {
		t.Fatalf("DefaultArgon2Params().Validate() = %v", err)
	}
	if err := DefaultArgon2Params().ValidateLimits(DefaultArgon2Limits()); err != nil {
		t.Fatalf("defaults must satisfy default open limits: %v", err)
	}
	if err := DefaultArgon2Params().ValidateForCreate(MinCreateArgonMemoryKiB); err != nil {
		t.Fatalf("defaults must satisfy create floor: %v", err)
	}

	invalid := []Argon2Params{
		{Time: 0, MemoryKiB: 64, Threads: 1},
		{Time: HardMaxArgonTime + 1, MemoryKiB: 64, Threads: 1},
		{Time: 1, MemoryKiB: MinArgonMemoryKiB - 1, Threads: 1},
		{Time: 1, MemoryKiB: HardMaxArgonMemoryKiB + 1, Threads: 1},
		{Time: 1, MemoryKiB: 64, Threads: 0},
		{Time: 1, MemoryKiB: 64, Threads: HardMaxArgonThreads + 1},
	}
	for _, p := range invalid {
		if err := p.Validate(); !errors.Is(err, ErrInvalidArgon2Params) {
			t.Errorf("Validate(%+v) = %v, want ErrInvalidArgon2Params", p, err)
		}
	}
}

// FINDING-01: open-time limits, including the combined Time*Memory work bound.
func TestArgon2ParamsValidateLimits(t *testing.T) {
	t.Parallel()

	limits := DefaultArgon2Limits()
	rejected := []Argon2Params{
		{Time: 0, MemoryKiB: 64, Threads: 1},
		{Time: HardMaxArgonTime, MemoryKiB: HardMaxArgonMemoryKiB, Threads: HardMaxArgonThreads},
		{Time: DefaultMaxArgonTime + 1, MemoryKiB: 64, Threads: 1},
		{Time: 1, MemoryKiB: DefaultMaxArgonMemoryKiB + 1, Threads: 1},
		{Time: 1, MemoryKiB: 64, Threads: DefaultMaxArgonThreads + 1},
		{Time: DefaultMaxArgonTime, MemoryKiB: DefaultMaxArgonMemoryKiB, Threads: 1}, // 16 * 512 MiB > work limit
	}
	for _, p := range rejected {
		if err := p.ValidateLimits(limits); !errors.Is(err, ErrInvalidArgon2Params) {
			t.Errorf("ValidateLimits(%+v) = %v, want ErrInvalidArgon2Params", p, err)
		}
	}

	accepted := []Argon2Params{
		{Time: 4, MemoryKiB: DefaultMaxArgonMemoryKiB, Threads: 4}, // exactly at work limit
		{Time: DefaultMaxArgonTime, MemoryKiB: 128 * 1024, Threads: DefaultMaxArgonThreads},
		fastParams(),
	}
	for _, p := range accepted {
		if err := p.ValidateLimits(limits); err != nil {
			t.Errorf("ValidateLimits(%+v) = %v, want nil", p, err)
		}
	}

	noWork := limits
	noWork.MaxWork = 0
	if err := (Argon2Params{Time: DefaultMaxArgonTime, MemoryKiB: DefaultMaxArgonMemoryKiB, Threads: 1}).ValidateLimits(noWork); err != nil {
		t.Errorf("MaxWork=0 must disable the product check: %v", err)
	}
}

// FINDING-02: creation floor rejects KiB/MiB unit mistakes.
func TestArgon2ParamsValidateForCreate(t *testing.T) {
	t.Parallel()

	weak := Argon2Params{Time: 3, MemoryKiB: 64, Threads: 2} // "64" meant as MiB
	if err := weak.ValidateForCreate(MinCreateArgonMemoryKiB); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("ValidateForCreate(weak) = %v, want ErrInvalidArgon2Params", err)
	}
	if err := weak.ValidateForCreate(MinArgonMemoryKiB); err != nil {
		t.Fatalf("ValidateForCreate(weak, low floor) = %v, want nil", err)
	}
	floor := Argon2Params{Time: 1, MemoryKiB: MinCreateArgonMemoryKiB, Threads: 1}
	if err := floor.ValidateForCreate(MinCreateArgonMemoryKiB); err != nil {
		t.Fatalf("ValidateForCreate(at floor) = %v, want nil", err)
	}
	overOpenLimit := Argon2Params{Time: DefaultMaxArgonTime + 1, MemoryKiB: MinCreateArgonMemoryKiB, Threads: 1}
	if err := overOpenLimit.ValidateForCreate(MinCreateArgonMemoryKiB); !errors.Is(err, ErrInvalidArgon2Params) {
		t.Fatalf("ValidateForCreate(over default open limit) = %v, want ErrInvalidArgon2Params", err)
	}
}
