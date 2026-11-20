# passwordium

A zero-exposure-RAM, single-file encrypted vault library in Go for storing sensitive credentials, keys, and notes.

## Architecture

- **Binary Envelope (`header.go`)**:
  - **50-byte Plaintext Header**: `Magic ("PSDM", 4B)` | `Version (uint16 BE)` | `Salt (32B)` | `ArgonTime (uint32 BE)` | `ArgonMemory (uint32 BE, KiB)` | `ArgonThreads (uint32 BE)`.
  - **24-byte Nonce**: Random XChaCha20-Poly1305 nonce.
  - **Ciphertext**: Protobuf-encoded `VaultData` sealed with XChaCha20-Poly1305 using the entire 50-byte plaintext header as associated authenticated data (AAD).
- **Two-Level Key Hierarchy (`internal/crypto`)**:
  - `masterKey` derived from the master password and salt via **Argon2id** (minimum 16 MiB and `DefaultMaxArgon2Params` upper bounds enforced on `Create`; pre-KDF resource caps `DefaultMaxArgon2Params` / `WithMaxArgon2Params` / `WithMaxArgon2Work` enforced on `Open`) and immediately wiped after subkey derivation.
  - `indexKey` (`HKDF-SHA256`, context `"passwordium:v1:index"`) initializes a single session AEAD (`crypto.Cipher`) to encrypt the outer `VaultData` container.
  - `secretKey` (`HKDF-SHA256`, context `"passwordium:v1:secret"`) initializes a single session AEAD (`crypto.Cipher`) to encrypt each entry's `SecretPayload` (padded with ISO/IEC 7816-4 to 256-byte blocks to hide exact secret lengths) individually with AAD `"<entry_id>:<entry_version>"`.
- **Minimized RAM Exposure**: After `Open`, searchable entry metadata (`EntryMeta`) is indexed in memory while secrets stay encrypted until `GetSecret(id)` is called. Temporary `[]byte` buffers are wiped via `clear()`, `Secret` implements `String()`, `GoString()`, and `slog.LogValuer` to prevent accidental credential logging, and `Close()` / `CloseWithSave(ctx)` releases session AEAD instances and zeroes entry secret buffers. (Note that callers should zero their `masterPassword []byte` slice after `Create`/`Open`, and that decrypted Go `string` fields on `Secret` reside in garbage-collected heap memory.)
- **Storage Backends (`storage.go`)**: `FileStorage` (atomic write via `os.CreateTemp`, `0600` permissions, `Sync`, atomic no-overwrite creation via `os.Link`, optimistic concurrency detection via `ErrConcurrentModification`, regular-file verification on both load and save, and bounded reads via `DefaultMaxFileSize` / `WithMaxFileSize`) and `MemoryStorage`.

## Project Layout

```
passwordium/
├── go.mod
├── go.sum
├── README.md
├── errors.go
├── types.go
├── options.go
├── uuid.go
├── header.go
├── storage.go
├── vault.go
├── proto/
│   └── vault.proto
├── internal/
│   ├── vaultpb/
│   │   └── vault.pb.go
│   └── crypto/
│       ├── crypto.go
│       └── crypto_test.go
├── header_test.go
├── storage_test.go
├── vault_test.go
└── vault_security_test.go
```

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/dmi3midd/passwordium"
)

func main() {
	ctx := context.Background()
	store := passwordium.NewFileStorage("vault.psdm")
	masterPassword := []byte("correct-horse-battery-staple")

	v, err := passwordium.Create(ctx, store, masterPassword)
	if err != nil {
		log.Fatal(err)
	}

	id, err := v.Put(ctx, passwordium.EntryMeta{
		Title:    "GitHub",
		Username: "octocat",
		URL:      "https://github.com",
		Tags:     []string{"dev", "git"},
	}, passwordium.Secret{
		Password: "s3cr3t-password",
		Notes:    "Personal token",
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := v.Save(ctx); err != nil {
		log.Fatal(err)
	}
	if err := v.Close(); err != nil {
		log.Fatal(err)
	}

	opened, err := passwordium.Open(ctx, store, masterPassword)
	if err != nil {
		log.Fatal(err)
	}
	defer opened.Close()

	matches := opened.Search(passwordium.SearchQuery{Query: "github"})
	secret, err := opened.GetSecret(id)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("found=%d password=%s\n", len(matches), secret.Password)
}
```
