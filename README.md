# passwordium

A zero-exposure-RAM, single-file encrypted vault library in Go for storing sensitive credentials, keys, and notes.

## Architecture

- **Binary Envelope (`header.go`)**:
  - **50-byte Plaintext Header**: `Magic ("PSDM", 4B)` | `Version (uint16 BE)` | `Salt (32B)` | `ArgonTime (uint32 BE)` | `ArgonMemory (uint32 BE, KiB)` | `ArgonThreads (uint32 BE)`.
  - **24-byte Nonce**: Random XChaCha20-Poly1305 nonce.
  - **Ciphertext**: Protobuf-encoded `VaultData` sealed with XChaCha20-Poly1305 using the entire 50-byte plaintext header as associated authenticated data (AAD).
- **Two-Level Key Hierarchy (`internal/crypto`)**:
  - `masterKey` derived from the master password and salt via **Argon2id** (minimum 16 MiB enforced on `Create`; pre-KDF resource caps `DefaultMaxArgon2Params` / `WithMaxArgon2Params` enforced on `Open`) and immediately wiped after subkey derivation.
  - `indexKey` (`HKDF-SHA256`, context `"passwordium:v1:index"`) initializes a single session AEAD (`crypto.Cipher`) to encrypt the outer `VaultData` container.
  - `secretKey` (`HKDF-SHA256`, context `"passwordium:v1:secret"`) initializes a single session AEAD (`crypto.Cipher`) to encrypt each entry's `SecretPayload` individually with AAD `"<entry_id>:<entry_version>"`.
- **Zero-Exposure RAM**: After `Open`, searchable entry metadata (`EntryMeta`) is indexed in memory while secrets stay encrypted until `GetSecret(id)` is called. `Close()` releases session AEAD instances and zeroes entry secret buffers via `clear()`.
- **Storage Backends (`storage.go`)**: `FileStorage` (atomic write via `os.CreateTemp`, `0600` permissions, `Sync`, `os.Rename`, regular-file verification, and bounded reads via `DefaultMaxFileSize` / `WithMaxFileSize`) and `MemoryStorage`.

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
