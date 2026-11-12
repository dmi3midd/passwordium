package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dmi3midd/passwordium/internal/vault/pb"
	"google.golang.org/protobuf/proto"
)

func TestVaultLifecycleAndDoubleEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.enc")
	masterPass := []byte("CorrectHorseBatteryStaple!2026")

	if Exists(vaultPath) {
		t.Fatalf("expected vault file not to exist initially")
	}

	v, err := Create(vaultPath, masterPass)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if !Exists(vaultPath) {
		t.Fatalf("expected vault file to exist after Create")
	}

	// Verify 0600 permissions and absence of leftover .tmp file
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("stat vault file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected file mode 0600, got %04o", perm)
	}
	if _, err := os.Stat(vaultPath + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("expected temporary file %s.tmp to be removed after atomic rename", vaultPath)
	}

	secretPassword := "s3cr3t-P@ssw0rd-GitHub!"
	secretNotes := "Recovery codes: 1111-2222, 3333-4444"

	entry, err := v.AddEntry("GitHub", "octocat", secretPassword, "https://github.com", secretNotes)
	if err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	// Verify in-memory entry keeps password and notes encrypted
	if bytes.Contains(entry.EncryptedPassword, []byte(secretPassword)) {
		t.Fatalf("plaintext password leaked in EncryptedPassword")
	}
	if bytes.Contains(entry.EncryptedNotes, []byte(secretNotes)) {
		t.Fatalf("plaintext notes leaked in EncryptedNotes")
	}

	v.Close()

	// Wrong master password must fail with ErrInvalidMasterPassword (Poly1305 auth error)
	if _, err := Open(vaultPath, []byte("WrongPassword123")); !errors.Is(err, ErrInvalidMasterPassword) {
		t.Fatalf("expected ErrInvalidMasterPassword, got %v", err)
	}

	// Re-open with valid master password
	reopened, err := Open(vaultPath, masterPass)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer reopened.Close()

	entries := reopened.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	gotPw, err := reopened.DecryptPassword(entries[0])
	if err != nil {
		t.Fatalf("DecryptPassword failed: %v", err)
	}
	if gotPw != secretPassword {
		t.Errorf("expected decrypted password %q, got %q", secretPassword, gotPw)
	}

	gotNotes, err := reopened.DecryptNotes(entries[0])
	if err != nil {
		t.Fatalf("DecryptNotes failed: %v", err)
	}
	if gotNotes != secretNotes {
		t.Errorf("expected decrypted notes %q, got %q", secretNotes, gotNotes)
	}

	// Verify AAD binding on entry ID: tampering with entry.Id must fail decryption
	tampered := proto.Clone(entries[0]).(*pb.VaultEntry)
	tampered.Id = "00000000-0000-0000-0000-000000000000"
	if _, err := reopened.DecryptPassword(tampered); err == nil {
		t.Fatalf("expected DecryptPassword to fail when entry ID (AAD) is tampered")
	}
}

func TestOuterAADTamperingDetection(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault.enc")
	masterPass := []byte("MasterPass#1")

	v, err := Create(vaultPath, masterPass)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	v.Close()

	// Tamper with outer version field in EncryptedVaultFile (part of AAD = version + salt)
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var encFile pb.EncryptedVaultFile
	if err := proto.Unmarshal(raw, &encFile); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	encFile.Version = 99
	tamperedBytes, err := proto.Marshal(&encFile)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(vaultPath, tamperedBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Open(vaultPath, masterPass); !errors.Is(err, ErrInvalidMasterPassword) {
		t.Fatalf("expected ErrInvalidMasterPassword when outer version AAD is tampered, got %v", err)
	}
}
